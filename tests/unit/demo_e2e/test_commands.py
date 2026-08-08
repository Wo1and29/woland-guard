from __future__ import annotations

import ctypes
import json
import os
import shutil
import sys
import time
from pathlib import Path

import pytest
from scripts.demo_e2e.commands import CommandRunner, DemoCommandError


def test_command_failure_does_not_reflect_environment_or_stderr(tmp_path: Path) -> None:
    canary = "synthetic-command-credential-canary"
    runner = CommandRunner()

    with pytest.raises(DemoCommandError) as captured:
        runner.run(
            [
                sys.executable,
                "-c",
                (
                    "import os,sys;"
                    "sys.stderr.write(os.environ['WG_DEMO_POSTGRES_PASSWORD']);"
                    "raise SystemExit(7)"
                ),
            ],
            cwd=tmp_path.resolve(),
            environment={"WG_DEMO_POSTGRES_PASSWORD": canary},
        )

    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)


def test_command_output_is_bounded(tmp_path: Path) -> None:
    runner = CommandRunner()

    with pytest.raises(DemoCommandError, match="safe limit"):
        runner.run(
            [sys.executable, "-c", "print('x' * 1024)"],
            cwd=tmp_path.resolve(),
            output_limit=16,
        )


def test_command_timeout_is_static_and_does_not_reflect_child_context(tmp_path: Path) -> None:
    canary = "synthetic-timeout-credential-canary"
    runner = CommandRunner()

    with pytest.raises(DemoCommandError) as captured:
        runner.run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path.resolve(),
            environment={"WG_DEMO_POSTGRES_PASSWORD": canary},
            timeout_seconds=0.01,
        )

    assert canary not in str(captured.value)


def test_windows_job_object_terminates_child_and_grandchild_tree(tmp_path: Path) -> None:
    parent_pid_file = tmp_path / "path with spaces" / "parent.pid"
    child_pid_file = parent_pid_file.with_name("child.pid")
    parent_pid_file.parent.mkdir()
    parent_program = (
        "import os,subprocess,sys,time;"
        "open(sys.argv[1],'w').write(str(os.getpid()));"
        "child='import os,sys,time;open(sys.argv[1],\"w\").write(str(os.getpid()));time.sleep(60)';"
        "subprocess.Popen([sys.executable,'-c',child,sys.argv[2]]);time.sleep(60)"
    )

    with pytest.raises(DemoCommandError, match="timed out"):
        CommandRunner().run(
            [sys.executable, "-c", parent_program, str(parent_pid_file), str(child_pid_file)],
            cwd=tmp_path.resolve(),
            timeout_seconds=1.5,
        )

    parent_pid = int(parent_pid_file.read_text(encoding="utf-8"))
    child_pid = int(child_pid_file.read_text(encoding="utf-8"))
    assert _wait_for_pid_absence(parent_pid)
    assert _wait_for_pid_absence(child_pid)


def test_outer_uv_tree_is_terminated_before_control_returns(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv executable is required for the 8B supervisor regression")
    parent_pid_file = tmp_path / "outer uv parent.pid"
    child_pid_file = tmp_path / "outer uv child.pid"
    parent_program = (
        "import os,subprocess,sys,time;"
        "open(sys.argv[1],'w').write(str(os.getpid()));"
        "child='import os,sys,time;open(sys.argv[1],\"w\").write(str(os.getpid()));time.sleep(60)';"
        "subprocess.Popen([sys.executable,'-c',child,sys.argv[2]]);time.sleep(60)"
    )

    with pytest.raises(DemoCommandError, match="timed out"):
        CommandRunner().run(
            [
                uv,
                "run",
                "--no-project",
                "--python",
                "3.12",
                "python",
                "-c",
                parent_program,
                str(parent_pid_file),
                str(child_pid_file),
            ],
            cwd=tmp_path.resolve(),
            timeout_seconds=2,
        )

    assert _wait_for_file(parent_pid_file)
    assert _wait_for_file(child_pid_file)
    assert _wait_for_pid_absence(int(parent_pid_file.read_text(encoding="utf-8")))
    assert _wait_for_pid_absence(int(child_pid_file.read_text(encoding="utf-8")))


def test_infinite_output_and_stderr_are_bounded_without_deadlock(tmp_path: Path) -> None:
    runner = CommandRunner()
    started = time.monotonic()
    with pytest.raises(DemoCommandError, match="safe limit"):
        runner.run(
            [
                sys.executable,
                "-c",
                "import sys\nwhile True:\n sys.stdout.write('x'*65536)\n sys.stdout.flush()",
            ],
            cwd=tmp_path.resolve(),
            output_limit=65_536,
            timeout_seconds=10,
        )
    assert time.monotonic() - started < 8

    with pytest.raises(DemoCommandError, match="safe limit"):
        runner.run(
            [sys.executable, "-c", "import sys;sys.stderr.write('x'*2097152)"],
            cwd=tmp_path.resolve(),
            timeout_seconds=10,
        )


def test_binary_output_and_stdin_consumer_timeout_remove_partial_output(tmp_path: Path) -> None:
    runner = CommandRunner()
    output = tmp_path / "partial.bin"
    with pytest.raises(DemoCommandError, match="timed out"):
        runner.run_to_file(
            [
                sys.executable,
                "-c",
                (
                    "import sys,time;"
                    "sys.stdout.buffer.write(b'x'*1024);"
                    "sys.stdout.flush();time.sleep(60)"
                ),
            ],
            cwd=tmp_path.resolve(),
            output_path=output,
            timeout_seconds=0.5,
            output_limit=4_096,
        )
    assert not output.exists()

    source = tmp_path / "input.bin"
    source.write_bytes(b"x" * 1_048_576)
    with pytest.raises(DemoCommandError, match="timed out"):
        runner.run(
            [sys.executable, "-c", "import time;time.sleep(60)"],
            cwd=tmp_path.resolve(),
            stdin_path=source,
            timeout_seconds=0.5,
        )


def test_child_environment_is_closed_and_explicit_paths_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "synthetic-parent-environment-canary"
    for name in (
        "AWS_SECRET_ACCESS_KEY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "PWDEBUG",
        "DEBUG",
    ):
        monkeypatch.setenv(name, canary)
    isolated = tmp_path / "isolated browser cache"
    result = CommandRunner().run(
        [
            sys.executable,
            "-c",
            (
                "import json,os;"
                f"print(json.dumps({{'leaked':any(os.getenv(k)=={canary!r} for k in "
                "['AWS_SECRET_ACCESS_KEY','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','PYTHONPATH',"
                "'PYTHONHOME','VIRTUAL_ENV','PWDEBUG','DEBUG']),"
                "'browser':os.environ['PLAYWRIGHT_BROWSERS_PATH']}))"
            ),
        ],
        cwd=tmp_path.resolve(),
        environment={"PLAYWRIGHT_BROWSERS_PATH": str(isolated)},
    )
    payload = json.loads(result.text())
    assert payload == {"browser": str(isolated), "leaked": False}


def _wait_for_pid_absence(process_id: int) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _pid_exists(process_id):
            return True
        time.sleep(0.05)
    return not _pid_exists(process_id)


def _wait_for_file(path: Path) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.is_file():
            return True
        time.sleep(0.05)
    return path.is_file()


def _pid_exists(process_id: int) -> bool:
    if os.name == "nt":
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x00100000, False, process_id)
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True
