"""Real Docker regression for the non-root private-tmpfs token lifecycle."""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
from pathlib import Path
from threading import Thread
from uuid import uuid4

import pytest

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("WG_RUN_DOCKER_TESTS") != "1",
        reason="real Docker lifecycle regression was not explicitly enabled",
    ),
]

PROJECT_ROOT = Path(__file__).parents[2]
PROBE = Path(__file__).with_name("telegram_secret_probe.py")
TOKEN_FILE_NAME = "docker-canary.token"  # noqa: S105
TOKEN_ONE = "synthetic-docker-token-one"  # noqa: S105
TOKEN_TWO = "synthetic-docker-token-two"  # noqa: S105


def _run(command: list[str], *, environment: dict[str, str], input_text: str | None = None) -> str:
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout + completed.stderr


def _next_line(
    lines: queue.Queue[str],
    expected_prefix: str,
    *,
    process: subprocess.Popen[str],
    errors: queue.Queue[str],
) -> str:
    for _ in range(600):
        try:
            line = lines.get(timeout=0.1)
        except queue.Empty:
            if process.poll() is not None:
                rendered_errors = "\n".join(list(errors.queue))
                raise AssertionError(rendered_errors or "container probe exited silently") from None
            continue
        assert line.startswith(expected_prefix), line
        return line
    raise AssertionError("container probe did not report progress")


def test_real_container_secret_rotation_and_compose_isolation() -> None:
    docker = shutil.which("docker")
    assert docker is not None
    test_root = PROJECT_ROOT / ".docker-test-telegram"
    staging = test_root / "staging"
    if test_root.exists():
        shutil.rmtree(test_root)
    staging.mkdir(parents=True)
    token_path = staging / TOKEN_FILE_NAME
    environment = os.environ.copy()
    environment["COMPOSE_PROJECT_NAME"] = f"wg6d{uuid4().hex[:12]}"
    environment["WG_TELEGRAM_STAGING_DIRECTORY"] = str(staging)
    environment.setdefault("WG_POSTGRES_PASSWORD", "synthetic-docker-test-password")
    compose = [docker, "compose", "--profile", "telegram-notifications"]
    try:
        _run([*compose, "build", "outbox-worker", "telegram-admin"], environment=environment)
        command = [
            *compose,
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--volume",
            f"{PROBE.as_posix()}:/tmp/telegram_secret_probe.py:ro",
            "--entrypoint",
            "python",
            "outbox-worker",
            "/tmp/telegram_secret_probe.py",  # noqa: S108
        ]
        process = subprocess.Popen(  # noqa: S603
            command,
            cwd=PROJECT_ROOT,
            env=environment,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process_stdout = process.stdout
        process_stderr = process.stderr
        lines: queue.Queue[str] = queue.Queue()
        errors: queue.Queue[str] = queue.Queue()

        def collect_stdout() -> None:
            for line in process_stdout:
                lines.put(line.rstrip("\r\n"))

        def collect_stderr() -> None:
            for line in process_stderr:
                errors.put(line.rstrip("\r\n"))

        Thread(target=collect_stdout, daemon=True).start()
        Thread(target=collect_stderr, daemon=True).start()
        _next_line(lines, "STARTED ", process=process, errors=errors)
        token_path.write_text(TOKEN_ONE, encoding="ascii")
        process.stdin.write("add\n")
        process.stdin.flush()
        _next_line(lines, "READY ", process=process, errors=errors)

        replacement = staging / "replacement"
        replacement.write_text(TOKEN_TWO, encoding="ascii")
        os.replace(replacement, token_path)
        process.stdin.write("rotate\n")
        process.stdin.flush()
        _next_line(lines, "ROTATED ", process=process, errors=errors)

        replacement.write_bytes(b"invalid\nrotation")
        os.replace(replacement, token_path)
        process.stdin.write("invalid\n")
        process.stdin.flush()
        _next_line(lines, "INVALID_PRESERVED", process=process, errors=errors)

        token_path.unlink()
        process.stdin.write("missing\n")
        process.stdin.flush()
        _next_line(lines, "MISSING_PRESERVED", process=process, errors=errors)
        process.stdin.write("finish\n")
        process.stdin.close()
        return_code = process.wait(timeout=180)
        stderr = "\n".join(list(errors.queue))
        assert return_code == 0, stderr
        for secret in (TOKEN_ONE, TOKEN_TWO):
            assert secret not in stderr

        token_path.write_text(TOKEN_TWO, encoding="ascii")
        _run([*compose, "up", "-d", "postgres"], environment=environment)
        _run(
            [*compose, "run", "--rm", "-T", "control-plane", "alembic", "upgrade", "head"],
            environment=environment,
        )
        isolation = _run(
            [
                *compose,
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "--entrypoint",
                "python",
                "control-plane",
                "-c",
                "from pathlib import Path; assert not Path('/run/woland-guard-staging').exists(); "
                "assert not Path('/run/secrets/woland-guard').exists()",
            ],
            environment=environment,
        )
        assert TOKEN_TWO not in isolation
        cli_output = _run(
            [
                *compose,
                "run",
                "--rm",
                "-T",
                "telegram-admin",
                "woland-guard-admin",
                "create-telegram-destination",
                "--token-file-name",
                TOKEN_FILE_NAME,
                "--minimum-severity",
                "high",
            ],
            environment=environment,
            input_text="4001002003\n",
        )
        assert "configured=true" in cli_output
        assert "staging_file_ready=true" in cli_output
        assert TOKEN_FILE_NAME not in cli_output
        assert "4001002003" not in cli_output
        assert TOKEN_ONE not in cli_output
        assert TOKEN_TWO not in cli_output
        admin_isolation = _run(
            [
                *compose,
                "run",
                "--rm",
                "-T",
                "--entrypoint",
                "python",
                "telegram-admin",
                "-c",
                "from pathlib import Path; assert not Path('/run/secrets/woland-guard').exists()",
            ],
            environment=environment,
        )
        assert TOKEN_TWO not in admin_isolation
    finally:
        subprocess.run(  # noqa: S603
            [docker, "compose", "down", "--volumes", "--remove-orphans"],
            cwd=PROJECT_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if test_root.exists():
            shutil.rmtree(test_root)
