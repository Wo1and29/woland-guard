"""Closed-environment, bounded process-tree supervision for 8B commands."""

from __future__ import annotations

import contextlib
import ctypes
import os
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any, BinaryIO, Final

from scripts.demo_e2e.contracts import DemoE2EError

DEFAULT_OUTPUT_LIMIT: Final = 1_048_576
MAX_INPUT_BYTES: Final = 256 * 1_048_576
STREAM_CHUNK_BYTES: Final = 65_536
PROCESS_POLL_SECONDS: Final = 0.02
TERMINATE_GRACE_SECONDS: Final = 1.0
KILL_GRACE_SECONDS: Final = 5.0

_WINDOWS_INHERITED_ENVIRONMENT: Final = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)
_POSIX_INHERITED_ENVIRONMENT: Final = frozenset({"PATH"})
_EXPLICIT_ENVIRONMENT: Final = frozenset(
    {
        "COMPOSE_ANSI",
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "PATH",
        "PLAYWRIGHT_BROWSERS_PATH",
        "PYTHONDONTWRITEBYTECODE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "UV_CACHE_DIR",
        "UV_NO_PROGRESS",
        "UV_PROJECT_ENVIRONMENT",
        "WG_DEMO_OWNERSHIP",
        "WG_DEMO_POSTGRES_PASSWORD",
        "WG_RUN_CLEAN_INSTALL",
        "WG_RUN_DEMO_E2E",
    }
)

_SHUTDOWN_REQUESTED = threading.Event()


class DemoCommandError(DemoE2EError):
    """A command failed without exposing arguments, environment or process output."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes = field(repr=False)

    def text(self) -> str:
        try:
            return self.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise DemoCommandError("demo command returned invalid text output") from None


@dataclass(slots=True)
class _StreamCapture:
    limit: int
    output: BinaryIO | None = field(default=None, repr=False)
    content: bytearray = field(default_factory=bytearray, repr=False)
    total: int = 0
    overflow: threading.Event = field(default_factory=threading.Event, repr=False)
    failed: threading.Event = field(default_factory=threading.Event, repr=False)


def shutdown_requested() -> bool:
    return _SHUTDOWN_REQUESTED.is_set()


def request_shutdown() -> None:
    _SHUTDOWN_REQUESTED.set()


def raise_if_shutdown_requested() -> None:
    if shutdown_requested():
        raise DemoCommandError("demo shutdown was requested")


@contextlib.contextmanager
def cooperative_signal_handlers() -> Iterator[None]:
    """Translate supported signals into an idempotent cooperative shutdown request."""

    if threading.current_thread() is not threading.main_thread():
        raise DemoCommandError("demo signal handling requires the main thread")
    _SHUTDOWN_REQUESTED.clear()
    handled = [signal.SIGINT]
    if hasattr(signal, "SIGTERM"):
        handled.append(signal.SIGTERM)
    previous: dict[signal.Signals, Any] = {}

    def _handler(_signum: int, _frame: FrameType | None) -> None:
        request_shutdown()

    try:
        for handled_signal in handled:
            previous[handled_signal] = signal.getsignal(handled_signal)
            signal.signal(handled_signal, _handler)
        yield
    finally:
        for handled_signal, old_handler in previous.items():
            signal.signal(handled_signal, old_handler)
        _SHUTDOWN_REQUESTED.clear()


def build_child_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the closed child environment without inheriting credentials or proxies."""

    inherited_names = (
        _WINDOWS_INHERITED_ENVIRONMENT if os.name == "nt" else _POSIX_INHERITED_ENVIRONMENT
    )
    result = {
        name: value
        for name in inherited_names
        if (value := os.environ.get(name)) is not None and "\x00" not in value
    }
    if os.name == "nt":
        result.setdefault("NO_PROXY", "127.0.0.1,localhost")
    else:
        result.update(
            {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "NO_PROXY": "127.0.0.1,localhost",
            }
        )
    if overrides is None:
        return result
    for key, value in overrides.items():
        if (
            type(key) is not str
            or type(value) is not str
            or key not in _EXPLICIT_ENVIRONMENT
            or "\x00" in key + value
        ):
            raise DemoCommandError("demo command environment is invalid")
        result[key] = value
    return result


class CommandRunner:
    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: float = 60.0,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
        check: bool = True,
        stdin: bytes | None = None,
        stdin_path: Path | None = None,
        input_limit: int = MAX_INPUT_BYTES,
        respect_shutdown: bool = True,
    ) -> CommandResult:
        return self._execute(
            arguments,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            check=check,
            stdin=stdin,
            stdin_path=stdin_path,
            input_limit=input_limit,
            output_path=None,
            respect_shutdown=respect_shutdown,
        )

    def run_to_file(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        output_path: Path,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: float = 60.0,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
        check: bool = True,
        stdin_path: Path | None = None,
        input_limit: int = MAX_INPUT_BYTES,
        respect_shutdown: bool = True,
    ) -> CommandResult:
        return self._execute(
            arguments,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            check=check,
            stdin=None,
            stdin_path=stdin_path,
            input_limit=input_limit,
            output_path=output_path,
            respect_shutdown=respect_shutdown,
        )

    def _execute(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str] | None,
        timeout_seconds: float,
        output_limit: int,
        check: bool,
        stdin: bytes | None,
        stdin_path: Path | None,
        input_limit: int,
        output_path: Path | None,
        respect_shutdown: bool,
    ) -> CommandResult:
        _validate_request(
            arguments,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            stdin=stdin,
            stdin_path=stdin_path,
            input_limit=input_limit,
            output_path=output_path,
        )
        if respect_shutdown:
            raise_if_shutdown_requested()
        child_environment = build_child_environment(environment)
        output_file: BinaryIO | None = None
        input_file: BinaryIO | None = None
        process: subprocess.Popen[bytes] | None = None
        job: Any = None
        succeeded = False
        try:
            if output_path is not None:
                descriptor = os.open(
                    output_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                output_file = os.fdopen(descriptor, "wb", closefd=True)
            if stdin_path is not None:
                input_file = stdin_path.open("rb")
            creation_flags = 0
            start_new_session = os.name != "nt"
            if os.name == "nt":
                creation_flags = int(getattr(subprocess, "CREATE_SUSPENDED", 0x00000004))
            process = subprocess.Popen(  # noqa: S603 - validated closed argv; shell is never used
                list(arguments),
                cwd=cwd,
                env=child_environment,
                stdin=subprocess.PIPE if stdin is not None or input_file is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=start_new_session,
                creationflags=creation_flags,
            )
            if os.name == "nt":
                job = _assign_windows_job_and_resume(process)
            result = _communicate_bounded(
                process,
                job=job,
                stdin=stdin,
                input_file=input_file,
                input_limit=input_limit,
                output_file=output_file,
                output_limit=output_limit,
                deadline=time.monotonic() + timeout_seconds,
                respect_shutdown=respect_shutdown,
            )
            if output_file is not None:
                output_file.flush()
                os.fsync(output_file.fileno())
            if check and result.returncode != 0:
                raise DemoCommandError("demo command failed safely")
            succeeded = True
            return result
        except DemoCommandError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise DemoCommandError("demo command failed safely") from None
        finally:
            if process is not None and process.poll() is None:
                _terminate_process_tree(process, job)
            if job is not None:
                _close_windows_job(job)
            if input_file is not None:
                input_file.close()
            if output_file is not None:
                output_file.close()
            if not succeeded and output_path is not None:
                _unlink_regular_file(output_path)


def _validate_request(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    output_limit: int,
    stdin: bytes | None,
    stdin_path: Path | None,
    input_limit: int,
    output_path: Path | None,
) -> None:
    if (
        not arguments
        or any(type(value) is not str or not value or "\x00" in value for value in arguments)
        or not cwd.is_absolute()
        or not cwd.is_dir()
        or timeout_seconds <= 0
        or not 1 <= output_limit <= 512 * 1_048_576
        or not 1 <= input_limit <= MAX_INPUT_BYTES
        or (stdin is not None and stdin_path is not None)
        or (stdin is not None and len(stdin) > input_limit)
    ):
        raise DemoCommandError("demo command request is invalid")
    if stdin_path is not None:
        _validate_regular_file(stdin_path, maximum=input_limit)
    if output_path is not None:
        if not output_path.is_absolute() or output_path.exists() or not output_path.parent.is_dir():
            raise DemoCommandError("demo command output path is invalid")


def _communicate_bounded(
    process: subprocess.Popen[bytes],
    *,
    job: Any,
    stdin: bytes | None,
    input_file: BinaryIO | None,
    input_limit: int,
    output_file: BinaryIO | None,
    output_limit: int,
    deadline: float,
    respect_shutdown: bool,
) -> CommandResult:
    if process.stdout is None or process.stderr is None:
        raise DemoCommandError("demo process pipes are unavailable")
    stdout_capture = _StreamCapture(limit=output_limit, output=output_file)
    stderr_capture = _StreamCapture(limit=DEFAULT_OUTPUT_LIMIT)
    workers = [
        threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_capture),
            name="wg8b-stdout-drain",
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_capture),
            name="wg8b-stderr-drain",
            daemon=True,
        ),
    ]
    if process.stdin is not None:
        workers.append(
            threading.Thread(
                target=_write_stdin,
                args=(process.stdin, stdin, input_file, input_limit),
                name="wg8b-stdin-writer",
                daemon=True,
            )
        )
    for worker in workers:
        worker.start()
    failure: str | None = None
    while process.poll() is None:
        if stdout_capture.overflow.is_set() or stderr_capture.overflow.is_set():
            failure = "demo command output exceeded the safe limit"
            break
        if stdout_capture.failed.is_set() or stderr_capture.failed.is_set():
            failure = "demo command streaming failed safely"
            break
        if respect_shutdown and shutdown_requested():
            failure = "demo shutdown was requested"
            break
        if time.monotonic() >= deadline:
            failure = "demo command timed out safely"
            break
        time.sleep(PROCESS_POLL_SECONDS)
    if failure is not None:
        _terminate_process_tree(process, job)
    for worker in workers:
        remaining = max(0.0, deadline - time.monotonic()) if failure is None else KILL_GRACE_SECONDS
        worker.join(timeout=min(KILL_GRACE_SECONDS, remaining))
    if any(worker.is_alive() for worker in workers):
        _terminate_process_tree(process, job)
        raise DemoCommandError("demo command streaming did not stop safely")
    if process.poll() is None:
        _terminate_process_tree(process, job)
    if failure is not None:
        raise DemoCommandError(failure)
    if stdout_capture.overflow.is_set() or stderr_capture.overflow.is_set():
        raise DemoCommandError("demo command output exceeded the safe limit")
    if stdout_capture.failed.is_set() or stderr_capture.failed.is_set():
        raise DemoCommandError("demo command streaming failed safely")
    _ensure_process_tree_stopped(process, job)
    return CommandResult(returncode=int(process.returncode), stdout=bytes(stdout_capture.content))


def _drain_stream(stream: BinaryIO, capture: _StreamCapture) -> None:
    try:
        while True:
            chunk = stream.read(STREAM_CHUNK_BYTES)
            if not chunk:
                return
            capture.total += len(chunk)
            if capture.total > capture.limit:
                capture.overflow.set()
                return
            if capture.output is None:
                capture.content.extend(chunk)
            else:
                capture.output.write(chunk)
    except (OSError, ValueError):
        capture.failed.set()
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _write_stdin(
    stream: BinaryIO,
    content: bytes | None,
    source: BinaryIO | None,
    limit: int,
) -> None:
    total = 0
    try:
        if content is not None:
            source_chunks: Iterator[bytes] = iter(
                content[offset : offset + STREAM_CHUNK_BYTES]
                for offset in range(0, len(content), STREAM_CHUNK_BYTES)
            )
        elif source is not None:
            source_chunks = iter(lambda: source.read(STREAM_CHUNK_BYTES), b"")
        else:
            source_chunks = iter(())
        for chunk in source_chunks:
            total += len(chunk)
            if total > limit:
                return
            stream.write(chunk)
            stream.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _terminate_process_tree(process: subprocess.Popen[bytes], job: Any) -> None:
    if os.name == "nt":
        descendant_handles = _open_windows_descendant_handles(process.pid)
        try:
            if job is not None and not _windows_job_is_empty(job):
                _terminate_windows_job(job)
            elif process.poll() is None:
                with contextlib.suppress(OSError):
                    process.terminate()
            _terminate_exact_windows_handles(descendant_handles)
            _wait_process(process, KILL_GRACE_SECONDS)
            if job is not None and not _wait_windows_job_empty(job, KILL_GRACE_SECONDS):
                raise DemoCommandError("demo process tree could not be terminated safely")
        finally:
            _close_windows_handles(descendant_handles)
    else:
        if process.poll() is None:
            _signal_posix_group(process, signal.SIGTERM)
            _wait_process(process, TERMINATE_GRACE_SECONDS)
        if process.poll() is None:
            _signal_posix_group(process, signal.Signals(9))
            _wait_process(process, KILL_GRACE_SECONDS)
        if process.poll() is None:
            raise DemoCommandError("demo process tree could not be terminated safely")


def _ensure_process_tree_stopped(process: subprocess.Popen[bytes], job: Any) -> None:
    if process.poll() is None:
        raise DemoCommandError("demo process did not terminate safely")
    if os.name == "nt" and job is not None and not _windows_job_is_empty(job):
        _terminate_windows_job(job)
        if not _wait_windows_job_empty(job, KILL_GRACE_SECONDS):
            raise DemoCommandError("demo process descendants did not terminate safely")


def _wait_process(process: subprocess.Popen[bytes], timeout: float) -> None:
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return


def _signal_posix_group(process: subprocess.Popen[bytes], requested_signal: signal.Signals) -> None:
    try:
        get_process_group: Any = os.__dict__["getpgid"]
        group = int(get_process_group(process.pid))
    except (OSError, ProcessLookupError):
        return
    if group != process.pid:
        raise DemoCommandError("demo process group identity changed")
    with contextlib.suppress(ProcessLookupError):
        kill_process_group: Any = os.__dict__["killpg"]
        kill_process_group(group, requested_signal)


def _assign_windows_job_and_resume(process: subprocess.Popen[bytes]) -> Any:
    kernel32 = _windows_kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        _kill_unassigned_process(process)
        raise DemoCommandError("demo Windows Job Object creation failed")
    try:
        _configure_windows_job(kernel32, job)
        process_handle = kernel32.OpenProcess(
            0x0100 | 0x0001 | 0x0400 | 0x00100000, False, process.pid
        )
        if not process_handle:
            raise OSError("OpenProcess failed")
        try:
            if not kernel32.AssignProcessToJobObject(job, process_handle):
                raise OSError("AssignProcessToJobObject failed")
        finally:
            kernel32.CloseHandle(process_handle)
        _resume_windows_process_threads(kernel32, process.pid)
        return job
    except Exception:
        with contextlib.suppress(Exception):
            kernel32.TerminateJobObject(job, 1)
        kernel32.CloseHandle(job)
        _kill_unassigned_process(process)
        raise DemoCommandError("demo Windows Job Object assignment failed") from None


def _configure_windows_job(kernel32: Any, job: Any) -> None:
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    information = _ExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(information), ctypes.sizeof(information)
    ):
        raise OSError("SetInformationJobObject failed")


def _resume_windows_process_threads(kernel32: Any, process_id: int) -> None:
    from ctypes import wintypes

    class _ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot == invalid_handle:
        raise OSError("CreateToolhelp32Snapshot failed")
    resumed = 0
    try:
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        success = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
        while success:
            if entry.th32OwnerProcessID == process_id:
                thread_handle = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)
                if not thread_handle:
                    raise OSError("OpenThread failed")
                try:
                    if kernel32.ResumeThread(thread_handle) == 0xFFFFFFFF:
                        raise OSError("ResumeThread failed")
                    resumed += 1
                finally:
                    kernel32.CloseHandle(thread_handle)
            success = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
    finally:
        kernel32.CloseHandle(snapshot)
    if resumed == 0:
        raise OSError("suspended process thread was unavailable")


def _windows_job_is_empty(job: Any) -> bool:
    return _query_windows_job_active_processes(job) == 0


def _wait_windows_job_empty(job: Any, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _windows_job_is_empty(job):
            return True
        time.sleep(PROCESS_POLL_SECONDS)
    return _windows_job_is_empty(job)


def _query_windows_job_active_processes(job: Any) -> int:
    from ctypes import wintypes

    class _BasicAccountingInformation(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    kernel32 = _windows_kernel32()
    information = _BasicAccountingInformation()
    if not kernel32.QueryInformationJobObject(
        job, 1, ctypes.byref(information), ctypes.sizeof(information), None
    ):
        raise DemoCommandError("demo Windows Job Object query failed")
    return int(information.ActiveProcesses)


def _terminate_windows_job(job: Any) -> None:
    kernel32 = _windows_kernel32()
    if not kernel32.TerminateJobObject(job, 1):
        raise DemoCommandError("demo Windows process tree termination failed")


def _close_windows_job(job: Any) -> None:
    kernel32 = _windows_kernel32()
    if not kernel32.CloseHandle(job):
        raise DemoCommandError("demo Windows Job Object close failed")


def _kill_unassigned_process(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(OSError):
        process.kill()
    _wait_process(process, KILL_GRACE_SECONDS)


def _windows_kernel32() -> Any:
    from ctypes import wintypes

    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    return kernel32


def _open_windows_descendant_handles(root_process_id: int) -> tuple[Any, ...]:
    from ctypes import wintypes

    class _ProcessEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = _windows_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise DemoCommandError("demo Windows process snapshot failed")
    parents: dict[int, int] = {}
    try:
        entry = _ProcessEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        success = bool(kernel32.Process32FirstW(snapshot, ctypes.byref(entry)))
        while success:
            parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            success = bool(kernel32.Process32NextW(snapshot, ctypes.byref(entry)))
    finally:
        kernel32.CloseHandle(snapshot)
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for process_id, parent_id in parents.items():
            if process_id == root_process_id or process_id in descendants:
                continue
            if parent_id == root_process_id or parent_id in descendants:
                descendants.add(process_id)
                changed = True
    handles: list[Any] = []
    try:
        for process_id in sorted(descendants):
            handle = kernel32.OpenProcess(
                0x0001 | 0x00100000 | 0x0400,
                False,
                process_id,
            )
            if not handle:
                continue
            handles.append(handle)
        return tuple(handles)
    except Exception:
        _close_windows_handles(tuple(handles))
        raise DemoCommandError("demo Windows descendant identity failed") from None


def _terminate_exact_windows_handles(handles: tuple[Any, ...]) -> None:
    kernel32 = _windows_kernel32()
    for handle in reversed(handles):
        if kernel32.WaitForSingleObject(handle, 0) == 0x00000102:
            if not kernel32.TerminateProcess(handle, 1) and (
                kernel32.WaitForSingleObject(handle, 250) == 0x00000102
            ):
                raise DemoCommandError("demo Windows descendant termination failed")
    for handle in handles:
        if kernel32.WaitForSingleObject(handle, int(KILL_GRACE_SECONDS * 1_000)) == 0x00000102:
            raise DemoCommandError("demo Windows descendant did not terminate safely")


def _close_windows_handles(handles: tuple[Any, ...]) -> None:
    kernel32 = _windows_kernel32()
    for handle in handles:
        kernel32.CloseHandle(handle)


def _validate_regular_file(path: Path, *, maximum: int) -> None:
    if not path.is_absolute():
        raise DemoCommandError("demo command input path is invalid")
    try:
        metadata = path.lstat()
    except OSError:
        raise DemoCommandError("demo command input path is invalid") from None
    reparse = bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )
    if (
        not __import__("stat").S_ISREG(metadata.st_mode)
        or reparse
        or not 0 <= metadata.st_size <= maximum
    ):
        raise DemoCommandError("demo command input path is invalid")


def _unlink_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    reparse = bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )
    if not __import__("stat").S_ISREG(metadata.st_mode) or reparse:
        raise DemoCommandError("demo command partial output identity changed")
    path.unlink()


def isolated_home_path(root: Path) -> Path:
    """Create a private isolated HOME for POSIX child tools."""

    path = root / "home"
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def default_temporary_root() -> Path:
    return Path(tempfile.gettempdir()).resolve(strict=True)
