"""Container-only probe for the real staging-to-tmpfs token lifecycle."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from woland_guard_control_plane.infrastructure.database.models import OutboxErrorCode
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    RUNTIME_TOKEN_DIRECTORY,
    STAGING_TOKEN_DIRECTORY,
    TelegramTokenFileError,
    TelegramTokenSynchronizer,
)

TOKEN_FILE_NAME = "docker-canary.token"  # noqa: S105


def _effective_uid() -> int:
    return int(os.geteuid())  # type: ignore[attr-defined]


def _effective_gid() -> int:
    return int(os.getegid())  # type: ignore[attr-defined]


def _capabilities_are_empty() -> bool:
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith("CapEff:"):
            return int(line.split(":", maxsplit=1)[1].strip(), 16) == 0
    return False


def _runtime_state() -> tuple[int, int, int, int]:
    directory = RUNTIME_TOKEN_DIRECTORY.lstat()
    token = (RUNTIME_TOKEN_DIRECTORY / TOKEN_FILE_NAME).lstat()
    return (
        token.st_uid,
        token.st_gid,
        stat.S_IMODE(token.st_mode),
        stat.S_IMODE(directory.st_mode),
    )


def _assert_staging_read_only() -> None:
    try:
        descriptor = os.open(STAGING_TOKEN_DIRECTORY / TOKEN_FILE_NAME, os.O_WRONLY)
    except OSError:
        return
    os.close(descriptor)
    raise AssertionError("staging bind mount is writable")


def _assert_symlink_rejected() -> None:
    staging = Path("/tmp/telegram-symlink-staging")  # noqa: S108
    runtime = Path("/tmp/telegram-symlink-runtime")  # noqa: S108
    staging.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    target = staging / "target"
    target.write_text("synthetic-symlink-token", encoding="ascii")
    os.symlink(target, staging / TOKEN_FILE_NAME)
    synchronizer = TelegramTokenSynchronizer(
        staging_directory=staging,
        runtime_directory=runtime,
        expected_uid=_effective_uid(),
        expected_gid=_effective_gid(),
    )
    assert synchronizer.staging_file_ready(TOKEN_FILE_NAME) is False


def main() -> None:
    assert _effective_uid() == 10001
    assert _effective_gid() == 10001
    assert _capabilities_are_empty()
    _assert_symlink_rejected()
    synchronizer = TelegramTokenSynchronizer()
    assert synchronizer.staging_file_ready(TOKEN_FILE_NAME) is False
    print("STARTED uid=10001 gid=10001 capabilities=none")
    input()
    _assert_staging_read_only()
    first = synchronizer.token_for_delivery(TOKEN_FILE_NAME).reveal_for_http()
    assert _runtime_state() == (10001, 10001, 0o400, 0o700)
    print("READY uid=10001 gid=10001 file_mode=0400 directory_mode=0700 capabilities=none")

    input()
    second = synchronizer.token_for_delivery(TOKEN_FILE_NAME).reveal_for_http()
    assert second != first
    assert _runtime_state() == (10001, 10001, 0o400, 0o700)
    print("ROTATED owner=10001:10001 file_mode=0400")

    input()
    try:
        synchronizer.token_for_delivery(TOKEN_FILE_NAME)
    except TelegramTokenFileError as invalid_error:
        assert invalid_error.error_code is OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID
    else:
        raise AssertionError("invalid staging rotation was accepted")
    assert (RUNTIME_TOKEN_DIRECTORY / TOKEN_FILE_NAME).read_text(encoding="ascii") == second
    print("INVALID_PRESERVED")

    input()
    try:
        synchronizer.token_for_delivery(TOKEN_FILE_NAME)
    except TelegramTokenFileError as missing_error:
        assert missing_error.error_code is OutboxErrorCode.TELEGRAM_STAGING_FILE_MISSING
    else:
        raise AssertionError("missing staging token was accepted")
    assert (RUNTIME_TOKEN_DIRECTORY / TOKEN_FILE_NAME).read_text(encoding="ascii") == second
    print("MISSING_PRESERVED")

    input()


if __name__ == "__main__":
    main()
