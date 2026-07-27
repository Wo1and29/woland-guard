"""Safe staging validation and on-demand runtime token synchronization."""

import os
import stat
import traceback
from pathlib import Path

import pytest

from woland_guard_control_plane.infrastructure.database.models import OutboxErrorCode
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramTokenFileError,
    TelegramTokenSynchronizer,
    validate_token_bytes,
    validate_token_file_name,
)

TOKEN_ONE = "synthetic-token-one"  # noqa: S105
TOKEN_TWO = "synthetic-token-two"  # noqa: S105


def _effective_uid() -> int:
    return int(os.geteuid())  # type: ignore[attr-defined]


def _effective_gid() -> int:
    return int(os.getegid())  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "value",
    ["", "../token", "nested/token", "nested\\token", ".hidden", "имя", "a" * 129],
)
def test_token_file_name_rejects_paths_and_unsafe_names(value: str) -> None:
    with pytest.raises(ValueError):
        validate_token_file_name(value)


@pytest.mark.parametrize(
    "value",
    [b"", b"has space", b"line\nnext", b"nul\0value", b"\xff", b"x" * 257],
)
def test_token_content_accepts_only_bounded_single_line_ascii(value: bytes) -> None:
    with pytest.raises(ValueError):
        validate_token_bytes(value)
    assert validate_token_bytes(b"opaque-future-token") == "opaque-future-token"
    assert validate_token_bytes(b"future:token/_?%#") == "future:token/_?%#"


def test_new_file_and_atomic_rotation_are_used_without_restart(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    synchronizer = TelegramTokenSynchronizer(
        staging_directory=staging,
        runtime_directory=runtime,
        enforce_posix_metadata=False,
    )
    name = "bot.token"
    (staging / name).write_text(TOKEN_ONE, encoding="ascii")

    assert synchronizer.token_for_delivery(name).reveal_for_http() == TOKEN_ONE
    replacement = staging / "replacement"
    replacement.write_text(TOKEN_TWO, encoding="ascii")
    os.replace(replacement, staging / name)

    assert synchronizer.token_for_delivery(name).reveal_for_http() == TOKEN_TWO


def test_invalid_rotation_preserves_previous_copy_but_fails_closed(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    synchronizer = TelegramTokenSynchronizer(
        staging_directory=staging,
        runtime_directory=runtime,
        enforce_posix_metadata=False,
    )
    name = "bot.token"
    (staging / name).write_text(TOKEN_ONE, encoding="ascii")
    synchronizer.token_for_delivery(name)
    previous = (runtime / name).read_bytes()
    replacement = staging / "replacement"
    replacement.write_bytes(b"broken\nrotation")
    os.replace(replacement, staging / name)

    with pytest.raises(TelegramTokenFileError) as captured:
        synchronizer.token_for_delivery(name)

    assert captured.value.error_code is OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID
    assert (runtime / name).read_bytes() == previous
    assert TOKEN_ONE not in str(captured.value)


def test_missing_staging_does_not_use_preserved_runtime_copy(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    synchronizer = TelegramTokenSynchronizer(
        staging_directory=staging,
        runtime_directory=runtime,
        enforce_posix_metadata=False,
    )
    name = "bot.token"
    path = staging / name
    path.write_text(TOKEN_ONE, encoding="ascii")
    synchronizer.token_for_delivery(name)
    path.unlink()

    with pytest.raises(TelegramTokenFileError) as captured:
        synchronizer.token_for_delivery(name)

    assert captured.value.error_code is OutboxErrorCode.TELEGRAM_STAGING_FILE_MISSING
    assert (runtime / name).exists()


def test_staging_symlink_is_rejected(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink is unavailable")
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    target = staging / "target"
    target.write_text(TOKEN_ONE, encoding="ascii")
    try:
        os.symlink(target, staging / "bot.token")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    synchronizer = TelegramTokenSynchronizer(
        staging_directory=staging,
        runtime_directory=runtime,
        enforce_posix_metadata=False,
    )
    assert synchronizer.staging_file_ready("bot.token") is False


def test_token_file_error_rendering_suppresses_sensitive_path(tmp_path: Path) -> None:
    canary_path = tmp_path / "sensitive-canary-directory"
    synchronizer = TelegramTokenSynchronizer(
        staging_directory=canary_path,
        runtime_directory=tmp_path / "runtime",
        enforce_posix_metadata=False,
    )

    with pytest.raises(TelegramTokenFileError) as captured:
        synchronizer.token_for_delivery("bot.token")

    rendered = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert "sensitive-canary-directory" not in rendered


@pytest.mark.skipif(os.name != "posix", reason="POSIX metadata is verified in Linux suite")
def test_posix_runtime_copy_has_private_owner_and_modes(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    name = "bot.token"
    (staging / name).write_text(TOKEN_ONE, encoding="ascii")
    synchronizer = TelegramTokenSynchronizer(
        staging_directory=staging,
        runtime_directory=runtime,
        expected_uid=_effective_uid(),
        expected_gid=_effective_gid(),
    )

    assert synchronizer.token_for_delivery(name).reveal_for_http() == TOKEN_ONE
    metadata = (runtime / name).stat()
    assert metadata.st_uid == _effective_uid()
    assert metadata.st_gid == _effective_gid()
    assert stat.S_IMODE(metadata.st_mode) == 0o400
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
