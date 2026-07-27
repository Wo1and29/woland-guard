"""Fail-closed staging and private-runtime Telegram token handling."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from woland_guard_control_plane.infrastructure.database.models import OutboxErrorCode

STAGING_TOKEN_DIRECTORY = Path("/run/woland-guard-staging/telegram")
RUNTIME_TOKEN_DIRECTORY = Path("/run/secrets/woland-guard/telegram")
TOKEN_MAX_BYTES = 256
TOKEN_FILE_MODE = 0o400
RUNTIME_DIRECTORY_MODE = 0o700
WORKER_UID = 10001
WORKER_GID = 10001


class TelegramTokenFileError(RuntimeError):
    """Safe token lifecycle error carrying only a closed error code."""

    def __init__(self, error_code: OutboxErrorCode) -> None:
        super().__init__("Telegram token file is not safely available.")
        self.error_code = error_code


class TelegramToken:
    """Short-lived secret whose string representations are always redacted."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        self.__value = value

    def reveal_for_http(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "TelegramToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class _FileFingerprint:
    device: int = field(repr=False)
    inode: int = field(repr=False)
    size: int = field(repr=False)
    modified_ns: int = field(repr=False)


@dataclass(frozen=True, slots=True)
class _StagingSnapshot:
    value: bytes = field(repr=False)
    fingerprint: _FileFingerprint = field(repr=False)


def validate_token_file_name(value: object) -> str:
    """Accept one conservative basename and reject every path-like value."""

    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ValueError("Telegram token file name is invalid.")
    if not value[0].isalnum() or not value[0].isascii():
        raise ValueError("Telegram token file name is invalid.")
    if any(
        not (character.isascii() and (character.isalnum() or character in "._-"))
        for character in value
    ):
        raise ValueError("Telegram token file name is invalid.")
    return value


def validate_token_bytes(value: bytes) -> str:
    """Validate only documented local safety properties, not provider grammar."""

    if not 1 <= len(value) <= TOKEN_MAX_BYTES:
        raise ValueError("Telegram token content is invalid.")
    if any(byte < 0x21 or byte > 0x7E for byte in value):
        raise ValueError("Telegram token content is invalid.")
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as error:  # pragma: no cover - byte range rejects first
        raise ValueError("Telegram token content is invalid.") from error


class TelegramTokenSynchronizer:
    """Synchronize one required staging file into a private tmpfs on demand."""

    def __init__(
        self,
        *,
        staging_directory: Path = STAGING_TOKEN_DIRECTORY,
        runtime_directory: Path = RUNTIME_TOKEN_DIRECTORY,
        expected_uid: int = WORKER_UID,
        expected_gid: int = WORKER_GID,
        enforce_posix_metadata: bool = True,
    ) -> None:
        self._staging_directory = staging_directory
        self._runtime_directory = runtime_directory
        self._expected_uid = expected_uid
        self._expected_gid = expected_gid
        self._enforce_posix_metadata = enforce_posix_metadata
        self._fingerprints: dict[str, _FileFingerprint] = {}

    def staging_file_ready(self, token_file_name: str) -> bool:
        """Report staging readiness without claiming access to worker-private state."""

        try:
            self._read_staging(validate_token_file_name(token_file_name))
        except (OSError, ValueError, TelegramTokenFileError):
            return False
        return True

    def token_for_delivery(self, token_file_name: str) -> TelegramToken:
        """Fail closed unless staging and the resulting private copy are both valid."""

        try:
            name = validate_token_file_name(token_file_name)
        except ValueError:
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID) from None
        snapshot = self._read_staging(name)
        if self._fingerprints.get(name) == snapshot.fingerprint:
            try:
                return TelegramToken(self._read_runtime(name))
            except TelegramTokenFileError:
                pass
        try:
            self._publish_runtime(name, snapshot.value)
        except TelegramTokenFileError:
            raise TelegramTokenFileError(
                OutboxErrorCode.TELEGRAM_RUNTIME_COPY_UNAVAILABLE
            ) from None
        try:
            value = self._read_runtime(name)
        except TelegramTokenFileError:
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_RUNTIME_COPY_INVALID) from None
        self._fingerprints[name] = snapshot.fingerprint
        return TelegramToken(value)

    def _read_staging(self, name: str) -> _StagingSnapshot:
        self._validate_staging_directory()
        path = self._staging_directory / name
        try:
            before = path.lstat()
        except FileNotFoundError:
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_STAGING_FILE_MISSING) from None
        except OSError:
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID) from None
        if not stat.S_ISREG(before.st_mode) or before.st_size > TOKEN_MAX_BYTES:
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                _require_same_file(before, opened)
                value = _read_bounded(descriptor)
                after = os.fstat(descriptor)
                _require_same_file(opened, after)
                validate_token_bytes(value)
            finally:
                os.close(descriptor)
        except TelegramTokenFileError:
            raise
        except (OSError, ValueError):
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID) from None
        return _StagingSnapshot(value=value, fingerprint=_fingerprint(after))

    def _validate_staging_directory(self) -> None:
        try:
            metadata = self._staging_directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError("staging token directory is invalid")
        except FileNotFoundError:
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_STAGING_FILE_MISSING) from None
        except OSError:
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID) from None

    def _publish_runtime(self, name: str, value: bytes) -> None:
        self._validate_runtime_directory()
        temporary_name = f".pending-{uuid4().hex}"
        temporary_path = self._runtime_directory / temporary_name
        final_path = self._runtime_directory / name
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary_path, flags, 0o600)
            created = os.fstat(descriptor)
            self._require_runtime_owner(created)
            if not stat.S_ISREG(created.st_mode):
                raise OSError("runtime temporary file is not regular")
            _set_descriptor_mode(descriptor, temporary_path, 0o600)
            _write_all(descriptor, value)
            os.fsync(descriptor)
            if self._enforce_posix_metadata:
                _set_descriptor_mode(descriptor, temporary_path, TOKEN_FILE_MODE)
            published = os.fstat(descriptor)
            self._require_runtime_owner(published)
            if self._enforce_posix_metadata and stat.S_IMODE(published.st_mode) != TOKEN_FILE_MODE:
                raise OSError("runtime token mode is invalid")
            os.close(descriptor)
            descriptor = None
            os.replace(temporary_path, final_path)
            if os.name == "posix":
                directory_descriptor = os.open(
                    self._runtime_directory,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        except OSError:
            raise TelegramTokenFileError(
                OutboxErrorCode.TELEGRAM_RUNTIME_COPY_UNAVAILABLE
            ) from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _read_runtime(self, name: str) -> str:
        self._validate_runtime_directory()
        path = self._runtime_directory / name
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                raise OSError("runtime token is not regular")
            self._require_runtime_owner(before)
            if self._enforce_posix_metadata and stat.S_IMODE(before.st_mode) != TOKEN_FILE_MODE:
                raise OSError("runtime token mode is invalid")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                _require_same_file(before, opened)
                self._require_runtime_owner(opened)
                if self._enforce_posix_metadata and stat.S_IMODE(opened.st_mode) != TOKEN_FILE_MODE:
                    raise OSError("runtime token mode is invalid")
                value = _read_bounded(descriptor)
                after = os.fstat(descriptor)
                _require_same_file(opened, after)
            finally:
                os.close(descriptor)
            return validate_token_bytes(value)
        except (OSError, ValueError):
            raise TelegramTokenFileError(OutboxErrorCode.TELEGRAM_RUNTIME_COPY_INVALID) from None

    def _validate_runtime_directory(self) -> None:
        try:
            metadata = self._runtime_directory.lstat()
        except OSError:
            raise TelegramTokenFileError(
                OutboxErrorCode.TELEGRAM_RUNTIME_COPY_UNAVAILABLE
            ) from None
        try:
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError("runtime token directory is invalid")
            self._require_runtime_owner(metadata)
            if (
                self._enforce_posix_metadata
                and stat.S_IMODE(metadata.st_mode) != RUNTIME_DIRECTORY_MODE
            ):
                raise OSError("runtime token directory mode is invalid")
        except OSError:
            raise TelegramTokenFileError(
                OutboxErrorCode.TELEGRAM_RUNTIME_COPY_UNAVAILABLE
            ) from None

    def _require_runtime_owner(self, metadata: os.stat_result) -> None:
        if self._enforce_posix_metadata and (
            metadata.st_uid != self._expected_uid or metadata.st_gid != self._expected_gid
        ):
            raise OSError("runtime token ownership is invalid")


def _fingerprint(metadata: os.stat_result) -> _FileFingerprint:
    return _FileFingerprint(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
    )


def _require_same_file(first: os.stat_result, second: os.stat_result) -> None:
    if _fingerprint(first) != _fingerprint(second):
        raise OSError("token file changed during secure read")


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = TOKEN_MAX_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) > TOKEN_MAX_BYTES:
        raise ValueError("token file is too large")
    return value


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError("runtime token write failed")
        offset += written


def _set_descriptor_mode(descriptor: int, path: Path, mode: int) -> None:
    if os.name == "posix":
        os.fchmod(descriptor, mode)  # type: ignore[attr-defined]
    else:  # pragma: no cover - production worker is a Linux container
        os.chmod(path, mode)
