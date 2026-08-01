"""Bounded tracked-only checkout creation with two-pass safe tar extraction."""

from __future__ import annotations

import os
import re
import shutil
import stat
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from scripts.demo_e2e.commands import CommandRunner, DemoCommandError
from scripts.demo_e2e.contracts import CleanCheckoutMetadata, DemoE2EError

MAX_ARCHIVE_BYTES: Final = 128 * 1_048_576
MAX_MEMBERS: Final = 20_000
MAX_MEMBER_BYTES: Final = 64 * 1_048_576
MAX_EXTRACTED_BYTES: Final = 256 * 1_048_576
MAX_METADATA_BYTES: Final = 2 * 1_048_576
FORBIDDEN_ROOT_NAMES: Final = frozenset(
    {".git", ".env", ".venv", ".playwright-browsers", ".pytest_cache", ".pytest-tmp"}
)
SUPPORTED_PAX_KEYS: Final = frozenset({"comment", "path"})
HEX_HEAD: Final = re.compile(r"^[0-9a-f]{40}$")
REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)


class CleanArchiveError(DemoE2EError):
    """A tracked-only archive could not be created or extracted safely."""


@dataclass(frozen=True, slots=True)
class _PreparedMember:
    member: tarfile.TarInfo
    relative: PurePosixPath
    is_directory: bool


def create_clean_checkout(source_root: Path) -> CleanCheckoutMetadata:
    source = source_root.resolve(strict=True)
    head = _git_text(source, ["git", "rev-parse", "HEAD"])
    if _git_text(source, ["git", "status", "--short"]):
        raise CleanArchiveError("source worktree is not clean")
    temporary_root = Path(tempfile.mkdtemp(prefix="wg8b-clean-"))
    archive_path = temporary_root / "source.tar"
    checkout_root = temporary_root / "checkout"
    try:
        _write_git_archive(source, archive_path)
        extract_tracked_archive(archive_path, checkout_root)
        archive_path.unlink()
        _audit_checkout_root(checkout_root)
        return CleanCheckoutMetadata(source_head=head, checkout_root=checkout_root)
    except Exception:
        _remove_private_tree(temporary_root)
        raise CleanArchiveError("tracked-only checkout creation failed") from None


def remove_clean_checkout(metadata: CleanCheckoutMetadata) -> None:
    root = metadata.checkout_root.parent.resolve(strict=False)
    if metadata.checkout_root.parent != root or not root.name.startswith("wg8b-clean-"):
        raise CleanArchiveError("clean checkout cleanup identity is invalid")
    _remove_private_tree(root)
    if root.exists():
        raise CleanArchiveError("clean checkout cleanup failed")


def extract_tracked_archive(archive_path: Path, destination: Path) -> None:
    archive = archive_path.resolve(strict=True)
    if destination.exists() or not destination.is_absolute():
        raise CleanArchiveError("tracked archive destination must be a new absolute path")
    target_parent = _real_directory(destination.parent)
    target = target_parent / destination.name
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise CleanArchiveError("tracked archive exceeds the safe size limit")
    _preflight_raw_headers(archive)
    created_identity: tuple[int, int] | None = None
    try:
        with tarfile.open(archive, mode="r:") as bundle:
            prepared = _preflight_members(bundle)
            target.mkdir(mode=0o700)
            target_metadata = target.lstat()
            created_identity = (target_metadata.st_dev, target_metadata.st_ino)
            extracted_bytes = 0
            for item in prepared:
                output = target.joinpath(*item.relative.parts)
                if item.is_directory:
                    _create_directory_chain(target, item.relative.parts)
                    continue
                _create_directory_chain(target, item.relative.parts[:-1])
                source = bundle.extractfile(item.member)
                if source is None:
                    raise CleanArchiveError("tracked archive member could not be read")
                # Without O_BINARY, Windows opens the descriptor in text mode and
                # os.write() rewrites every "\n" to "\r\n", corrupting tar members
                # (e.g. git-archived CRLF text) that already contain "\r\n".
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_BINARY", 0)
                )
                descriptor = os.open(output, flags, 0o600)
                written = 0
                try:
                    while written < item.member.size:
                        chunk = source.read(min(65_536, item.member.size - written))
                        if not chunk:
                            raise CleanArchiveError("tracked archive member was truncated")
                        offset = 0
                        while offset < len(chunk):
                            count = os.write(descriptor, chunk[offset:])
                            if count <= 0:
                                raise CleanArchiveError("tracked archive extraction failed")
                            offset += count
                        written += len(chunk)
                    if source.read(1):
                        raise CleanArchiveError("tracked archive member exceeded declared size")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                    source.close()
                extracted_bytes += written
                if extracted_bytes > MAX_EXTRACTED_BYTES:
                    raise CleanArchiveError("tracked archive expands beyond the safe limit")
                mode = 0o755 if item.member.mode & stat.S_IXUSR else 0o644
                os.chmod(output, mode)
                _require_regular_non_reparse(output)
    except CleanArchiveError:
        if created_identity is not None:
            _remove_created_tree(target, created_identity)
        raise
    except Exception:
        if created_identity is not None:
            _remove_created_tree(target, created_identity)
        raise CleanArchiveError("tracked archive extraction failed safely") from None


def _preflight_members(bundle: tarfile.TarFile) -> tuple[_PreparedMember, ...]:
    prepared: list[_PreparedMember] = []
    paths: dict[tuple[str, ...], bool] = {}
    casefold_paths: dict[tuple[str, ...], tuple[str, ...]] = {}
    declared_bytes = 0
    metadata_bytes = 0
    for member_count, member in enumerate(bundle, start=1):
        if member_count > MAX_MEMBERS:
            raise CleanArchiveError("tracked archive contains too many entries")
        relative = _safe_member_path(member.name)
        parts = tuple(relative.parts)
        metadata_bytes += len(member.name.encode("utf-8"))
        metadata_bytes += sum(
            len(key.encode("utf-8")) + len(value.encode("utf-8"))
            for key, value in member.pax_headers.items()
        )
        if metadata_bytes > MAX_METADATA_BYTES:
            raise CleanArchiveError("tracked archive metadata exceeds the safe limit")
        _validate_pax_headers(member)
        if (
            member.issym()
            or member.islnk()
            or member.isdev()
            or member.isfifo()
            or bool(getattr(member, "sparse", None))
            or member.type == getattr(tarfile, "GNUTYPE_SPARSE", b"S")
        ):
            raise CleanArchiveError("tracked archive contains a forbidden entry type")
        is_directory = member.isdir()
        if not is_directory and (
            not member.isfile() or member.size < 0 or member.size > MAX_MEMBER_BYTES
        ):
            raise CleanArchiveError("tracked archive contains an invalid file")
        if parts in paths:
            raise CleanArchiveError("tracked archive contains a duplicate normalized path")
        for index in range(1, len(parts)):
            prefix = parts[:index]
            if prefix in paths and not paths[prefix]:
                raise CleanArchiveError("tracked archive contains a file/directory collision")
        if not is_directory and any(
            existing[: len(parts)] == parts and len(existing) > len(parts) for existing in paths
        ):
            raise CleanArchiveError("tracked archive contains a file/directory collision")
        for index in range(1, len(parts) + 1):
            prefix = parts[:index]
            folded = tuple(part.casefold() for part in prefix)
            if os.name == "nt" and (folded in casefold_paths and casefold_paths[folded] != prefix):
                raise CleanArchiveError("tracked archive contains a Windows case-fold collision")
            casefold_paths[folded] = prefix
        paths[parts] = is_directory
        if not is_directory:
            declared_bytes += member.size
            if declared_bytes > MAX_EXTRACTED_BYTES:
                raise CleanArchiveError("tracked archive expands beyond the safe limit")
        prepared.append(
            _PreparedMember(member=member, relative=relative, is_directory=is_directory)
        )
    return tuple(prepared)


def _safe_member_path(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name or re.match(r"^[A-Za-z]:", name):
        raise CleanArchiveError("tracked archive member name is invalid")
    raw_parts = name.split("/")
    normalized_parts: list[str] = []
    for part in raw_parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise CleanArchiveError("tracked archive member path is invalid")
        normalized = unicodedata.normalize("NFC", part)
        if not normalized or "/" in normalized or "\x00" in normalized:
            raise CleanArchiveError("tracked archive member path is invalid")
        normalized_parts.append(normalized)
    path = PurePosixPath(*normalized_parts)
    if not normalized_parts or path.is_absolute() or name.startswith("//"):
        raise CleanArchiveError("tracked archive member path is invalid")
    return path


def _validate_pax_headers(member: tarfile.TarInfo) -> None:
    if set(member.pax_headers) - SUPPORTED_PAX_KEYS:
        raise CleanArchiveError("tracked archive contains unsupported PAX metadata")
    comment = member.pax_headers.get("comment")
    if comment is not None and HEX_HEAD.fullmatch(comment) is None:
        raise CleanArchiveError("tracked archive contains invalid PAX metadata")
    pax_path = member.pax_headers.get("path")
    if pax_path is not None and pax_path != member.name:
        raise CleanArchiveError("tracked archive PAX path is inconsistent")


def _preflight_raw_headers(archive: Path) -> None:
    with archive.open("rb") as source:
        while True:
            header = source.read(512)
            if not header or header == b"\0" * 512:
                return
            if len(header) != 512:
                raise CleanArchiveError("tracked archive header is truncated")
            raw_name = header[:100].split(b"\0", 1)[0]
            raw_prefix = header[345:500].split(b"\0", 1)[0]
            try:
                name = raw_name.decode("utf-8", errors="strict")
                prefix = raw_prefix.decode("utf-8", errors="strict")
                size_field = header[124:136].strip(b"\0 ") or b"0"
                if size_field[0] & 0x80:
                    raise ValueError("base-256 size is unsupported")
                size = int(size_field, 8)
            except (UnicodeDecodeError, ValueError, IndexError):
                raise CleanArchiveError("tracked archive header metadata is invalid") from None
            expanded = f"{prefix}/{name}" if prefix else name
            if expanded.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", expanded):
                raise CleanArchiveError("tracked archive contains an absolute raw path")
            if size < 0 or size > MAX_MEMBER_BYTES + MAX_METADATA_BYTES:
                raise CleanArchiveError("tracked archive raw member size is invalid")
            padded = ((size + 511) // 512) * 512
            if source.seek(padded, os.SEEK_CUR) < 0:
                raise CleanArchiveError("tracked archive header seek failed")


def _create_directory_chain(root: Path, parts: tuple[str, ...]) -> None:
    current = root
    root_identity = root.lstat()
    if not stat.S_ISDIR(root_identity.st_mode) or _is_reparse(root_identity):
        raise CleanArchiveError("tracked archive extraction root identity changed")
    for part in parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            raise CleanArchiveError("tracked archive parent directory is unsafe")


def _real_directory(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    metadata = path.lstat()
    if path != resolved or not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
        raise CleanArchiveError("tracked archive parent directory is unsafe")
    return resolved


def _require_regular_non_reparse(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        raise CleanArchiveError("tracked archive output identity is unsafe")


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT)


def _remove_created_tree(path: Path, identity: tuple[int, int]) -> None:
    metadata = path.lstat()
    if (
        (metadata.st_dev, metadata.st_ino) != identity
        or not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise CleanArchiveError("partial checkout identity changed")
    _remove_private_tree(path)


def _remove_private_tree(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
        raise CleanArchiveError("private cleanup root is unsafe")
    shutil.rmtree(path)


def _write_git_archive(source: Path, output: Path) -> None:
    git_executable = shutil.which("git")
    if git_executable is None:
        raise CleanArchiveError("Git executable is unavailable")
    try:
        CommandRunner().run_to_file(
            [git_executable, "archive", "--format=tar", "HEAD"],
            cwd=source,
            output_path=output,
            timeout_seconds=60,
            output_limit=MAX_ARCHIVE_BYTES,
        )
    except DemoCommandError:
        raise CleanArchiveError("git archive failed safely") from None


def _git_text(source: Path, arguments: list[str]) -> str:
    try:
        return CommandRunner().run(arguments, cwd=source, timeout_seconds=30).text().strip()
    except DemoCommandError:
        raise CleanArchiveError("Git source audit failed safely") from None


def _audit_checkout_root(root: Path) -> None:
    present = {entry.name for entry in root.iterdir()}
    if present & FORBIDDEN_ROOT_NAMES:
        raise CleanArchiveError("tracked-only checkout contains forbidden local state")
