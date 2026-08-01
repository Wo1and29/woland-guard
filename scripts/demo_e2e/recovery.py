"""Versioned, canonical and private recovery ledger for exact 8B cleanup."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from scripts.demo_e2e.contracts import (
    DemoE2EError,
    DemoRunIdentity,
    RecoveryArtifact,
    RecoveryArtifactKind,
    RecoveryLedger,
    RecoveryPhase,
    RecoveryResource,
)

MAX_LEDGER_BYTES: Final = 64 * 1_024
REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)


class DemoRecoveryError(DemoE2EError):
    """Recovery metadata or exact cleanup could not be handled safely."""


class RecoveryLedgerStore:
    __slots__ = ("_ledger", "path")

    def __init__(self, *, path: Path, ledger: RecoveryLedger) -> None:
        self.path = path
        self._ledger = ledger

    @classmethod
    def create(cls, path: Path, identity: DemoRunIdentity) -> RecoveryLedgerStore:
        ledger_path = _validate_new_ledger_path(path)
        store = cls(path=ledger_path, ledger=RecoveryLedger.create(identity))
        store._write(initial=True)
        return store

    @classmethod
    def open(cls, path: Path) -> RecoveryLedgerStore:
        ledger_path = _validate_existing_ledger_path(path)
        content = _read_regular_file(ledger_path)
        try:
            decoded = content.decode("utf-8", errors="strict")
            document = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
            ledger = RecoveryLedger.model_validate_json(
                json.dumps(document, ensure_ascii=True, allow_nan=False),
                strict=True,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValidationError,
            ValueError,
            DemoE2EError,
        ):
            raise DemoRecoveryError("recovery ledger is invalid") from None
        if content != _canonical_bytes(ledger):
            raise DemoRecoveryError("recovery ledger is not canonical")
        return cls(path=ledger_path, ledger=ledger)

    @property
    def ledger(self) -> RecoveryLedger:
        return self._ledger

    @property
    def identity(self) -> DemoRunIdentity:
        return DemoRunIdentity.from_run_id(self._ledger.run_id)

    def set_phase(self, phase: RecoveryPhase) -> None:
        self._replace(phase=phase)

    def replace_project_resources(
        self,
        project_name: str,
        resources: Iterable[RecoveryResource],
    ) -> None:
        if project_name not in {
            self._ledger.main_project_name,
            self._ledger.restore_project_name,
        }:
            raise DemoRecoveryError("recovery project identity is invalid")
        replacement = tuple(resources)
        if any(resource.project_name != project_name for resource in replacement):
            raise DemoRecoveryError("recovery resource project is invalid")
        retained = tuple(
            resource for resource in self._ledger.resources if resource.project_name != project_name
        )
        self._replace(resources=tuple(sorted((*retained, *replacement), key=_resource_key)))

    def remove_resource(self, resource: RecoveryResource) -> None:
        if resource not in self._ledger.resources:
            raise DemoRecoveryError("recovery resource identity is not recorded")
        self._replace(resources=tuple(item for item in self._ledger.resources if item != resource))

    def add_artifact(self, kind: RecoveryArtifactKind, path: Path) -> None:
        artifact = RecoveryArtifact(kind=kind, path=str(path))
        if artifact in self._ledger.artifacts:
            raise DemoRecoveryError("recovery artifact identity is duplicated")
        self._replace(
            artifacts=tuple(sorted((*self._ledger.artifacts, artifact), key=_artifact_key))
        )

    def remove_artifact(self, kind: RecoveryArtifactKind, path: Path) -> None:
        artifact = RecoveryArtifact(kind=kind, path=str(path))
        if artifact not in self._ledger.artifacts:
            raise DemoRecoveryError("recovery artifact identity is not recorded")
        self._replace(artifacts=tuple(item for item in self._ledger.artifacts if item != artifact))

    def finish(self) -> None:
        if self._ledger.resources or self._ledger.artifacts:
            raise DemoRecoveryError("recovery ledger still owns resources")
        ledger_path = _validate_existing_ledger_path(self.path)
        ledger_path.unlink()
        _fsync_directory(ledger_path.parent)
        if ledger_path.exists():
            raise DemoRecoveryError("recovery ledger removal failed")

    def _replace(self, **changes: object) -> None:
        try:
            candidate = RecoveryLedger.model_validate(
                self._ledger.model_copy(update=changes).model_dump(mode="python")
            )
        except ValidationError:
            raise DemoRecoveryError("recovery ledger update is invalid") from None
        self._ledger = candidate
        self._write(initial=False)

    def _write(self, *, initial: bool) -> None:
        parent = _validate_private_parent(self.path.parent)
        if not initial:
            _validate_existing_ledger_path(self.path)
        temporary = parent / f".{self.path.name}.{os.getpid()}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                # Without O_BINARY, Windows text-mode os.write() would rewrite "\n" to
                # "\r\n" and corrupt the canonical JSON byte length.
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
            content = _canonical_bytes(self._ledger)
            if len(content) > MAX_LEDGER_BYTES:
                raise DemoRecoveryError("recovery ledger exceeds the safe size limit")
            view = memoryview(content)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("short ledger write")
                written += count
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, self.path)
            if os.name == "posix":
                os.chmod(self.path, 0o600)
            _fsync_directory(parent)
            _validate_existing_ledger_path(self.path)
        except (OSError, DemoRecoveryError):
            if descriptor is not None:
                os.close(descriptor)
            _remove_exact_temporary(temporary)
            raise DemoRecoveryError("recovery ledger update failed safely") from None


def cleanup_recorded_artifacts(store: RecoveryLedgerStore) -> None:
    """Delete only exact, validated temporary artifact identities from the ledger."""

    for artifact in tuple(store.ledger.artifacts):
        path = Path(artifact.path)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            store.remove_artifact(artifact.kind, path)
            continue
        reparse = bool(getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT)
        if reparse or stat.S_ISLNK(metadata.st_mode):
            raise DemoRecoveryError("recovery artifact identity is unsafe")
        if artifact.kind == RecoveryArtifactKind.CREDENTIALS:
            if not stat.S_ISREG(metadata.st_mode):
                raise DemoRecoveryError("recovery credential artifact is invalid")
            path.unlink()
        else:
            prefix = {
                RecoveryArtifactKind.CHECKOUT: "wg8b-clean-",
                RecoveryArtifactKind.MANIFESTS: "wg8b-manifests-",
                RecoveryArtifactKind.BACKUP: "wg8b-backup-",
                RecoveryArtifactKind.TLS: "wg-browser-tls-",
                RecoveryArtifactKind.ENVIRONMENT: "wg-browser-postgres-",
                RecoveryArtifactKind.BROWSER: ".pytest-browser",
            }.get(artifact.kind)
            if prefix is None or not path.name.startswith(prefix):
                raise DemoRecoveryError("recovery artifact name is invalid")
            if stat.S_ISREG(metadata.st_mode):
                path.unlink()
            elif stat.S_ISDIR(metadata.st_mode):
                _validate_tree_without_links(path)
                shutil.rmtree(path)
            else:
                raise DemoRecoveryError("recovery artifact type is invalid")
        if path.exists():
            raise DemoRecoveryError("recovery artifact absence could not be confirmed")
        store.remove_artifact(artifact.kind, path)


def create_private_ledger_directory(identity: DemoRunIdentity, root: Path) -> Path:
    identity.validate()
    parent = root.resolve(strict=True)
    directory = parent / f"wg8b-recovery-{identity.run_id}"
    try:
        directory.mkdir(mode=0o700)
    except OSError:
        raise DemoRecoveryError("recovery directory creation failed") from None
    return _validate_private_parent(directory)


def _canonical_bytes(ledger: RecoveryLedger) -> bytes:
    payload = (
        json.dumps(
            ledger.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate recovery key")
        result[key] = value
    return result


def _validate_new_ledger_path(path: Path) -> Path:
    if not path.is_absolute() or path.exists():
        raise DemoRecoveryError("recovery ledger path must be a new absolute file")
    parent = _validate_private_parent(path.parent)
    if path.parent != parent or not path.name.endswith(".json"):
        raise DemoRecoveryError("recovery ledger path is invalid")
    return path


def _validate_existing_ledger_path(path: Path) -> Path:
    if not path.is_absolute() or path.parent != _validate_private_parent(path.parent):
        raise DemoRecoveryError("recovery ledger path is invalid")
    try:
        metadata = path.lstat()
    except OSError:
        raise DemoRecoveryError("recovery ledger is unavailable") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT)
        or not 1 <= metadata.st_size <= MAX_LEDGER_BYTES
        or (os.name == "posix" and metadata.st_uid != int(os.__dict__["getuid"]()))
        or (os.name == "posix" and metadata.st_mode & 0o077)
    ):
        raise DemoRecoveryError("recovery ledger identity is invalid")
    return path


def _validate_private_parent(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError:
        raise DemoRecoveryError("recovery ledger directory is invalid") from None
    if (
        path != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT)
        or (os.name == "posix" and metadata.st_uid != int(os.__dict__["getuid"]()))
        or (os.name == "posix" and metadata.st_mode & 0o077)
    ):
        raise DemoRecoveryError("recovery ledger directory is unsafe")
    return resolved


def _read_regular_file(path: Path) -> bytes:
    # Without O_BINARY, Windows text-mode os.read() would rewrite "\r\n" to "\n"
    # and desynchronize the byte count from the on-disk size checked below.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            before.st_dev != opened.st_dev
            or before.st_ino != opened.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_size > MAX_LEDGER_BYTES
        ):
            raise OSError("ledger identity changed")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(8_192, MAX_LEDGER_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LEDGER_BYTES:
                raise OSError("ledger too large")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError:
        raise DemoRecoveryError("recovery ledger could not be read safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_exact_temporary(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT
    ):
        raise DemoRecoveryError("recovery temporary identity changed")
    path.unlink()


def _validate_tree_without_links(root: Path) -> None:
    for current_root, directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        for name in (*directories, *files):
            metadata = (current / name).lstat()
            if stat.S_ISLNK(metadata.st_mode) or bool(
                getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT
            ):
                raise DemoRecoveryError("recovery artifact tree contains a link")


def _resource_key(resource: RecoveryResource) -> tuple[str, str, str]:
    return resource.project_name, resource.kind.value, resource.resource_id


def _artifact_key(artifact: RecoveryArtifact) -> tuple[str, str]:
    return artifact.kind.value, artifact.path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resume exact Woland Guard demo cleanup")
    subcommands = parser.add_subparsers(dest="command", required=True)
    cleanup = subcommands.add_parser("cleanup")
    cleanup.add_argument("--ledger", type=Path, required=True)
    return parser


def main() -> None:
    arguments = _build_parser().parse_args()
    try:
        store = RecoveryLedgerStore.open(arguments.ledger)
        from scripts.demo_e2e.ownership import recover_from_ledger

        recover_from_ledger(store)
    except DemoE2EError:
        print("Exact demo recovery failed safely.")
        raise SystemExit(1) from None
    print("Exact demo recovery completed.")


if __name__ == "__main__":
    main()
