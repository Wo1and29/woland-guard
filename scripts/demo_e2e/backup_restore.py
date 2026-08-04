"""Bounded custom-format PostgreSQL backup and isolated restore smoke."""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from scripts.demo_e2e.commands import CommandRunner, DemoCommandError
from scripts.demo_e2e.contracts import DemoE2EError, DemoRunIdentity, SecretValue
from scripts.demo_e2e.ownership import ComposeDemoEnvironment, expected_migration_head
from scripts.demo_e2e.pipeline import (
    DemoProvisioning,
    PipelineSnapshot,
    SchemaFingerprint,
    assert_restore_metadata,
    create_session_factory,
    database_schema_fingerprint,
    database_snapshot,
)
from scripts.demo_e2e.recovery import RecoveryLedgerStore

MAX_BACKUP_BYTES: Final = 256 * 1_048_576


class DemoBackupError(DemoE2EError):
    """The synthetic custom-format backup could not be handled safely."""

    __slots__ = ("phase",)

    def __init__(self, message: str, *, phase: str = "general") -> None:
        if phase not in {
            "general",
            "restore_start",
            "restore_stream",
            "restore_connection",
            "restore_revision",
            "restore_snapshot",
            "restore_constraint_identity",
            "restore_constraint_flags",
            "restore_constraint_columns",
            "restore_constraint_fk",
            "restore_constraint_semantics",
            "restore_triggers",
            "restore_index_identity",
            "restore_index_flags",
            "restore_index_keys",
            "restore_index_predicate",
            "restore_index_semantics",
            "restore_metadata",
            "restore_cleanup",
        }:
            raise ValueError("invalid backup failure phase")
        super().__init__(message)
        self.phase = phase


_RESTORE_FAILURE_MESSAGES: Final = {
    "restore_start": "PostgreSQL restore failed during isolated database startup",
    "restore_stream": "PostgreSQL restore failed during bounded restore streaming",
    "restore_connection": "PostgreSQL restore failed during isolated database connection",
    "restore_revision": "PostgreSQL restore failed during migration revision verification",
    "restore_snapshot": "PostgreSQL restore failed during persistence snapshot verification",
    "restore_constraint_identity": (
        "PostgreSQL restore failed during constraint identity verification"
    ),
    "restore_constraint_flags": "PostgreSQL restore failed during constraint flag verification",
    "restore_constraint_columns": "PostgreSQL restore failed during constraint column verification",
    "restore_constraint_fk": "PostgreSQL restore failed during foreign-key verification",
    "restore_constraint_semantics": (
        "PostgreSQL restore failed during CHECK/constraint semantic verification"
    ),
    "restore_triggers": "PostgreSQL restore failed during trigger verification",
    "restore_index_identity": "PostgreSQL restore failed during index identity verification",
    "restore_index_flags": "PostgreSQL restore failed during index flag verification",
    "restore_index_keys": "PostgreSQL restore failed during index key verification",
    "restore_index_predicate": "PostgreSQL restore failed during index predicate verification",
    "restore_index_semantics": "PostgreSQL restore failed during index semantic verification",
    "restore_metadata": "PostgreSQL restore failed during metadata verification",
}


@dataclass(slots=True)
class TemporaryBackup:
    _directory: tempfile.TemporaryDirectory[str] = field(repr=False)
    path: Path = field(repr=False)

    def __repr__(self) -> str:
        return "TemporaryBackup(path=<redacted>)"

    def cleanup(self) -> None:
        self._directory.cleanup()
        if self.path.exists():
            raise DemoBackupError("temporary backup cleanup failed")


def create_backup(
    environment: ComposeDemoEnvironment,
    *,
    forbidden_plaintext: tuple[str, ...],
) -> TemporaryBackup:
    container_id = environment.service_container_id("demo-postgres")
    temporary = tempfile.TemporaryDirectory(prefix="wg8b-backup-")
    path = Path(temporary.name) / "synthetic.dump"
    docker = shutil.which("docker")
    if docker is None:
        temporary.cleanup()
        raise DemoBackupError("Docker executable is unavailable")
    try:
        CommandRunner().run_to_file(
            [
                docker,
                "exec",
                container_id,
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "--username=wg_demo",
                "--dbname=wg_demo",
            ],
            cwd=environment.project_root,
            output_path=path,
            timeout_seconds=120,
            output_limit=MAX_BACKUP_BYTES,
        )
        if not path.is_file() or path.stat().st_size == 0:
            raise DemoBackupError("PostgreSQL backup failed safely")
        if os.name == "posix":
            os.chmod(path, 0o600)
        _scan_backup_canaries(path, forbidden_plaintext)
        return TemporaryBackup(_directory=temporary, path=path)
    except Exception:
        temporary.cleanup()
        raise DemoBackupError("PostgreSQL backup failed safely") from None


def restore_and_verify(
    *,
    project_root: Path,
    identity: DemoRunIdentity,
    ledger: RecoveryLedgerStore,
    backup: TemporaryBackup,
    expected_snapshot: PipelineSnapshot,
    expected_schema: SchemaFingerprint,
    provisioning: DemoProvisioning,
    _test_schema_mutator: Callable[[sessionmaker[Session]], None] | None = None,
) -> None:
    restore_environment = ComposeDemoEnvironment(
        project_root=project_root,
        identity=identity,
        ledger=ledger,
        password=SecretValue(secrets.token_urlsafe(32)),
        restore=True,
    )
    engine = None
    primary_error = False
    phase = "restore_start"
    try:
        restore_environment.start_postgres_only()
        phase = "restore_stream"
        _restore_backup(restore_environment, backup)
        phase = "restore_connection"
        session_factory, engine = create_session_factory(
            restore_environment.database_configuration()
        )
        phase = "restore_revision"
        _verify_revision(session_factory, project_root)
        phase = "restore_snapshot"
        actual = database_snapshot(session_factory, provisioning)
        if actual != expected_snapshot:
            raise DemoBackupError("restored persistence snapshot did not match the source")
        if _test_schema_mutator is not None:
            _test_schema_mutator(session_factory)
        restored_schema = database_schema_fingerprint(session_factory)
        phase = "restore_constraint_identity"
        _verify_constraint_projection(restored_schema, expected_schema, (0, 1, 2))
        phase = "restore_constraint_flags"
        _verify_constraint_projection(restored_schema, expected_schema, (3, 4, 5, 6))
        phase = "restore_constraint_columns"
        _verify_constraint_projection(restored_schema, expected_schema, (7,))
        phase = "restore_constraint_fk"
        _verify_constraint_projection(restored_schema, expected_schema, (8, 9, 10, 11, 12))
        phase = "restore_constraint_semantics"
        _verify_constraint_projection(restored_schema, expected_schema, (13,))
        phase = "restore_triggers"
        if restored_schema.triggers != expected_schema.triggers:
            raise DemoBackupError("restored trigger fingerprint did not match the source")
        phase = "restore_index_identity"
        _verify_index_projection(restored_schema, expected_schema, (0, 1))
        phase = "restore_index_flags"
        _verify_index_projection(restored_schema, expected_schema, tuple(range(2, 13)))
        phase = "restore_index_keys"
        _verify_index_projection(restored_schema, expected_schema, (13,))
        phase = "restore_index_predicate"
        _verify_index_projection(restored_schema, expected_schema, (14,))
        phase = "restore_index_semantics"
        _verify_index_projection(restored_schema, expected_schema, (15, 16, 17))
        phase = "restore_metadata"
        assert_restore_metadata(session_factory)
    except Exception:
        primary_error = True
        raise DemoBackupError(
            _RESTORE_FAILURE_MESSAGES.get(phase, "PostgreSQL restore verification failed safely"),
            phase=phase,
        ) from None
    finally:
        if engine is not None:
            engine.dispose()
        try:
            restore_environment.stop()
        except Exception:
            message = (
                "PostgreSQL restore cleanup failed after verification failure"
                if primary_error
                else "PostgreSQL restore cleanup failed safely"
            )
            raise DemoBackupError(message, phase="restore_cleanup") from None


def _restore_backup(environment: ComposeDemoEnvironment, backup: TemporaryBackup) -> None:
    if not backup.path.is_file() or not 1 <= backup.path.stat().st_size <= MAX_BACKUP_BYTES:
        raise DemoBackupError("temporary backup artifact is invalid")
    docker = shutil.which("docker")
    if docker is None:
        raise DemoBackupError("Docker executable is unavailable")
    container_id = environment.service_container_id("demo-postgres")
    try:
        CommandRunner().run(
            [
                docker,
                "exec",
                "-i",
                container_id,
                "pg_restore",
                "--exit-on-error",
                "--single-transaction",
                "--no-owner",
                "--no-privileges",
                "--username=wg_demo",
                "--dbname=wg_demo",
            ],
            cwd=environment.project_root,
            stdin_path=backup.path,
            input_limit=MAX_BACKUP_BYTES,
            timeout_seconds=180,
            output_limit=1_048_576,
        )
    except DemoCommandError:
        raise DemoBackupError("PostgreSQL restore failed safely") from None


def _verify_constraint_projection(
    actual: SchemaFingerprint,
    expected: SchemaFingerprint,
    columns: tuple[int, ...],
) -> None:
    actual_projection = tuple(
        tuple(row[column] for column in columns) for row in actual.constraints
    )
    expected_projection = tuple(
        tuple(row[column] for column in columns) for row in expected.constraints
    )
    if actual_projection != expected_projection:
        raise DemoBackupError("restored constraint fingerprint did not match the source")


def _verify_index_projection(
    actual: SchemaFingerprint,
    expected: SchemaFingerprint,
    columns: tuple[int, ...],
) -> None:
    actual_projection = tuple(tuple(row[column] for column in columns) for row in actual.indexes)
    expected_projection = tuple(
        tuple(row[column] for column in columns) for row in expected.indexes
    )
    if actual_projection != expected_projection:
        raise DemoBackupError("restored index fingerprint did not match the source")


def _verify_revision(session_factory: sessionmaker[Session], project_root: Path) -> None:
    with session_factory() as session:
        revision = session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    if revision != expected_migration_head(project_root):
        raise DemoBackupError("restored migration revision is invalid")


def _scan_backup_canaries(path: Path, forbidden_plaintext: tuple[str, ...]) -> None:
    content = path.read_bytes()
    if any(secret.encode("utf-8") in content for secret in forbidden_plaintext):
        raise DemoBackupError("PostgreSQL backup contains forbidden plaintext credential material")
