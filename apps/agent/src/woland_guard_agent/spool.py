"""Durable SQLite spool with atomic event and journald cursor persistence."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from woland_guard_contracts import NormalizedEventV1


class SpoolFullError(RuntimeError):
    """The bounded spool rejected the newest record without moving its cursor."""


class SpoolSecurityError(RuntimeError):
    """The spool path failed local ownership or file-type checks."""


class EnqueueResult(StrEnum):
    INSERTED = "inserted"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class QueuedEvent:
    """An event selected for a delivery attempt."""

    event: NormalizedEventV1
    attempts: int


@dataclass(frozen=True, slots=True)
class SpoolStatistics:
    pending: int
    quarantined: int
    oversized: int
    diagnostics: int = 0

    @property
    def total(self) -> int:
        return self.pending + self.quarantined + self.oversized


@dataclass(frozen=True, slots=True)
class SpoolEventSummary:
    """Payload-free operator view of one queued event."""

    event_id: UUID
    status: str
    attempts: int
    enqueued_at: float
    last_error: str | None


@dataclass(frozen=True, slots=True)
class DiagnosticState:
    """Persistent safe diagnostic without journal payload content."""

    code: str
    first_seen_at: float
    last_seen_at: float
    occurrences: int


class SQLiteSpool:
    """Thread-safe-by-connection queue; each operation opens its own SQLite connection."""

    def __init__(self, path: Path, *, max_events: int) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self._path = path
        self._max_events = max_events

    def initialize(self) -> None:
        """Create the private WAL database and its version-1 schema."""

        self._prepare_storage()
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS spool_events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    enqueued_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'quarantined', 'oversized')),
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_spool_events_delivery
                    ON spool_events (status, next_attempt_at, enqueued_at);
                CREATE TABLE IF NOT EXISTS source_cursors (
                    source_name TEXT PRIMARY KEY,
                    cursor TEXT NOT NULL CHECK (length(cursor) BETWEEN 1 AND 4096),
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_diagnostics (
                    code TEXT PRIMARY KEY CHECK (length(code) BETWEEN 1 AND 100),
                    first_seen_at REAL NOT NULL,
                    last_seen_at REAL NOT NULL,
                    occurrences INTEGER NOT NULL CHECK (occurrences >= 1)
                );
                """
            )
        self._secure_runtime_files()

    @property
    def max_events(self) -> int:
        return self._max_events

    def enqueue_with_cursor(
        self,
        *,
        source_name: str,
        cursor: str,
        event: NormalizedEventV1,
    ) -> EnqueueResult:
        """Insert the event and only then advance the cursor in one transaction."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                duplicate = connection.execute(
                    "SELECT 1 FROM spool_events WHERE event_id = ?",
                    (str(event.event_id),),
                ).fetchone()
                if duplicate is not None:
                    self._upsert_cursor(
                        connection,
                        source_name=source_name,
                        cursor=cursor,
                    )
                    connection.commit()
                    return EnqueueResult.DUPLICATE

                current_size = int(
                    connection.execute("SELECT count(*) FROM spool_events").fetchone()[0]
                )
                if current_size >= self._max_events:
                    connection.rollback()
                    raise SpoolFullError("spool capacity reached; cursor was not advanced")

                connection.execute(
                    """
                    INSERT INTO spool_events (event_id, payload, enqueued_at)
                    VALUES (?, ?, ?)
                    """,
                    (str(event.event_id), event.model_dump_json(), time.time()),
                )
                self._upsert_cursor(
                    connection,
                    source_name=source_name,
                    cursor=cursor,
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return EnqueueResult.INSERTED

    def advance_cursor(self, *, source_name: str, cursor: str) -> None:
        """Commit progress for an intentionally ignored source record."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._upsert_cursor(
                    connection,
                    source_name=source_name,
                    cursor=cursor,
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def clear_cursor(self, source_name: str) -> None:
        """Explicitly rebase a source only after recording a persistent gap."""

        with self._connect() as connection:
            connection.execute(
                "DELETE FROM source_cursors WHERE source_name = ?",
                (source_name,),
            )

    def record_diagnostic(self, code: str) -> None:
        """Persist a fixed diagnostic code without raw journal data."""

        if not 1 <= len(code) <= 100 or not code.replace("_", "").isalnum():
            raise ValueError("diagnostic code has an unsafe format")
        observed_at = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_diagnostics (
                    code, first_seen_at, last_seen_at, occurrences
                ) VALUES (?, ?, ?, 1)
                ON CONFLICT (code) DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    occurrences = agent_diagnostics.occurrences + 1
                """,
                (code, observed_at, observed_at),
            )

    def diagnostics(self) -> list[DiagnosticState]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT code, first_seen_at, last_seen_at, occurrences
                FROM agent_diagnostics
                ORDER BY code
                """
            ).fetchall()
        return [
            DiagnosticState(
                code=str(row[0]),
                first_seen_at=float(row[1]),
                last_seen_at=float(row[2]),
                occurrences=int(row[3]),
            )
            for row in rows
        ]

    def cursor(self, source_name: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT cursor FROM source_cursors WHERE source_name = ?",
                (source_name,),
            ).fetchone()
        return None if row is None else str(row[0])

    def ready_batch(self, *, limit: int, now: float | None = None) -> list[QueuedEvent]:
        if not 1 <= limit <= 100:
            raise ValueError("batch limit must be between 1 and 100")
        threshold = time.time() if now is None else now
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload, attempts
                FROM spool_events
                WHERE status = 'pending' AND next_attempt_at <= ?
                ORDER BY enqueued_at, event_id
                LIMIT ?
                """,
                (threshold, limit),
            ).fetchall()
        return [
            QueuedEvent(
                event=NormalizedEventV1.model_validate_json(str(row[0])),
                attempts=int(row[1]),
            )
            for row in rows
        ]

    def acknowledge(self, event_ids: list[UUID]) -> None:
        """Delete an acknowledged batch; callers invoke this only after HTTP 200."""

        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self._connect() as connection:
            connection.execute(
                f"DELETE FROM spool_events WHERE event_id IN ({placeholders})",  # noqa: S608
                [str(event_id) for event_id in event_ids],
            )

    def defer(
        self,
        event_ids: list[UUID],
        *,
        delay_seconds: float,
        error_code: str,
    ) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        next_attempt = time.time() + max(0.0, delay_seconds)
        parameters: list[object] = [next_attempt, error_code]
        parameters.extend(str(event_id) for event_id in event_ids)
        with self._connect() as connection:
            connection.execute(
                f"""
                UPDATE spool_events
                SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
                WHERE event_id IN ({placeholders}) AND status = 'pending'
                """,  # noqa: S608
                parameters,
            )

    def quarantine(self, event_id: UUID, *, status: str, error_code: str) -> None:
        if status not in {"quarantined", "oversized"}:
            raise ValueError("unsupported terminal spool status")
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE spool_events
                SET status = ?, attempts = attempts + 1, last_error = ?
                WHERE event_id = ? AND status = 'pending'
                """,
                (status, error_code, str(event_id)),
            )

    def statistics(self) -> SpoolStatistics:
        counts = {"pending": 0, "quarantined": 0, "oversized": 0}
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT status, count(*) FROM spool_events GROUP BY status"
            ).fetchall()
        for status, count in rows:
            counts[str(status)] = int(count)
        with self._connect() as connection:
            diagnostic_count = int(
                connection.execute("SELECT count(*) FROM agent_diagnostics").fetchone()[0]
            )
        return SpoolStatistics(**counts, diagnostics=diagnostic_count)

    def list_events(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[SpoolEventSummary]:
        """List queue metadata without reading or returning event payloads."""

        if status is not None and status not in {"pending", "quarantined", "oversized"}:
            raise ValueError("unsupported spool status")
        if not 1 <= limit <= 1_000:
            raise ValueError("list limit must be between 1 and 1000")
        query = """
            SELECT event_id, status, attempts, enqueued_at, last_error
            FROM spool_events
        """
        parameters: tuple[object, ...]
        if status is None:
            parameters = (limit,)
        else:
            query += " WHERE status = ?"
            parameters = (status, limit)
        query += " ORDER BY enqueued_at, event_id LIMIT ?"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            SpoolEventSummary(
                event_id=UUID(str(row[0])),
                status=str(row[1]),
                attempts=int(row[2]),
                enqueued_at=float(row[3]),
                last_error=None if row[4] is None else str(row[4]),
            )
            for row in rows
        ]

    def requeue(self, event_id: UUID) -> bool:
        """Move one terminal event back to pending without exposing its payload."""

        with self._connect() as connection:
            result = connection.execute(
                """
                UPDATE spool_events
                SET status = 'pending', attempts = 0, next_attempt_at = 0,
                    last_error = NULL
                WHERE event_id = ? AND status IN ('quarantined', 'oversized')
                """,
                (str(event_id),),
            )
        return result.rowcount == 1

    def delete(self, event_id: UUID) -> bool:
        """Delete one explicitly confirmed event from the local spool."""

        with self._connect() as connection:
            result = connection.execute(
                "DELETE FROM spool_events WHERE event_id = ?",
                (str(event_id),),
            )
        return result.rowcount == 1

    def journal_mode(self) -> str:
        with self._connect() as connection:
            return str(connection.execute("PRAGMA journal_mode").fetchone()[0])

    def contains(self, event_id: UUID) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM spool_events WHERE event_id = ?",
                (str(event_id),),
            ).fetchone()
        return row is not None

    def _connect(self) -> sqlite3.Connection:
        if os.name == "posix":
            self._assert_private_regular_file(self._path)
        connection = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=5000")
            self._secure_runtime_files()
        except BaseException:
            connection.close()
            raise
        return connection

    def _prepare_storage(self) -> None:
        if os.name != "posix":
            self._path.parent.mkdir(parents=True, exist_ok=True)
            return

        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_metadata = self._path.parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
            raise SpoolSecurityError("spool parent must be a real directory")
        if parent_metadata.st_uid != _current_user_id():
            raise SpoolSecurityError("spool parent must be owned by the agent user")
        self._path.parent.chmod(0o700)

        if self._path.exists() or self._path.is_symlink():
            self._assert_private_regular_file(self._path)
            self._path.chmod(0o600)
            return

        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._path, flags, 0o600)
        os.close(descriptor)
        self._path.chmod(0o600)
        self._assert_private_regular_file(self._path)

    def _assert_private_regular_file(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise SpoolSecurityError("spool file is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise SpoolSecurityError("spool path must be a regular file, not a symlink")
        if metadata.st_uid != _current_user_id():
            raise SpoolSecurityError("spool file must be owned by the agent user")

    def _secure_runtime_files(self) -> None:
        if os.name != "posix":
            return
        for path in (self._path, Path(f"{self._path}-wal"), Path(f"{self._path}-shm")):
            if not path.exists() and not path.is_symlink():
                continue
            self._assert_private_regular_file(path)
            path.chmod(0o600)

    @staticmethod
    def _upsert_cursor(
        connection: sqlite3.Connection,
        *,
        source_name: str,
        cursor: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO source_cursors (source_name, cursor, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT (source_name) DO UPDATE
            SET cursor = excluded.cursor, updated_at = excluded.updated_at
            """,
            (source_name, cursor, time.time()),
        )


def _current_user_id() -> int:
    return Path("/proc/self").stat().st_uid
