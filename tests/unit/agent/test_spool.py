"""SQLite cursor, durability, uniqueness and bounded queue tests."""

import os
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from woland_guard_agent.spool import (
    EnqueueResult,
    SpoolFullError,
    SpoolSecurityError,
    SQLiteSpool,
)
from woland_guard_contracts import NormalizedEventV1


def test_event_and_cursor_are_saved_and_restored_together(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SQLiteSpool(path, max_events=10)
    spool.initialize()
    event = make_event("00000000-0000-0000-0000-000000000001")

    result = spool.enqueue_with_cursor(source_name="journald", cursor="s=one", event=event)
    restarted = SQLiteSpool(path, max_events=10)
    restarted.initialize()

    assert result is EnqueueResult.INSERTED
    assert restarted.cursor("journald") == "s=one"
    assert restarted.contains(event.event_id)
    assert restarted.journal_mode().lower() == "wal"


def test_cursor_failure_rolls_back_preceding_event_insert(tmp_path: Path) -> None:
    spool = SQLiteSpool(tmp_path / "atomic.sqlite3", max_events=10)
    spool.initialize()
    event = make_event("00000000-0000-0000-0000-000000000002")

    with pytest.raises(sqlite3.IntegrityError):
        spool.enqueue_with_cursor(
            source_name="journald",
            cursor="x" * 4_097,
            event=event,
        )

    assert not spool.contains(event.event_id)
    assert spool.cursor("journald") is None


def test_duplicate_event_id_atomically_advances_cursor_for_safe_replay(
    tmp_path: Path,
) -> None:
    spool = SQLiteSpool(tmp_path / "duplicate.sqlite3", max_events=10)
    spool.initialize()
    event = make_event("00000000-0000-0000-0000-000000000003")
    spool.enqueue_with_cursor(source_name="journald", cursor="s=first", event=event)

    result = spool.enqueue_with_cursor(
        source_name="journald",
        cursor="s=replayed;i=2",
        event=event,
    )

    assert result is EnqueueResult.DUPLICATE
    assert spool.cursor("journald") == "s=replayed;i=2"
    assert spool.statistics().total == 1

    restarted = SQLiteSpool(tmp_path / "duplicate.sqlite3", max_events=10)
    restarted.initialize()
    assert restarted.cursor("journald") == "s=replayed;i=2"
    assert restarted.statistics().total == 1


def test_bounded_spool_rejects_newest_without_cursor_advance(tmp_path: Path) -> None:
    spool = SQLiteSpool(tmp_path / "bounded.sqlite3", max_events=1)
    spool.initialize()
    first = make_event("00000000-0000-0000-0000-000000000004")
    second = make_event("00000000-0000-0000-0000-000000000005")
    spool.enqueue_with_cursor(source_name="journald", cursor="s=first", event=first)

    with pytest.raises(SpoolFullError, match="cursor was not advanced"):
        spool.enqueue_with_cursor(source_name="journald", cursor="s=second", event=second)

    assert spool.cursor("journald") == "s=first"
    assert spool.contains(first.event_id)
    assert not spool.contains(second.event_id)


def test_ready_batch_is_limited_to_one_hundred(tmp_path: Path) -> None:
    spool = SQLiteSpool(tmp_path / "batch.sqlite3", max_events=101)
    spool.initialize()
    for number in range(101):
        event = NormalizedEventV1(
            event_id=UUID(int=number + 1),
            occurred_at=datetime(2024, 1, 1, tzinfo=UTC),
            collected_at=datetime(2024, 1, 1, tzinfo=UTC),
            event_type="linux.journald",
        )
        spool.enqueue_with_cursor(
            source_name="journald",
            cursor=f"s=batch;i={number}",
            event=event,
        )

    assert len(spool.ready_batch(limit=100)) == 100


def test_operator_list_never_returns_payload_and_requeue_is_explicit(
    tmp_path: Path,
) -> None:
    spool = SQLiteSpool(tmp_path / "operator.sqlite3", max_events=10)
    spool.initialize()
    event = make_event("00000000-0000-0000-0000-000000000006")
    spool.enqueue_with_cursor(source_name="journald", cursor="s=operator", event=event)
    spool.quarantine(event.event_id, status="quarantined", error_code="invalid_event")

    listed = spool.list_events(status="quarantined")

    assert len(listed) == 1
    assert not hasattr(listed[0], "payload")
    assert listed[0].event_id == event.event_id
    assert spool.requeue(event.event_id)
    assert spool.list_events(status="pending")[0].attempts == 0
    assert spool.delete(event.event_id)
    assert not spool.contains(event.event_id)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode semantics")
def test_posix_spool_directory_database_and_sidecars_are_private(tmp_path: Path) -> None:
    directory = tmp_path / "private-spool"
    path = directory / "spool.sqlite3"
    spool = SQLiteSpool(path, max_events=10)
    spool.initialize()

    connection = spool._connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO agent_diagnostics VALUES ('mode_check', 1, 1, 1)")
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{path}{suffix}")
            assert sidecar.exists()
            assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
        connection.rollback()
    finally:
        connection.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file type semantics")
@pytest.mark.parametrize("unsafe_kind", ["symlink", "directory"])
def test_posix_spool_rejects_symlink_and_non_regular_file(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    directory = tmp_path / f"unsafe-{unsafe_kind}"
    directory.mkdir()
    path = directory / "spool.sqlite3"
    if unsafe_kind == "symlink":
        path.symlink_to(directory / "target.sqlite3")
    else:
        path.mkdir()

    with pytest.raises(SpoolSecurityError, match="regular file"):
        SQLiteSpool(path, max_events=10).initialize()


@pytest.mark.skipif(
    os.name != "posix" or Path("/proc/self").stat().st_uid != 0,
    reason="requires POSIX root to create a foreign-owned fixture",
)
def test_posix_spool_rejects_file_owned_by_another_user(tmp_path: Path) -> None:
    directory = tmp_path / "wrong-owner"
    directory.mkdir()
    path = directory / "spool.sqlite3"
    path.touch()
    try:
        getattr(os, "chown")(  # noqa: B009 - absent in Windows stubs
            path,
            65534,
            65534,
        )
    except PermissionError:
        pytest.skip("test container does not have CAP_CHOWN")

    with pytest.raises(SpoolSecurityError, match="owned by the agent user"):
        SQLiteSpool(path, max_events=10).initialize()


def make_event(event_id: str) -> NormalizedEventV1:
    return NormalizedEventV1(
        event_id=UUID(event_id),
        occurred_at=datetime(2024, 1, 1, tzinfo=UTC),
        collected_at=datetime(2024, 1, 1, tzinfo=UTC),
        event_type="linux.journald",
        summary="synthetic",
    )
