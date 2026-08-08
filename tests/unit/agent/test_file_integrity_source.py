"""Behaviour of the file integrity source and its privilege boundary (ADR-0022)."""

from __future__ import annotations

import os
from pathlib import Path
from threading import Event

import pytest

from woland_guard_agent.normalization import normalize_record
from woland_guard_agent.sources import JournalRecord
from woland_guard_agent.sources.file_integrity import (
    MAX_HASHED_BYTES,
    FileIntegritySource,
    parse_baseline,
    read_state,
)
from woland_guard_contracts import EventSource


def scan(source: FileIntegritySource, cursor: str | None) -> list[JournalRecord]:
    return list(source.backlog(after_cursor=cursor, stop_event=Event(), initial_limit=None))


def changes(records: list[JournalRecord]) -> list[dict[str, object]]:
    """Return only the records that normalization turns into real events."""

    events = [normalize_record(record, source=EventSource.FILE_INTEGRITY) for record in records]
    return [dict(event.attributes) for event in events if event is not None]


def test_first_scan_establishes_a_baseline_without_reporting_anything(tmp_path: Path) -> None:
    """Otherwise every agent install would begin with 'everything changed'."""

    watched = tmp_path / "sshd_config"
    watched.write_text("PermitRootLogin no\n", encoding="utf-8")
    source = FileIntegritySource([watched])

    records = scan(source, None)

    assert len(records) == 1
    assert changes(records) == []
    assert records[0].cursor


def test_content_change_is_reported_after_the_baseline_exists(tmp_path: Path) -> None:
    watched = tmp_path / "sshd_config"
    watched.write_text("PermitRootLogin no\n", encoding="utf-8")
    source = FileIntegritySource([watched])
    baseline = scan(source, None)[0].cursor

    watched.write_text("PermitRootLogin yes\n", encoding="utf-8")
    reported = changes(scan(source, baseline))

    assert reported == [{"path": str(watched), "change": "content", "monitoring": "content"}]


def test_unchanged_file_reports_nothing_however_often_it_is_scanned(tmp_path: Path) -> None:
    watched = tmp_path / "passwd"
    watched.write_text("root:x:0:0::/root:/bin/sh\n", encoding="utf-8")
    source = FileIntegritySource([watched])
    cursor = scan(source, None)[0].cursor

    for _ in range(3):
        records = scan(source, cursor)
        assert records == []


def test_neither_content_nor_hash_reaches_the_event(tmp_path: Path) -> None:
    """A hash of a small config is a confirmable-guess oracle (ADR-0022 §4)."""

    watched = tmp_path / "sshd_config"
    watched.write_text("AllowUsers alice\n", encoding="utf-8")
    source = FileIntegritySource([watched])
    baseline = scan(source, None)[0].cursor

    synthetic_marker = "AllowUsers alice bob canary-internal-host\n"
    watched.write_text(synthetic_marker, encoding="utf-8")
    records = scan(source, baseline)
    event = normalize_record(records[0], source=EventSource.FILE_INTEGRITY)

    assert event is not None
    serialised = event.model_dump_json()
    assert "canary-internal-host" not in serialised
    assert "AllowUsers" not in serialised
    assert set(event.attributes) == {"path", "change", "monitoring"}


def test_touching_a_readable_file_without_changing_it_is_not_a_change(tmp_path: Path) -> None:
    """Configuration management rewrites identical content constantly."""

    watched = tmp_path / "sshd_config"
    watched.write_text("PermitRootLogin no\n", encoding="utf-8")
    source = FileIntegritySource([watched])
    baseline = scan(source, None)[0].cursor

    os.utime(watched, (1_000_000, 1_000_000))
    watched.write_text("PermitRootLogin no\n", encoding="utf-8")

    assert changes(scan(source, baseline)) == []


def test_deleted_then_recreated_file_is_reported_as_two_distinct_changes(
    tmp_path: Path,
) -> None:
    watched = tmp_path / "sudoers"
    watched.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
    source = FileIntegritySource([watched])
    cursor = scan(source, None)[0].cursor

    watched.unlink()
    removal = scan(source, cursor)
    assert [item["change"] for item in changes(removal)] == ["disappeared"]

    watched.write_text("root ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    recreation = scan(source, removal[-1].cursor)

    assert [item["change"] for item in changes(recreation)] == ["appeared"]


def test_a_missing_file_that_stays_missing_is_reported_once(tmp_path: Path) -> None:
    source = FileIntegritySource([tmp_path / "never-created"])
    cursor = scan(source, None)[0].cursor

    assert scan(source, cursor) == []


def test_permission_change_alone_is_reported_as_permissions(tmp_path: Path) -> None:
    watched = tmp_path / "sshd_config"
    watched.write_text("PermitRootLogin no\n", encoding="utf-8")
    source = FileIntegritySource([watched])
    baseline = scan(source, None)[0].cursor

    watched.chmod(0o777)
    reported = changes(scan(source, baseline))

    if not reported:  # pragma: no cover - Windows ignores most POSIX mode bits
        pytest.skip("filesystem does not record POSIX permission bits")
    assert reported[0]["change"] == "permissions"
    assert reported[0]["monitoring"] == "content"


def test_reordering_the_configured_paths_is_not_a_change(tmp_path: Path) -> None:
    """The baseline is keyed by path, not by position in the list."""

    first = tmp_path / "passwd"
    second = tmp_path / "group"
    first.write_text("root:x:0:0::/root:/bin/sh\n", encoding="utf-8")
    second.write_text("root:x:0:\n", encoding="utf-8")
    cursor = scan(FileIntegritySource([first, second]), None)[0].cursor

    assert scan(FileIntegritySource([second, first]), cursor) == []


def test_adding_a_path_later_does_not_report_it_as_changed(tmp_path: Path) -> None:
    first = tmp_path / "passwd"
    second = tmp_path / "group"
    first.write_text("root:x:0:0::/root:/bin/sh\n", encoding="utf-8")
    second.write_text("root:x:0:\n", encoding="utf-8")
    cursor = scan(FileIntegritySource([first]), None)[0].cursor

    records = scan(FileIntegritySource([first, second]), cursor)

    assert changes(records) == []


def test_a_path_removed_from_the_configuration_leaves_the_baseline(tmp_path: Path) -> None:
    first = tmp_path / "passwd"
    second = tmp_path / "group"
    first.write_text("root:x:0:0::/root:/bin/sh\n", encoding="utf-8")
    second.write_text("root:x:0:\n", encoding="utf-8")
    cursor = scan(FileIntegritySource([first, second]), None)[0].cursor

    records = scan(FileIntegritySource([first]), cursor)

    assert changes(records) == []
    assert len(parse_baseline(records[-1].cursor)) == 1


def test_a_non_regular_file_is_never_opened_for_content(tmp_path: Path) -> None:
    """Whatever is at the path, only a regular file is ever read.

    A directory stands in for the case that actually matters, a FIFO left in
    place of a config: reading one would block the collector forever, so the
    type is checked on the already-open descriptor (ADR-0022 §9).
    """

    directory = tmp_path / "not-a-file"
    directory.mkdir()

    state = read_state(directory)

    assert state.present is True
    assert state.readable is False


def test_an_oversized_file_falls_back_to_metadata(tmp_path: Path) -> None:
    watched = tmp_path / "huge"
    with watched.open("wb") as handle:
        handle.truncate(MAX_HASHED_BYTES + 1)

    state = read_state(watched)

    assert state.present is True
    assert state.readable is False


def test_an_unhashable_file_still_reports_a_change_from_its_metadata(tmp_path: Path) -> None:
    """The weak tier: a file the agent cannot hash is still watched via stat.

    An oversized file stands in for the real case, /etc/shadow, which the agent
    can stat but must never be given permission to read (ADR-0022 §2).
    """

    watched = tmp_path / "huge"
    with watched.open("wb") as handle:
        handle.truncate(MAX_HASHED_BYTES + 1)
    source = FileIntegritySource([watched])
    baseline = scan(source, None)[0].cursor

    with watched.open("wb") as handle:
        handle.truncate(MAX_HASHED_BYTES + 4_096)
    reported = changes(scan(source, baseline))

    assert reported == [{"path": str(watched), "change": "metadata", "monitoring": "metadata"}]


def test_a_corrupt_cursor_is_treated_as_no_baseline_not_as_change(tmp_path: Path) -> None:
    watched = tmp_path / "sshd_config"
    watched.write_text("PermitRootLogin no\n", encoding="utf-8")
    source = FileIntegritySource([watched])

    for corrupt in ("not-a-baseline", "abc:", "abc:short", "a b:cccc", ""):
        records = scan(source, corrupt)

        assert changes(records) == []


def test_more_paths_than_the_cursor_can_hold_are_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="too many watched paths"):
        FileIntegritySource([Path(f"/etc/file-{index}") for index in range(65)])


def test_the_serialized_baseline_stays_inside_the_spool_cursor_limit(tmp_path: Path) -> None:
    """The spool schema rejects a cursor longer than 4096 characters."""

    paths = []
    for index in range(64):
        path = tmp_path / f"config-{index:02d}-with-a-fairly-long-name.conf"
        path.write_text(f"setting = {index}\n", encoding="utf-8")
        paths.append(path)

    cursor = scan(FileIntegritySource(paths), None)[0].cursor

    assert len(cursor) <= 4096
