"""Behaviour of the RFC3164 syslog file adapter (ADR-0019)."""

from __future__ import annotations

import os
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import cast

import pytest

from woland_guard_agent.normalization import normalize_record
from woland_guard_agent.sources import JournalRecord
from woland_guard_agent.sources.syslog_file import (
    MAX_LINE_BYTES,
    SyslogCursorUnavailableError,
    SyslogFileSource,
    SyslogFileUnavailableError,
)
from woland_guard_contracts import EventSource

FAILED_LOGIN = "sshd[1234]: Failed password for root from 198.51.100.7 port 22 ssh2"
ACCEPTED_LOGIN = "sshd[1235]: Accepted publickey for deploy from 198.51.100.9 port 22 ssh2"


def stamp(moment: datetime) -> str:
    """Render an RFC3164 prefix, whose day field is space padded."""

    return f"{moment.strftime('%b')} {moment.day:>2} {moment.strftime('%H:%M:%S')} host"


def write_lines(path: Path, *messages: str, moment: datetime | None = None) -> None:
    when = moment or datetime.now(UTC) - timedelta(minutes=1)
    with path.open("a", encoding="utf-8") as handle:
        for message in messages:
            handle.write(f"{stamp(when)} {message}\n")


def drain(source: SyslogFileSource, cursor: str | None = None) -> list[JournalRecord]:
    stop = Event()
    return list(source.backlog(after_cursor=cursor, stop_event=stop, initial_limit=None))


def test_reads_recognised_lines_and_ignores_everything_else(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    write_lines(
        log,
        FAILED_LOGIN,
        "CRON[99]: pam_unix(cron:session): session opened for user root",
        ACCEPTED_LOGIN,
    )

    records = drain(SyslogFileSource(log))
    events = [normalize_record(r, source=EventSource.SYSLOG_FILE) for r in records]
    recognised = [event for event in events if event is not None]

    assert len(records) == 3, "every well-formed syslog line becomes a record"
    assert [event.event_type for event in recognised] == [
        "linux.ssh.authentication_failed",
        "linux.ssh.login_succeeded",
    ]
    assert all(event.source is EventSource.SYSLOG_FILE for event in recognised)


def test_reuses_the_journald_parsers_without_a_second_allowlist(tmp_path: Path) -> None:
    """The file adapter must not widen what the agent is willing to report."""

    log = tmp_path / "auth.log"
    write_lines(log, FAILED_LOGIN)

    event = normalize_record(drain(SyslogFileSource(log))[0], source=EventSource.SYSLOG_FILE)

    assert event is not None
    assert event.actor == "root"
    assert str(event.source_ip) == "198.51.100.7"
    # The raw line never reaches the event, exactly as on the journald path.
    assert event.summary == "SSH authentication failed"
    assert set(event.attributes) == {"authentication_method", "invalid_user"}


def test_resumes_after_the_committed_cursor(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    write_lines(log, FAILED_LOGIN)
    source = SyslogFileSource(log)
    first = drain(source)

    write_lines(log, ACCEPTED_LOGIN)
    resumed = drain(source, first[-1].cursor)

    assert len(resumed) == 1
    assert "Accepted" in str(resumed[0].fields["MESSAGE"])


def test_partial_trailing_line_is_not_emitted_until_complete(tmp_path: Path) -> None:
    """A half-written line would parse into a truncated, wrong event."""

    log = tmp_path / "auth.log"
    write_lines(log, FAILED_LOGIN)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp(datetime.now(UTC))} sshd[9]: Accepted password for deploy from ")

    source = SyslogFileSource(log)
    first = drain(source)
    assert len(first) == 1

    with log.open("a", encoding="utf-8") as handle:
        handle.write("198.51.100.9 port 22 ssh2\n")

    completed = drain(source, first[-1].cursor)
    assert len(completed) == 1
    assert "198.51.100.9" in str(completed[0].fields["MESSAGE"])


def test_rotation_to_a_new_inode_is_reported_as_a_gap_not_a_silent_restart(
    tmp_path: Path,
) -> None:
    """Losing the unread tail must surface, mirroring the journald cursor gap."""

    log = tmp_path / "auth.log"
    write_lines(log, FAILED_LOGIN)
    source = SyslogFileSource(log)
    cursor = drain(source)[-1].cursor

    log.rename(tmp_path / "auth.log.1")
    write_lines(log, ACCEPTED_LOGIN)

    with pytest.raises(SyslogCursorUnavailableError):
        drain(source, cursor)


def test_same_position_with_different_content_yields_a_different_cursor(
    tmp_path: Path,
) -> None:
    """The cursor hash is what prevents a silent duplicate-id collision.

    Both lines are the same length and are written at offset zero of the same
    inode, so device, inode and end offset are all identical. Only the content
    differs. Without the hash the cursors would match, uuid5 would produce one
    id, and a genuinely new login attempt from a different address would be
    dropped as an already-delivered replay.
    """

    from_first_ip = "sshd[1234]: Failed password for root from 198.51.100.7 port 22 ssh2"
    from_second_ip = "sshd[1234]: Failed password for root from 198.51.100.8 port 22 ssh2"
    assert len(from_first_ip) == len(from_second_ip), "the offsets must be identical"

    log = tmp_path / "auth.log"
    moment = datetime.now(UTC) - timedelta(minutes=1)
    write_lines(log, from_first_ip, moment=moment)
    first = drain(SyslogFileSource(log))[0]

    # Truncate in place: the inode survives, so device/inode/offset all repeat.
    with log.open("w", encoding="utf-8"):
        pass
    write_lines(log, from_second_ip, moment=moment)
    second = drain(SyslogFileSource(log))[0]

    def position(cursor: str) -> list[str]:
        """Everything except the trailing content hash."""

        return cursor.split(":")[0:3]

    assert position(first.cursor) == position(second.cursor)
    assert first.cursor != second.cursor, "only the content hash separates them"

    original = normalize_record(first, source=EventSource.SYSLOG_FILE)
    genuine = normalize_record(second, source=EventSource.SYSLOG_FILE)
    assert original is not None and genuine is not None
    assert original.event_id != genuine.event_id
    assert str(original.source_ip) != str(genuine.source_ip)


def test_truncation_in_place_restarts_from_the_top(tmp_path: Path) -> None:
    """copytruncate keeps the inode but replaces the content."""

    log = tmp_path / "auth.log"
    write_lines(log, FAILED_LOGIN, ACCEPTED_LOGIN)
    source = SyslogFileSource(log)
    cursor = drain(source)[-1].cursor

    with log.open("w", encoding="utf-8"):
        pass
    write_lines(log, FAILED_LOGIN)

    resumed = drain(source, cursor)
    assert len(resumed) == 1, "content after truncation is read, not skipped"


def test_overlong_line_is_skipped_without_buffering_it(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp(datetime.now(UTC))} sshd[1]: {'A' * (MAX_LINE_BYTES + 10)}\n")
    write_lines(log, FAILED_LOGIN)

    records = drain(SyslogFileSource(log))

    assert len(records) == 1
    assert "Failed password" in str(records[0].fields["MESSAGE"])


def test_december_line_read_in_january_is_not_dated_into_the_future(tmp_path: Path) -> None:
    """RFC3164 carries no year; guessing the current one breaks at the boundary."""

    log = tmp_path / "auth.log"
    tomorrow = datetime.now(UTC) + timedelta(days=30)
    write_lines(log, FAILED_LOGIN, moment=tomorrow)

    records = drain(SyslogFileSource(log))
    event = normalize_record(records[0], source=EventSource.SYSLOG_FILE)

    assert event is not None
    assert event.occurred_at <= event.collected_at
    assert event.occurred_at < datetime.now(UTC) + timedelta(days=1)


def test_nul_and_unparsable_lines_are_dropped(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    with log.open("ab") as handle:
        handle.write(b"not a syslog line at all\n")
        handle.write(f"{stamp(datetime.now(UTC))} sshd[1]: with\x00nul\n".encode())
    write_lines(log, FAILED_LOGIN)

    records = drain(SyslogFileSource(log))

    assert len(records) == 1


def test_missing_file_is_reported_as_unavailable_not_as_empty(tmp_path: Path) -> None:
    with pytest.raises(SyslogFileUnavailableError):
        drain(SyslogFileSource(tmp_path / "absent.log"))


def test_invalid_saved_cursor_is_rejected(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    write_lines(log, FAILED_LOGIN)

    with pytest.raises(SyslogCursorUnavailableError):
        drain(SyslogFileSource(log), "not-a-cursor")


@pytest.mark.skipif(os.name != "posix", reason="symlink refusal relies on O_NOFOLLOW")
def test_symlinked_path_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real.log"
    write_lines(target, FAILED_LOGIN)
    link = tmp_path / "auth.log"
    link.symlink_to(target)

    with pytest.raises(SyslogFileUnavailableError):
        drain(SyslogFileSource(link))


def test_follow_picks_up_appended_lines(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    write_lines(log, FAILED_LOGIN)
    source = SyslogFileSource(log, poll_seconds=0.01)
    stop = Event()

    # follow() is declared as an Iterator by the protocol; the adapter returns a
    # generator, and the test closes it so the file handle is not left suspended.
    stream = cast(
        Generator[JournalRecord, None, None], source.follow(after_cursor=None, stop_event=stop)
    )
    try:
        first = next(stream)
        assert "Failed password" in str(first.fields["MESSAGE"])

        write_lines(log, ACCEPTED_LOGIN)
        second = next(stream)
        assert "Accepted" in str(second.fields["MESSAGE"])
    finally:
        stop.set()
        stream.close()
