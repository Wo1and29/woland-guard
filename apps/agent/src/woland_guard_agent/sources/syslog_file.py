"""RFC3164 syslog file adapter for hosts without a readable journal (ADR-0019)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

from woland_guard_agent.sources.base import JournalRecord
from woland_guard_agent.sources.followed_file import (
    MAX_LINE_BYTES,
    FollowedFile,
    FollowedFileCursorUnavailableError,
    FollowedFileUnavailableError,
    RawLine,
)
from woland_guard_contracts import EventSource

__all__ = [
    "MAX_LINE_BYTES",
    "SyslogCursorUnavailableError",
    "SyslogFileSource",
    "SyslogFileUnavailableError",
]

# Kept as aliases so callers can catch a source-specific name if they prefer.
SyslogFileUnavailableError = FollowedFileUnavailableError
SyslogCursorUnavailableError = FollowedFileCursorUnavailableError

# "Aug  4 12:34:56 hostname sshd[1234]: Failed password for root from ..."
_SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<host>[^\s]+)\s+"
    r"(?P<identifier>[A-Za-z0-9_.\-/]{1,64})(?:\[(?P<pid>\d{1,10})\])?:\s"
    r"(?P<message>.*)$"
)
_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}  # fmt: skip


class SyslogFileSource:
    """Follow one syslog file and reuse the journald message allowlist."""

    name = "syslog_file"
    event_source = EventSource.SYSLOG_FILE

    def __init__(self, path: Path, *, poll_seconds: float = 0.5) -> None:
        self._file = FollowedFile(path, poll_seconds=poll_seconds)

    def backlog(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        initial_limit: int | None,
    ) -> Iterator[JournalRecord]:
        """Drain everything already written after the committed position."""

        for line in self._file.backlog(
            after_cursor=after_cursor,
            stop_event=stop_event,
            initial_limit=initial_limit,
        ):
            record = _record(line)
            if record is not None:
                yield record

    def follow(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
    ) -> Iterator[JournalRecord]:
        """Follow the file, re-opening it after rotation until asked to stop."""

        for line in self._file.follow(after_cursor=after_cursor, stop_event=stop_event):
            record = _record(line)
            if record is not None:
                yield record


def _record(line: RawLine) -> JournalRecord | None:
    matched = _SYSLOG_LINE.fullmatch(line.text)
    if matched is None:
        return None
    occurred_at = _timestamp(matched)
    if occurred_at is None:
        return None
    return JournalRecord(
        cursor=line.cursor,
        fields={
            "MESSAGE": matched.group("message"),
            "SYSLOG_IDENTIFIER": matched.group("identifier"),
            "__REALTIME_TIMESTAMP": int(occurred_at.timestamp() * 1_000_000),
        },
    )


def _timestamp(matched: re.Match[str]) -> datetime | None:
    """Resolve an RFC3164 stamp, which carries no year, against the clock.

    A line written on 31 December and read on 1 January would otherwise land a
    year in the future, and the contract masks that by dragging collected_at
    forward instead of rejecting it (ADR-0019 §4).
    """

    month = _MONTHS.get(matched.group("month").lower())
    if month is None:
        return None

    now = datetime.now(UTC)
    for year in (now.year, now.year - 1):
        try:
            candidate = datetime(
                year,
                month,
                int(matched.group("day")),
                int(matched.group("hour")),
                int(matched.group("minute")),
                int(matched.group("second")),
                tzinfo=UTC,
            )
        except ValueError:
            continue
        if candidate <= now + timedelta(days=1):
            return candidate
    return None
