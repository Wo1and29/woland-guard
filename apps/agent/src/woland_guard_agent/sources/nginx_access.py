"""Nginx combined-format access log adapter (ADR-0020).

Unlike the system journal, one line here describes an arbitrary HTTP request and
routinely carries material that must not leave the host. What this parser takes
is therefore a short closed list, and the query string is dropped before an
event is built at all.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from threading import Event

from woland_guard_agent.sources.base import JournalRecord
from woland_guard_agent.sources.followed_file import FollowedFile, RawLine
from woland_guard_contracts import EventSource

# The nginx default. An operator-defined log_format is not guessed: a line that
# does not match is skipped rather than parsed into something plausible.
_COMBINED = re.compile(
    r"^(?P<remote_addr>\S+) \S+ \S+ "
    r"\[(?P<time_local>[^\]]{1,64})\] "
    r'"(?P<method>[A-Z]{3,10}) (?P<target>\S{1,8192}) HTTP/(?P<version>[\d.]{1,8})" '
    r"(?P<status>\d{3}) (?P<bytes_sent>\d{1,20}) "
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

# Everything else in the line -- referer, user agent, remote user -- is not read
# at all rather than read and redacted (ADR-0020 §3).
_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
)
MAX_PATH_CHARS = 256
REDACTED_PATH = "<unprintable>"
TRUNCATED_SUFFIX = "..."


class NginxAccessSource:
    """Follow one nginx access log and report request outcomes by address."""

    name = "nginx_access"
    event_source = EventSource.NGINX_ACCESS

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
    matched = _COMBINED.fullmatch(line.text)
    if matched is None:
        return None

    method = matched.group("method")
    if method not in _METHODS:
        return None
    try:
        address = ipaddress.ip_address(matched.group("remote_addr"))
    except ValueError:
        return None
    status = int(matched.group("status"))
    if not 100 <= status <= 599:
        return None
    occurred_at = _timestamp(matched.group("time_local"))
    if occurred_at is None:
        return None

    return JournalRecord(
        cursor=line.cursor,
        fields={
            "NGINX_STATUS": status,
            "NGINX_METHOD": method,
            "NGINX_PATH": safe_path(matched.group("target")),
            "NGINX_REMOTE_ADDR": str(address),
            "__REALTIME_TIMESTAMP": int(occurred_at.timestamp() * 1_000_000),
        },
    )


def safe_path(target: str) -> str:
    """Drop the query string, then bound and validate what remains.

    The parameter carrying a secret cannot be recognised by name (``?t=``,
    ``?auth=``, ``?token=`` are all plausible), so the whole segment after the
    first ``?`` is discarded rather than filtered (ADR-0020 §1).
    """

    path = target.split("?", 1)[0]
    if not path.isprintable() or not path.isascii():
        return REDACTED_PATH
    if len(path) > MAX_PATH_CHARS:
        return path[: MAX_PATH_CHARS - len(TRUNCATED_SUFFIX)] + TRUNCATED_SUFFIX
    return path


def _timestamp(raw: str) -> datetime | None:
    """Parse nginx's ``10/Oct/2000:13:55:36 -0700``, which carries its offset."""

    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
