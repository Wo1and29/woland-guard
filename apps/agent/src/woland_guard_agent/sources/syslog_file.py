"""RFC3164 syslog file adapter for hosts without a readable journal (ADR-0019)."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import BinaryIO, cast

from woland_guard_agent.sources.base import (
    JournalRecord,
    SourceCursorUnavailableError,
    SourceUnavailableError,
)
from woland_guard_contracts import EventSource

logger = logging.getLogger(__name__)

# A single journal line has no legitimate reason to approach this; anything
# longer is treated as corrupt and skipped rather than buffered (ADR-0019 §7).
MAX_LINE_BYTES = 64 * 1024

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

_CURSOR = re.compile(r"^(?P<dev>\d{1,20}):(?P<ino>\d{1,20}):(?P<offset>\d{1,19}):[0-9a-f]{12}$")


class SyslogFileUnavailableError(SourceUnavailableError):
    """The configured syslog file cannot be opened or read."""


class SyslogCursorUnavailableError(SyslogFileUnavailableError, SourceCursorUnavailableError):
    """The saved position belongs to a file this host can no longer reach."""


class SyslogFileSource:
    """Follow one syslog file, surviving rotation without replaying old lines."""

    name = "syslog_file"
    event_source = EventSource.SYSLOG_FILE

    def __init__(self, path: Path, *, poll_seconds: float = 0.5) -> None:
        self._path = path
        self._poll_seconds = poll_seconds

    def backlog(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        initial_limit: int | None,
    ) -> Iterator[JournalRecord]:
        """Drain everything already written after the committed position."""

        handle, identity = self._open_at(after_cursor)
        emitted = 0
        try:
            for record in self._read_available(handle, identity, stop_event=stop_event):
                yield record
                emitted += 1
                if initial_limit is not None and emitted >= initial_limit:
                    return
        finally:
            handle.close()

    def follow(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
    ) -> Iterator[JournalRecord]:
        """Follow the file, re-opening it after rotation until asked to stop."""

        handle, identity = self._open_at(after_cursor)
        try:
            while not stop_event.is_set():
                yield from self._read_available(handle, identity, stop_event=stop_event)
                rotated = self._rotated_identity(identity)
                if rotated is not None:
                    # The open descriptor still points at the rotated-away file,
                    # so its tail is drained before the handle is released.
                    yield from self._read_available(handle, identity, stop_event=stop_event)
                    handle.close()
                    handle, identity = self._open_path(start_offset=0)
                    continue
                stop_event.wait(self._poll_seconds)
        finally:
            handle.close()

    # ------------------------------------------------------------------ reading

    def _read_available(
        self,
        handle: BinaryIO,
        identity: tuple[int, int],
        *,
        stop_event: Event,
    ) -> Iterator[JournalRecord]:
        """Yield every complete line currently readable from the open handle."""

        while not stop_event.is_set():
            start = handle.tell()
            chunk = handle.readline(MAX_LINE_BYTES)
            if not chunk:
                return
            if not chunk.endswith(b"\n"):
                if len(chunk) >= MAX_LINE_BYTES:
                    if not self._discard_overlong(handle, stop_event=stop_event):
                        return
                    continue
                # A line still being written: rewind so it is read once complete.
                handle.seek(start)
                return
            record = self._record(chunk, identity=identity, end_offset=handle.tell())
            if record is not None:
                yield record

    def _discard_overlong(self, handle: BinaryIO, *, stop_event: Event) -> bool:
        """Skip past a line longer than the cap; return False at end of file."""

        logger.warning("syslog_line_discarded reason=too_long")
        while not stop_event.is_set():
            chunk = handle.readline(MAX_LINE_BYTES)
            if not chunk:
                return False
            if chunk.endswith(b"\n"):
                return True
        return False

    def _record(
        self,
        raw: bytes,
        *,
        identity: tuple[int, int],
        end_offset: int,
    ) -> JournalRecord | None:
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if "\x00" in line:
            return None
        matched = _SYSLOG_LINE.fullmatch(line)
        if matched is None:
            return None

        occurred_at = _timestamp(matched)
        if occurred_at is None:
            return None

        device, inode = identity
        digest = hashlib.sha256(raw).hexdigest()[:12]
        return JournalRecord(
            cursor=f"{device}:{inode}:{end_offset}:{digest}",
            fields={
                "MESSAGE": matched.group("message"),
                "SYSLOG_IDENTIFIER": matched.group("identifier"),
                "__REALTIME_TIMESTAMP": int(occurred_at.timestamp() * 1_000_000),
            },
        )

    # ------------------------------------------------------------------ opening

    def _open_at(self, after_cursor: str | None) -> tuple[BinaryIO, tuple[int, int]]:
        """Open the file positioned after the committed cursor."""

        if after_cursor is None:
            return self._open_path(start_offset=0)

        parsed = _CURSOR.fullmatch(after_cursor)
        if parsed is None:
            raise SyslogCursorUnavailableError("saved syslog cursor is invalid")

        handle, identity = self._open_path(start_offset=0)
        device, inode = identity
        if (int(parsed.group("dev")), int(parsed.group("ino"))) != (device, inode):
            # The cursor names a file this path no longer resolves to: the tail
            # we never read is gone with it (ADR-0019 §3).
            handle.close()
            raise SyslogCursorUnavailableError("saved syslog cursor belongs to a rotated file")

        offset = int(parsed.group("offset"))
        size = os.fstat(handle.fileno()).st_size
        if offset > size:
            # copytruncate: same inode, fresh content — restart from the top.
            logger.warning("syslog_file_truncated restart=true")
            return handle, identity
        handle.seek(offset)
        return handle, identity

    def _open_path(self, *, start_offset: int) -> tuple[BinaryIO, tuple[int, int]]:
        flags = os.O_RDONLY | cast(int, getattr(os, "O_NOFOLLOW", 0))
        try:
            descriptor = os.open(self._path, flags)
        except OSError as error:
            raise SyslogFileUnavailableError("syslog file cannot be opened") from error

        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise SyslogFileUnavailableError("syslog file must be a regular file")
            handle = cast(BinaryIO, os.fdopen(descriptor, "rb"))
        except Exception:
            os.close(descriptor)
            raise

        handle.seek(start_offset)
        return handle, (metadata.st_dev, metadata.st_ino)

    def _rotated_identity(self, identity: tuple[int, int]) -> tuple[int, int] | None:
        """Return the new identity when the path stopped resolving to our handle."""

        try:
            metadata = self._path.stat()
        except OSError:
            return None
        current = (metadata.st_dev, metadata.st_ino)
        return current if current != identity else None


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
