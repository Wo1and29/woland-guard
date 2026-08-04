"""Shared line tailer with rotation-safe cursors (ADR-0019 §2-§3, ADR-0020 §6).

Every file-backed source needs the same delicate parts: a cursor that survives
rotation without colliding, a partial trailing line held back until complete,
and a bounded line length. They live here once so a second source adds only its
own line parser.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import BinaryIO, cast

from woland_guard_agent.sources.base import (
    SourceCursorUnavailableError,
    SourceUnavailableError,
)

logger = logging.getLogger(__name__)

# A single log line has no legitimate reason to approach this; anything longer
# is treated as corrupt and skipped rather than buffered (ADR-0019 §7).
MAX_LINE_BYTES = 64 * 1024

CURSOR_PATTERN = re.compile(
    r"^(?P<dev>\d{1,20}):(?P<ino>\d{1,20}):(?P<offset>\d{1,19}):[0-9a-f]{12}$"
)


class FollowedFileUnavailableError(SourceUnavailableError):
    """The configured file cannot be opened or read."""


class FollowedFileCursorUnavailableError(
    FollowedFileUnavailableError, SourceCursorUnavailableError
):
    """The saved position belongs to a file this host can no longer reach."""


@dataclass(frozen=True, slots=True)
class RawLine:
    """One complete line plus the cursor that addresses it."""

    text: str
    cursor: str


class FollowedFile:
    """Tail one file, surviving rotation without replaying or losing lines."""

    def __init__(self, path: Path, *, poll_seconds: float = 0.5) -> None:
        self._path = path
        self._poll_seconds = poll_seconds

    def backlog(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        initial_limit: int | None,
    ) -> Iterator[RawLine]:
        """Drain everything already written after the committed position."""

        handle, identity = self._open_at(after_cursor)
        emitted = 0
        try:
            for line in self._read_available(handle, identity, stop_event=stop_event):
                yield line
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
    ) -> Iterator[RawLine]:
        """Follow the file, re-opening it after rotation until asked to stop."""

        handle, identity = self._open_at(after_cursor)
        try:
            while not stop_event.is_set():
                yield from self._read_available(handle, identity, stop_event=stop_event)
                if self._rotated_away(identity):
                    # The open descriptor still addresses the renamed file, so
                    # its tail is drained before the handle is released.
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
    ) -> Iterator[RawLine]:
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
                # Still being written: rewind so it is read once complete.
                handle.seek(start)
                return
            line = self._line(chunk, identity=identity, end_offset=handle.tell())
            if line is not None:
                yield line

    def _discard_overlong(self, handle: BinaryIO, *, stop_event: Event) -> bool:
        """Skip past a line longer than the cap; return False at end of file."""

        logger.warning("log_line_discarded reason=too_long")
        while not stop_event.is_set():
            chunk = handle.readline(MAX_LINE_BYTES)
            if not chunk:
                return False
            if chunk.endswith(b"\n"):
                return True
        return False

    def _line(
        self,
        raw: bytes,
        *,
        identity: tuple[int, int],
        end_offset: int,
    ) -> RawLine | None:
        text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if "\x00" in text:
            return None
        device, inode = identity
        # The content hash is what stops a reused inode from re-issuing a cursor
        # already committed for a different line (ADR-0019 §2).
        digest = hashlib.sha256(raw).hexdigest()[:12]
        return RawLine(text=text, cursor=f"{device}:{inode}:{end_offset}:{digest}")

    # ------------------------------------------------------------------ opening

    def _open_at(self, after_cursor: str | None) -> tuple[BinaryIO, tuple[int, int]]:
        if after_cursor is None:
            return self._open_path(start_offset=0)

        parsed = CURSOR_PATTERN.fullmatch(after_cursor)
        if parsed is None:
            raise FollowedFileCursorUnavailableError("saved cursor is invalid")

        handle, identity = self._open_path(start_offset=0)
        if (int(parsed.group("dev")), int(parsed.group("ino"))) != identity:
            handle.close()
            raise FollowedFileCursorUnavailableError("saved cursor belongs to a rotated file")

        offset = int(parsed.group("offset"))
        if offset > os.fstat(handle.fileno()).st_size:
            # copytruncate: same inode, fresh content — restart from the top.
            logger.warning("log_file_truncated restart=true")
            return handle, identity
        handle.seek(offset)
        return handle, identity

    def _open_path(self, *, start_offset: int) -> tuple[BinaryIO, tuple[int, int]]:
        flags = os.O_RDONLY | cast(int, getattr(os, "O_NOFOLLOW", 0))
        try:
            descriptor = os.open(self._path, flags)
        except OSError as error:
            raise FollowedFileUnavailableError("log file cannot be opened") from error

        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise FollowedFileUnavailableError("log file must be a regular file")
            handle = cast(BinaryIO, os.fdopen(descriptor, "rb"))
        except Exception:
            os.close(descriptor)
            raise

        handle.seek(start_offset)
        return handle, (metadata.st_dev, metadata.st_ino)

    def _rotated_away(self, identity: tuple[int, int]) -> bool:
        try:
            metadata = self._path.stat()
        except OSError:
            return False
        return (metadata.st_dev, metadata.st_ino) != identity
