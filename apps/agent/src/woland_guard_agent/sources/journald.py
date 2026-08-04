"""Ubuntu 24.04 journald adapter implemented through the fixed journalctl binary."""

from __future__ import annotations

import json
import logging
import re
import select
import subprocess
from collections.abc import Iterator, Sequence
from threading import Event
from typing import IO

from woland_guard_agent.journald_fields import JOURNALD_OUTPUT_FIELDS
from woland_guard_agent.sources.base import (
    JournalRecord,
    SourceCursorUnavailableError,
    SourceUnavailableError,
)
from woland_guard_contracts import EventSource

logger = logging.getLogger(__name__)

JOURNALCTL_PATH = "/usr/bin/journalctl"
_CURSOR_PATTERN = re.compile(r"^[A-Za-z0-9;=_:.+-]{1,4096}$")


class JournaldUnavailableError(SourceUnavailableError):
    """The fixed journald reader cannot be started or completed."""


class JournaldCursorUnavailableError(JournaldUnavailableError, SourceCursorUnavailableError):
    """The saved cursor is no longer addressable by the local journal."""


class JournaldSource:
    """Read journald JSON and resume from a previously committed cursor."""

    name = "journald"
    event_source = EventSource.JOURNALD

    def backlog(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        initial_limit: int | None,
    ) -> Iterator[JournalRecord]:
        """Drain all records currently available after the committed cursor."""

        yield from self._read(
            after_cursor=_require_valid_cursor(after_cursor),
            stop_event=stop_event,
            follow=False,
            initial_limit=initial_limit,
        )

    def follow(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
    ) -> Iterator[JournalRecord]:
        """Follow from the committed cursor, covering the phase transition window."""

        yield from self._read(
            after_cursor=_require_valid_cursor(after_cursor),
            stop_event=stop_event,
            follow=True,
            initial_limit=1,
        )

    def _read(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        follow: bool,
        initial_limit: int | None,
    ) -> Iterator[JournalRecord]:
        command = build_journalctl_command(
            after_cursor=after_cursor,
            follow=follow,
            initial_limit=initial_limit,
        )
        try:
            process = subprocess.Popen(  # noqa: S603 - executable and arguments are fixed
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as error:
            raise JournaldUnavailableError("journalctl could not be started") from error

        if process.stdout is None:
            process.kill()
            process.wait(timeout=3)
            raise JournaldUnavailableError("journalctl stdout pipe is unavailable")
        yielded_record = False
        try:
            for record in _records_from_process(
                process,
                process.stdout,
                stop_event=stop_event,
            ):
                yielded_record = True
                yield record
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)

        if process.returncode not in (0, -15) and not stop_event.is_set():
            if after_cursor is not None and not yielded_record:
                raise JournaldCursorUnavailableError("saved journald cursor is unavailable")
            raise JournaldUnavailableError("journalctl failed while reading the journal")


def build_journalctl_command(
    *,
    after_cursor: str | None,
    follow: bool,
    initial_limit: int | None,
) -> list[str]:
    """Build a non-shell command with no user-controlled executable or arbitrary flags."""

    output_fields = ",".join(JOURNALD_OUTPUT_FIELDS)
    command = [
        JOURNALCTL_PATH,
        "--output=json",
        f"--output-fields={output_fields}",
        "--no-pager",
    ]
    if after_cursor is not None:
        validated = _validated_cursor(after_cursor)
        if validated is None:
            raise ValueError("unsafe journald cursor")
        command.append(f"--after-cursor={validated}")
    if follow:
        command.extend(("--follow", "--lines=all"))
    elif initial_limit is None:
        command.append("--lines=all")
    else:
        safe_limit = max(1, min(initial_limit, 1_000))
        line_count = f"+{safe_limit}" if after_cursor is not None else str(safe_limit)
        command.append(f"--lines={line_count}")
    return command


def parse_journal_json_line(line: str) -> JournalRecord | None:
    """Parse one synthetic or journalctl-produced JSON line without normalizing fields."""

    try:
        document = json.loads(line)
    except (json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(document, dict):
        return None

    cursor = document.get("__CURSOR")
    if not isinstance(cursor, str) or _validated_cursor(cursor) is None:
        return None
    return JournalRecord(cursor=cursor, fields=document)


def _records_from_process(
    process: subprocess.Popen[str],
    output: IO[str],
    *,
    stop_event: Event,
) -> Iterator[JournalRecord]:
    while not stop_event.is_set():
        readable, _, _ = select.select([output], [], [], 0.5)
        if not readable:
            if process.poll() is not None:
                break
            continue
        line = output.readline()
        if not line:
            if process.poll() is not None:
                break
            continue
        record = parse_journal_json_line(line)
        if record is not None:
            yield record


def _validated_cursor(cursor: str | None) -> str | None:
    if cursor is None or _CURSOR_PATTERN.fullmatch(cursor) is None:
        return None
    return cursor


def _require_valid_cursor(cursor: str | None) -> str | None:
    if cursor is None:
        return None
    validated = _validated_cursor(cursor)
    if validated is None:
        raise JournaldCursorUnavailableError("saved journald cursor is invalid")
    return validated


def command_contains_only_fixed_options(command: Sequence[str]) -> bool:
    """Expose a small diagnostic assertion without executing journalctl."""

    return (
        bool(command)
        and command[0] == JOURNALCTL_PATH
        and all("\x00" not in item for item in command)
    )
