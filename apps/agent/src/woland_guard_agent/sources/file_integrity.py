"""Periodic integrity comparison for an explicit list of system files (ADR-0022).

Unlike every other source this one reads no log. It compares the current state of
each configured path against the state remembered in the source cursor, and the
privilege boundary is the whole point: the agent hashes only what it can already
read as an unprivileged user, and falls back to metadata for everything else
rather than asking for `root` or the `shadow` group.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from woland_guard_agent.sources.base import JournalRecord
from woland_guard_contracts import EventSource

# Configuration files are measured in kilobytes; anything larger is a sign the
# path is wrong, not that the file needs hashing.
MAX_HASHED_BYTES = 8 * 1024 * 1024
# The spool schema caps a cursor at 4096 characters and one entry costs 33, so
# this bound keeps the serialized baseline well inside it (ADR-0022 §8).
MAX_WATCHED_PATHS = 64

_STATE_CHARS = 16
_PERMISSION_CHARS = 8
# A file that is absent has to be distinguishable from one that is merely
# unreadable, or its reappearance would be reported as an ordinary edit.
MISSING_STATE = "0" * _STATE_CHARS
MISSING_PERMISSIONS = "0" * _PERMISSION_CHARS


@dataclass(frozen=True, slots=True)
class FileState:
    """What the agent was able to observe about one path in one scan."""

    state_digest: str
    permission_digest: str
    present: bool
    # False only when the file exists but could not be read; this is what selects
    # between the strong and the weak monitoring mode (ADR-0022 §2).
    readable: bool

    def observable(self) -> str:
        return f"{self.state_digest}{self.permission_digest}"


class FileIntegritySource:
    """Compare configured paths against the baseline carried in the cursor."""

    name = "file_integrity"
    event_source = EventSource.FILE_INTEGRITY

    def __init__(self, paths: Sequence[Path], *, poll_seconds: float = 60.0) -> None:
        if not paths:
            raise ValueError("file integrity source requires at least one path")
        if len(paths) > MAX_WATCHED_PATHS:
            raise ValueError("too many watched paths")
        self._paths = tuple(paths)
        self._poll_seconds = poll_seconds

    def backlog(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        initial_limit: int | None,
    ) -> Iterator[JournalRecord]:
        """Run exactly one comparison; this source has no backlog to drain."""

        del initial_limit
        yield from self._scan(after_cursor, stop_event)

    def follow(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
    ) -> Iterator[JournalRecord]:
        """Compare on every interval until asked to stop."""

        baseline = after_cursor
        while not stop_event.is_set():
            for record in self._scan(baseline, stop_event):
                baseline = record.cursor
                yield record
            stop_event.wait(self._poll_seconds)

    def _scan(self, after_cursor: str | None, stop_event: Event) -> Iterator[JournalRecord]:
        baseline = parse_baseline(after_cursor)
        current = {key(path): (path, read_state(path)) for path in self._paths}
        committed = {name: value for name, value in baseline.items() if name in current}

        if not baseline:
            # The first observation is not a change (ADR-0022 §7). This record
            # carries no change marker, so normalization drops it and the service
            # commits the cursor without emitting an event -- which is exactly
            # what persists the baseline across a restart.
            yield _baseline_record(
                {name: state.observable() for name, (_, state) in current.items()}
            )
            return

        for name, (path, state) in current.items():
            if stop_event.is_set():
                return
            previous = baseline.get(name)
            observed = state.observable()
            committed[name] = observed
            if previous is None:
                # A newly configured path establishes its own baseline silently,
                # for the same reason the very first scan does.
                continue
            if previous == observed:
                continue
            yield JournalRecord(
                cursor=serialize_baseline(committed),
                fields={
                    "FILE_INTEGRITY_PATH": str(path),
                    "FILE_INTEGRITY_CHANGE": classify(previous, state),
                    "FILE_INTEGRITY_MONITORING": "content" if state.readable else "metadata",
                },
            )

        if set(committed) != set(baseline):
            # Paths removed from the configuration must leave the baseline, or
            # they would occupy cursor length forever.
            yield _baseline_record(committed)


def _baseline_record(entries: Mapping[str, str]) -> JournalRecord:
    return JournalRecord(
        cursor=serialize_baseline(entries),
        fields={"FILE_INTEGRITY_BASELINE": True},
    )


def classify(previous: str, state: FileState) -> str:
    """Name the change without revealing which bytes moved."""

    if not state.present:
        return "disappeared"
    if previous[:_STATE_CHARS] == MISSING_STATE:
        return "appeared"
    if previous[:_STATE_CHARS] != state.state_digest:
        return "content" if state.readable else "metadata"
    return "permissions"


def read_state(path: Path) -> FileState:
    """Observe one path with the strongest mode its permissions allow."""

    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return _state_without_reading(path)

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HASHED_BYTES:
            # A FIFO or character device in place of a config would block the read
            # forever, and an oversized file is a misconfigured path (ADR-0022 §9).
            return _state_from_stat(info, content=None)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 65_536):
            digest.update(chunk)
        return _state_from_stat(info, content=digest.hexdigest())
    except OSError:
        return _state_without_reading(path)
    finally:
        os.close(descriptor)


def _state_without_reading(path: Path) -> FileState:
    """Fall back to stat, which needs no read permission on the file itself."""

    try:
        info = os.stat(path)
    except OSError:
        return FileState(
            state_digest=MISSING_STATE,
            permission_digest=MISSING_PERMISSIONS,
            present=False,
            readable=False,
        )
    return _state_from_stat(info, content=None)


def _state_from_stat(info: os.stat_result, *, content: str | None) -> FileState:
    permissions = f"{stat.S_IMODE(info.st_mode):04o}:{info.st_uid}:{info.st_gid}"
    # Size and mtime participate only when the content is unavailable: with a hash
    # in hand they are noise that fires on every configuration-management rewrite
    # of identical content (ADR-0022 §3).
    material = content if content is not None else f"meta|{info.st_size}|{info.st_mtime_ns}"
    return FileState(
        state_digest=_digest(material, _STATE_CHARS),
        permission_digest=_digest(permissions, _PERMISSION_CHARS),
        present=True,
        readable=content is not None,
    )


def _digest(material: str, length: int) -> str:
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:length]


def key(path: Path) -> str:
    """Key the baseline by path, so reordering the configuration changes nothing."""

    return _digest(str(path), 8)


def serialize_baseline(entries: Mapping[str, str]) -> str:
    return ",".join(f"{name}:{value}" for name, value in sorted(entries.items()))


def parse_baseline(cursor: str | None) -> dict[str, str]:
    """Read a committed baseline, treating anything malformed as absent."""

    if not cursor:
        return {}
    entries: dict[str, str] = {}
    for item in cursor.split(","):
        name, separator, value = item.partition(":")
        if not separator or not name.isalnum() or not value.isalnum():
            return {}
        if len(value) != _STATE_CHARS + _PERMISSION_CHARS:
            return {}
        entries[name] = value
    return entries
