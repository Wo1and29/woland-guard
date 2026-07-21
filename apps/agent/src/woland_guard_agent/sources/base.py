"""Source-independent interface for journal event adapters."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from threading import Event
from typing import Protocol


@dataclass(frozen=True, slots=True)
class JournalRecord:
    """A raw record plus the cursor needed for reliable resumption."""

    cursor: str
    fields: Mapping[str, object]


class JournalSource(Protocol):
    """Common extension point for current and future journal adapters."""

    name: str

    def backlog(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        initial_limit: int | None,
    ) -> Iterator[JournalRecord]:
        """Read the finite backlog available after the committed cursor."""

        ...

    def follow(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
    ) -> Iterator[JournalRecord]:
        """Resume after the committed cursor and continue following live records."""

        ...
