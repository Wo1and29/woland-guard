"""Journald adapter tests that never access the host journal."""

from collections.abc import Iterator
from threading import Event

import pytest

from woland_guard_agent.journald_fields import JOURNALD_OUTPUT_FIELDS
from woland_guard_agent.sources import JournalRecord
from woland_guard_agent.sources.journald import (
    JOURNALCTL_PATH,
    JournaldCursorUnavailableError,
    JournaldSource,
    build_journalctl_command,
    command_contains_only_fixed_options,
    parse_journal_json_line,
)


def test_continuous_backlog_without_cursor_reads_all_available_records() -> None:
    command = build_journalctl_command(
        after_cursor=None,
        follow=False,
        initial_limit=None,
    )

    assert command == [
        JOURNALCTL_PATH,
        "--output=json",
        f"--output-fields={','.join(JOURNALD_OUTPUT_FIELDS)}",
        "--no-pager",
        "--lines=all",
    ]
    assert command_contains_only_fixed_options(command)


def test_continuous_backlog_after_cursor_reads_all_available_records() -> None:
    command = build_journalctl_command(
        after_cursor="s=fixture;i=10",
        follow=False,
        initial_limit=None,
    )

    assert command[-2:] == [
        "--after-cursor=s=fixture;i=10",
        "--lines=all",
    ]


def test_follow_command_replays_transition_window_before_live_records() -> None:
    command = build_journalctl_command(
        after_cursor="s=fixture;i=11",
        follow=True,
        initial_limit=1,
    )

    assert command[-3:] == [
        "--after-cursor=s=fixture;i=11",
        "--follow",
        "--lines=all",
    ]
    assert "--lines=0" not in command


def test_run_once_without_cursor_reads_latest_bounded_snapshot() -> None:
    command = build_journalctl_command(
        after_cursor=None,
        follow=False,
        initial_limit=25,
    )

    assert command[-1] == "--lines=25"


def test_run_once_after_cursor_reads_oldest_bounded_backlog() -> None:
    command = build_journalctl_command(
        after_cursor="s=fixture;i=12",
        follow=False,
        initial_limit=25,
    )

    assert command[-2:] == [
        "--after-cursor=s=fixture;i=12",
        "--lines=+25",
    ]


def test_unsafe_cursor_cannot_become_a_journalctl_argument() -> None:
    with pytest.raises(ValueError, match="unsafe journald cursor"):
        build_journalctl_command(
            after_cursor="cursor\x00--output=export",
            follow=False,
            initial_limit=100,
        )


def test_invalid_json_or_missing_cursor_is_skipped() -> None:
    assert parse_journal_json_line("not-json") is None
    assert parse_journal_json_line('{"MESSAGE":"missing"}') is None


def test_unavailable_stored_cursor_is_not_silently_rebased() -> None:
    class SyntheticJournald(JournaldSource):
        def __init__(self) -> None:
            self.calls: list[str | None] = []

        def _read(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
            follow: bool,
            initial_limit: int | None,
        ) -> Iterator[JournalRecord]:
            del stop_event, follow, initial_limit
            self.calls.append(after_cursor)
            raise JournaldCursorUnavailableError("synthetic stale cursor")

    source = SyntheticJournald()

    with pytest.raises(JournaldCursorUnavailableError, match="stale cursor"):
        list(
            source.backlog(
                after_cursor="s=old;i=1",
                stop_event=Event(),
                initial_limit=None,
            )
        )

    assert source.calls == ["s=old;i=1"]


def test_invalid_stored_cursor_is_an_explicit_gap() -> None:
    source = JournaldSource()

    with pytest.raises(JournaldCursorUnavailableError, match="invalid"):
        list(
            source.backlog(
                after_cursor="unsafe cursor",
                stop_event=Event(),
                initial_limit=None,
            )
        )
