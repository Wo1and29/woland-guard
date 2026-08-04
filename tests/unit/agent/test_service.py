"""Restart and SIGTERM lifecycle tests using only synthetic records."""

import signal
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from random import Random
from threading import Event
from types import FrameType

import pytest

from woland_guard_agent.delivery import BackoffPolicy, DeliveryManager
from woland_guard_agent.service import AgentRuntimeError, AgentService
from woland_guard_agent.sources import JournalRecord, JournalSource
from woland_guard_agent.sources.journald import JournaldCursorUnavailableError
from woland_guard_agent.spool import SQLiteSpool
from woland_guard_agent.transport import DeliveryClass, TransportResult
from woland_guard_contracts import EventSource, NormalizedEventV1


class SyntheticSource:
    name = "journald"
    event_source = EventSource.JOURNALD

    def __init__(self, records: list[JournalRecord]) -> None:
        self._records = records
        self.after_cursors: list[str | None] = []

    def backlog(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
        initial_limit: int | None,
    ) -> Iterator[JournalRecord]:
        del stop_event, initial_limit
        self.after_cursors.append(after_cursor)
        yield from self._records

    def follow(
        self,
        *,
        after_cursor: str | None,
        stop_event: Event,
    ) -> Iterator[JournalRecord]:
        del after_cursor, stop_event
        yield from ()


class FixedTransport:
    def __init__(self, classification: DeliveryClass) -> None:
        self.classification = classification
        self.sent: list[list[NormalizedEventV1]] = []

    def send(self, events: list[NormalizedEventV1]) -> TransportResult:
        self.sent.append(events)
        accepted = len(events) if self.classification is DeliveryClass.SUCCESS else 0
        return TransportResult(
            self.classification,
            request_id="synthetic-request",
            accepted=accepted,
        )


def test_restart_uses_cursor_and_retries_existing_spool(tmp_path: Path) -> None:
    path = tmp_path / "restart.sqlite3"
    first_source = SyntheticSource(
        [
            JournalRecord(
                cursor="s=restart;i=1",
                fields={
                    "__REALTIME_TIMESTAMP": "1720000000000000",
                    "SYSLOG_IDENTIFIER": "sshd",
                    "MESSAGE": ("Failed password for restart_user from 192.0.2.30 port 22 ssh2"),
                },
            )
        ]
    )
    first_spool = SQLiteSpool(path, max_events=10)
    first_transport = FixedTransport(DeliveryClass.NETWORK_ERROR)
    first_service = make_service(first_source, first_spool, first_transport)

    first_result = first_service.run_once()

    assert first_result.collected == 1
    assert first_spool.cursor("journald") == "s=restart;i=1"
    assert first_spool.statistics().pending == 1

    restarted_source = SyntheticSource([])
    restarted_spool = SQLiteSpool(path, max_events=10)
    recovered_transport = FixedTransport(DeliveryClass.SUCCESS)
    restarted_service = make_service(restarted_source, restarted_spool, recovered_transport)

    second_result = restarted_service.run_once()

    assert restarted_source.after_cursors == ["s=restart;i=1"]
    assert second_result.delivery.accepted == 1
    assert restarted_spool.statistics().total == 0


def test_repeated_run_once_respects_limit_and_continues_oldest_backlog(
    tmp_path: Path,
) -> None:
    class PaginatedSource:
        name = "journald"
        event_source = EventSource.JOURNALD

        def __init__(self) -> None:
            self.records = [
                supported_record(
                    f"s=page;i={number}",
                    actor=f"page_{number}",
                    ip=f"192.0.2.{number}",
                )
                for number in range(1, 6)
            ]
            self.calls: list[tuple[str | None, int | None, list[str]]] = []

        def backlog(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
            initial_limit: int | None,
        ) -> Iterator[JournalRecord]:
            del stop_event
            cursor_order = ["s=page;i=0", *(record.cursor for record in self.records)]
            start = 0 if after_cursor is None else cursor_order.index(after_cursor)
            available = self.records[start:]
            selected = available if initial_limit is None else available[:initial_limit]
            self.calls.append((after_cursor, initial_limit, [record.cursor for record in selected]))
            yield from selected

        def follow(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
        ) -> Iterator[JournalRecord]:
            del after_cursor, stop_event
            yield from ()

    spool = SQLiteSpool(tmp_path / "paginated-run-once.sqlite3", max_events=10)
    spool.initialize()
    spool.advance_cursor(source_name="journald", cursor="s=page;i=0")
    source = PaginatedSource()
    service = make_service(source, spool, FixedTransport(DeliveryClass.NETWORK_ERROR))

    first = service.run_once(source_limit=2)
    second = service.run_once(source_limit=2)
    third = service.run_once(source_limit=2)

    assert [first.collected, second.collected, third.collected] == [2, 2, 1]
    assert [call[0] for call in source.calls] == [
        "s=page;i=0",
        "s=page;i=2",
        "s=page;i=4",
    ]
    assert all(len(call[2]) <= 2 for call in source.calls)
    assert [cursor for call in source.calls for cursor in call[2]] == [
        "s=page;i=1",
        "s=page;i=2",
        "s=page;i=3",
        "s=page;i=4",
        "s=page;i=5",
    ]
    assert spool.cursor("journald") == "s=page;i=5"
    assert spool.statistics().total == 5


def test_restart_drains_ordered_backlog_then_follows_live_records(tmp_path: Path) -> None:
    class TwoPhaseSource:
        name = "journald"
        event_source = EventSource.JOURNALD

        def __init__(self) -> None:
            self.backlog_cursor: str | None = None
            self.follow_cursor: str | None = None

        def backlog(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
            initial_limit: int | None,
        ) -> Iterator[JournalRecord]:
            del stop_event, initial_limit
            self.backlog_cursor = after_cursor
            yield supported_record("s=backlog;i=1", actor="backlog_one", ip="192.0.2.1")
            yield supported_record("s=backlog;i=2", actor="backlog_two", ip="192.0.2.2")

        def follow(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
        ) -> Iterator[JournalRecord]:
            del stop_event
            self.follow_cursor = after_cursor
            yield supported_record("s=live;i=3", actor="live_three", ip="192.0.2.3")

    spool = SQLiteSpool(tmp_path / "two-phase.sqlite3", max_events=10)
    spool.initialize()
    spool.advance_cursor(source_name="journald", cursor="s=before-stop;i=0")
    source = TwoPhaseSource()
    transport = FixedTransport(DeliveryClass.SUCCESS)
    service = make_service(source, spool, transport)

    service._collect_cycle()

    assert source.backlog_cursor == "s=before-stop;i=0"
    assert source.follow_cursor == "s=backlog;i=2"
    assert spool.cursor("journald") == "s=live;i=3"
    expected_actors = [
        "backlog_one",
        "backlog_two",
        "live_three",
    ]
    assert [event.event.actor for event in spool.ready_batch(limit=10)] == expected_actors

    delivery = service._delivery.deliver_once()

    assert delivery.accepted == 3
    assert [event.actor for event in transport.sent[0]] == expected_actors
    assert spool.statistics().total == 0


def test_unknown_message_advances_cursor_without_creating_event(tmp_path: Path) -> None:
    source = SyntheticSource(
        [
            JournalRecord(
                cursor="s=unknown;i=1",
                fields={"SYSLOG_IDENTIFIER": "bash", "MESSAGE": "echo secret"},
            )
        ]
    )
    spool = SQLiteSpool(tmp_path / "skipped.sqlite3", max_events=10)
    service = make_service(source, spool, FixedTransport(DeliveryClass.NETWORK_ERROR))

    result = service.run_once()

    assert result.skipped == 1
    assert result.collected == 0
    assert spool.cursor("journald") == "s=unknown;i=1"
    assert spool.statistics().total == 0


def test_stale_cursor_records_persistent_gap_before_rebase(tmp_path: Path) -> None:
    class StaleSource(SyntheticSource):
        def backlog(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
            initial_limit: int | None,
        ) -> Iterator[JournalRecord]:
            del after_cursor, stop_event, initial_limit
            raise JournaldCursorUnavailableError("synthetic stale cursor")

    spool = SQLiteSpool(tmp_path / "gap.sqlite3", max_events=10)
    spool.initialize()
    spool.advance_cursor(source_name="journald", cursor="s=rotated;i=1")
    service = make_service(
        StaleSource([]),
        spool,
        FixedTransport(DeliveryClass.NETWORK_ERROR),
    )

    service.run_once()

    assert spool.cursor("journald") is None
    diagnostics = spool.diagnostics()
    assert [(item.code, item.occurrences) for item in diagnostics] == [("journal_gap", 1)]


def test_sigterm_handler_stops_without_deleting_spool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = SyntheticSource([])
    spool = SQLiteSpool(tmp_path / "sigterm.sqlite3", max_events=10)
    spool.initialize()
    event = NormalizedEventV1(
        occurred_at=datetime(2024, 1, 1, tzinfo=UTC),
        collected_at=datetime(2024, 1, 1, tzinfo=UTC),
        event_type="linux.journald",
    )
    spool.enqueue_with_cursor(source_name="journald", cursor="s=sigterm", event=event)
    service = make_service(source, spool, FixedTransport(DeliveryClass.NETWORK_ERROR))
    handlers: dict[int, Callable[[int, FrameType | None], None]] = {}

    def capture_handler(
        signum: int,
        handler: Callable[[int, FrameType | None], None],
    ) -> None:
        handlers[signum] = handler

    monkeypatch.setattr(signal, "signal", capture_handler)
    service.install_signal_handlers()
    handlers[signal.SIGTERM](signal.SIGTERM, None)

    assert service.stopping
    assert spool.contains(event.event_id)
    assert spool.cursor("journald") == "s=sigterm"


def test_unexpected_collector_failure_exits_safely_for_systemd_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class FailingIterator:
        def __iter__(self) -> "FailingIterator":
            return self

        def __next__(self) -> JournalRecord:
            raise RuntimeError("synthetic-sensitive-payload")

    class FailingSource:
        name = "journald"
        event_source = EventSource.JOURNALD

        def backlog(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
            initial_limit: int | None,
        ) -> Iterator[JournalRecord]:
            del after_cursor, stop_event, initial_limit
            return FailingIterator()

        def follow(
            self,
            *,
            after_cursor: str | None,
            stop_event: Event,
        ) -> Iterator[JournalRecord]:
            del after_cursor, stop_event
            yield from ()

    spool = SQLiteSpool(tmp_path / "collector-failure.sqlite3", max_events=10)
    service = make_service(
        FailingSource(),
        spool,
        FixedTransport(DeliveryClass.NETWORK_ERROR),
    )
    monkeypatch.setattr(signal, "signal", lambda *_arguments: None)

    with caplog.at_level("ERROR"), pytest.raises(AgentRuntimeError, match="collector failed"):
        service.run()

    assert "synthetic-sensitive-payload" not in caplog.text
    assert "source_collector_failed" in caplog.text


def make_service(
    source: JournalSource,
    spool: SQLiteSpool,
    transport: FixedTransport,
) -> AgentService:
    delivery = DeliveryManager(
        spool=spool,
        transport=transport,
        configured_batch_size=100,
        backoff=BackoffPolicy(
            base_seconds=0,
            maximum_seconds=0,
            random_source=Random(1),  # noqa: S311 - deterministic test jitter
        ),
        authentication_retry_seconds=300,
    )
    return AgentService(
        source=source,
        spool=spool,
        delivery=delivery,
        delivery_poll_seconds=0.01,
    )


def supported_record(cursor: str, *, actor: str, ip: str) -> JournalRecord:
    return JournalRecord(
        cursor=cursor,
        fields={
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": f"Accepted publickey for {actor} from {ip} port 22 ssh2",
        },
    )
