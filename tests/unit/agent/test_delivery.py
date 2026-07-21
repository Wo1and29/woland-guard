"""Spool delivery policy for every required HTTP class."""

from datetime import UTC, datetime
from pathlib import Path
from random import Random
from uuid import UUID

import pytest

from woland_guard_agent.delivery import (
    BackoffPolicy,
    DeliveryAction,
    DeliveryManager,
)
from woland_guard_agent.spool import SQLiteSpool
from woland_guard_agent.transport import DeliveryClass, TransportResult
from woland_guard_contracts import NormalizedEventV1


class SequenceTransport:
    def __init__(self, results: list[TransportResult]) -> None:
        self._results = iter(results)
        self.batches: list[list[NormalizedEventV1]] = []

    def send(self, events: list[NormalizedEventV1]) -> TransportResult:
        self.batches.append(events)
        return next(self._results)


def test_success_deletes_batch_after_accepted_and_existing(tmp_path: Path) -> None:
    spool = populated_spool(tmp_path, count=2)
    transport = SequenceTransport(
        [
            TransportResult(
                DeliveryClass.SUCCESS,
                request_id="success",
                accepted=1,
                existing=1,
            )
        ]
    )
    manager = make_manager(spool, transport, batch_size=2)

    outcome = manager.deliver_once()

    assert outcome.action is DeliveryAction.DELIVERED
    assert outcome.accepted == 1
    assert outcome.existing == 1
    assert spool.statistics().total == 0


@pytest.mark.parametrize(
    "classification",
    [DeliveryClass.AUTHENTICATION, DeliveryClass.FORBIDDEN],
)
def test_authentication_failures_use_non_aggressive_retry(
    tmp_path: Path,
    classification: DeliveryClass,
) -> None:
    spool = populated_spool(tmp_path, count=1)
    transport = SequenceTransport([TransportResult(classification, request_id="auth-failure")])
    manager = make_manager(spool, transport, batch_size=1)

    outcome = manager.deliver_once()

    assert outcome.action is DeliveryAction.DEFERRED
    assert outcome.retry_after_seconds == 300
    assert spool.statistics().pending == 1


def test_413_reduces_next_batch_size_without_deleting_events(tmp_path: Path) -> None:
    spool = populated_spool(tmp_path, count=4)
    transport = SequenceTransport(
        [TransportResult(DeliveryClass.PAYLOAD_TOO_LARGE, request_id="too-large")]
    )
    manager = make_manager(spool, transport, batch_size=4)

    outcome = manager.deliver_once()

    assert outcome.action is DeliveryAction.DEFERRED
    assert manager.current_batch_size == 2
    assert spool.statistics().pending == 4


def test_single_422_is_quarantined_and_not_retried_forever(tmp_path: Path) -> None:
    spool = populated_spool(tmp_path, count=1)
    transport = SequenceTransport(
        [TransportResult(DeliveryClass.UNPROCESSABLE, request_id="invalid")]
    )
    manager = make_manager(spool, transport, batch_size=1)

    first = manager.deliver_once()
    second = manager.deliver_once()

    assert first.action is DeliveryAction.QUARANTINED
    assert second.action is DeliveryAction.IDLE
    assert spool.statistics().quarantined == 1
    assert spool.statistics().total == 1


def test_429_honors_retry_after(tmp_path: Path) -> None:
    spool = populated_spool(tmp_path, count=1)
    transport = SequenceTransport(
        [
            TransportResult(
                DeliveryClass.RATE_LIMITED,
                request_id="rate-limited",
                retry_after_seconds=23,
            )
        ]
    )
    manager = make_manager(spool, transport, batch_size=1)

    outcome = manager.deliver_once()

    assert outcome.retry_after_seconds == 23
    assert spool.statistics().pending == 1


@pytest.mark.parametrize(
    "classification",
    [DeliveryClass.SERVER_ERROR, DeliveryClass.NETWORK_ERROR],
)
def test_transient_failures_use_exponential_jitter(
    tmp_path: Path,
    classification: DeliveryClass,
) -> None:
    spool = populated_spool(tmp_path, count=1)
    transport = SequenceTransport([TransportResult(classification, request_id="transient")])
    manager = make_manager(spool, transport, batch_size=1, backoff_base=2)

    outcome = manager.deliver_once()

    assert outcome.action is DeliveryAction.DEFERRED
    assert outcome.retry_after_seconds is not None
    assert 1 <= outcome.retry_after_seconds <= 2
    assert spool.statistics().pending == 1


def populated_spool(tmp_path: Path, *, count: int) -> SQLiteSpool:
    spool = SQLiteSpool(tmp_path / f"spool-{count}.sqlite3", max_events=100)
    spool.initialize()
    for number in range(count):
        event = NormalizedEventV1(
            event_id=UUID(int=number + 1),
            occurred_at=datetime(2024, 1, 1, tzinfo=UTC),
            collected_at=datetime(2024, 1, 1, tzinfo=UTC),
            event_type="linux.journald",
            summary=f"synthetic-{number}",
        )
        spool.enqueue_with_cursor(
            source_name="journald",
            cursor=f"s=delivery;i={number}",
            event=event,
        )
    return spool


def make_manager(
    spool: SQLiteSpool,
    transport: SequenceTransport,
    *,
    batch_size: int,
    backoff_base: float = 1,
) -> DeliveryManager:
    return DeliveryManager(
        spool=spool,
        transport=transport,
        configured_batch_size=batch_size,
        backoff=BackoffPolicy(
            base_seconds=backoff_base,
            maximum_seconds=60,
            random_source=Random(7),  # noqa: S311 - deterministic jitter assertion
        ),
        authentication_retry_seconds=300,
    )
