"""Reliable spool delivery policy and bounded retry scheduling."""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from woland_guard_agent.spool import SQLiteSpool
from woland_guard_agent.transport import DeliveryClass, IngestionTransport, TransportResult
from woland_guard_contracts import NormalizedEventV1


class Transport(Protocol):
    def send(self, events: list[NormalizedEventV1]) -> TransportResult: ...


class RandomSource(Protocol):
    def random(self) -> float: ...


class DeliveryAction(StrEnum):
    IDLE = "idle"
    DELIVERED = "delivered"
    DEFERRED = "deferred"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    action: DeliveryAction
    request_id: str | None = None
    event_count: int = 0
    accepted: int = 0
    existing: int = 0
    retry_after_seconds: float | None = None


class BackoffPolicy:
    """Exponential equal-jitter delays capped by configuration."""

    def __init__(
        self,
        *,
        base_seconds: float,
        maximum_seconds: float,
        random_source: RandomSource | None = None,
    ) -> None:
        self._base = base_seconds
        self._maximum = maximum_seconds
        self._random = random_source or random.SystemRandom()

    def delay(self, attempt: int) -> float:
        exponent = max(0, min(attempt, 30))
        cap = min(self._maximum, self._base * (2**exponent))
        return float(cap / 2 + self._random.random() * cap / 2)


class DeliveryManager:
    """Apply status-specific behavior while deleting rows only after valid HTTP 200."""

    def __init__(
        self,
        *,
        spool: SQLiteSpool,
        transport: Transport,
        configured_batch_size: int,
        backoff: BackoffPolicy,
        authentication_retry_seconds: float,
    ) -> None:
        self._spool = spool
        self._transport = transport
        self._configured_batch_size = configured_batch_size
        self._current_batch_size = configured_batch_size
        self._backoff = backoff
        self._authentication_retry_seconds = authentication_retry_seconds

    @property
    def current_batch_size(self) -> int:
        return self._current_batch_size

    @property
    def transport(self) -> Transport:
        return self._transport

    def deliver_once(self) -> DeliveryOutcome:
        queued = self._spool.ready_batch(limit=self._current_batch_size)
        if not queued:
            return DeliveryOutcome(DeliveryAction.IDLE)

        events = [item.event for item in queued]
        event_ids = [event.event_id for event in events]
        result = self._transport.send(events)

        if result.classification is DeliveryClass.SUCCESS:
            self._spool.acknowledge(event_ids)
            self._current_batch_size = self._configured_batch_size
            return DeliveryOutcome(
                DeliveryAction.DELIVERED,
                request_id=result.request_id,
                event_count=len(events),
                accepted=result.accepted,
                existing=result.existing,
            )

        if result.classification in {DeliveryClass.AUTHENTICATION, DeliveryClass.FORBIDDEN}:
            return self._defer(
                event_ids,
                result=result,
                delay=self._authentication_retry_seconds,
            )

        if result.classification is DeliveryClass.PAYLOAD_TOO_LARGE:
            return self._handle_splittable_failure(
                event_ids,
                result=result,
                terminal_status="oversized",
            )

        if result.classification is DeliveryClass.UNPROCESSABLE:
            return self._handle_splittable_failure(
                event_ids,
                result=result,
                terminal_status="quarantined",
            )

        if result.classification is DeliveryClass.RATE_LIMITED:
            delay = result.retry_after_seconds
            if delay is None:
                delay = self._backoff.delay(max(item.attempts for item in queued))
            return self._defer(event_ids, result=result, delay=delay)

        delay = self._backoff.delay(max(item.attempts for item in queued))
        return self._defer(event_ids, result=result, delay=delay)

    def _handle_splittable_failure(
        self,
        event_ids: list[UUID],
        *,
        result: TransportResult,
        terminal_status: str,
    ) -> DeliveryOutcome:
        if len(event_ids) > 1:
            self._current_batch_size = max(1, len(event_ids) // 2)
            return self._defer(event_ids, result=result, delay=0.0)

        self._spool.quarantine(
            event_ids[0],
            status=terminal_status,
            error_code=result.classification.value,
        )
        return DeliveryOutcome(
            DeliveryAction.QUARANTINED,
            request_id=result.request_id,
            event_count=1,
        )

    def _defer(
        self,
        event_ids: list[UUID],
        *,
        result: TransportResult,
        delay: float,
    ) -> DeliveryOutcome:
        self._spool.defer(
            event_ids,
            delay_seconds=delay,
            error_code=result.classification.value,
        )
        return DeliveryOutcome(
            DeliveryAction.DEFERRED,
            request_id=result.request_id,
            event_count=len(event_ids),
            retry_after_seconds=delay,
        )


def close_transport(transport: object) -> None:
    """Close the production transport without expanding the protocol used in tests."""

    if isinstance(transport, IngestionTransport):
        transport.close()
