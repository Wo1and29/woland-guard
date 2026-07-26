"""Lease-based at-least-once outbox worker with safe adapter boundaries."""

from __future__ import annotations

import logging
import math
import random
import signal
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Event
from types import FrameType
from typing import Protocol
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import case, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from woland_guard_control_plane.application.audit import record_local_cli_action
from woland_guard_control_plane.application.outbox import IncidentCreatedNotificationV1
from woland_guard_control_plane.infrastructure.database.models import (
    NotificationDestination,
    OutboxErrorCode,
    OutboxMessage,
    OutboxStatus,
)

logger = logging.getLogger(__name__)

_ERROR_MESSAGES: Mapping[OutboxErrorCode, str] = {
    OutboxErrorCode.ADAPTER_UNEXPECTED_ERROR: "Delivery adapter failed unexpectedly.",
    OutboxErrorCode.ATTEMPTS_EXHAUSTED: "Delivery attempt limit was exhausted.",
    OutboxErrorCode.DESTINATION_DISABLED: "Notification destination is disabled.",
    OutboxErrorCode.DESTINATION_UNCONFIGURED: "Notification destination is not configured.",
    OutboxErrorCode.LEASE_EXPIRED: "Delivery claim lease expired.",
    OutboxErrorCode.PAYLOAD_INVALID: "Notification payload is invalid.",
    OutboxErrorCode.PERMANENT_DELIVERY_ERROR: "Delivery was rejected permanently.",
    OutboxErrorCode.RETRYABLE_DELIVERY_ERROR: "Delivery failed temporarily.",
}


class OutboxOperationError(RuntimeError):
    """Safe application-layer error without database or adapter details."""


class LeaseLostError(OutboxOperationError):
    """The caller no longer owns the processing lease."""


class RetryableFailure(RuntimeError):
    """A safe expected adapter failure that may carry only a retry hint."""

    def __init__(self, *, retry_after_seconds: float | None = None) -> None:
        super().__init__("delivery adapter reported a retryable failure")
        self.retry_after_seconds = retry_after_seconds


class DeliveryDisposition(StrEnum):
    DELIVERED = "delivered"
    RETRYABLE = "retryable"
    PERMANENT = "permanent"


@dataclass(frozen=True, slots=True)
class DeliveryRequest:
    """Safe adapter input; claim ownership deliberately stays in the worker."""

    outbox_id: UUID
    incident_id: UUID
    destination_id: UUID
    adapter_kind: str
    notification_type: str
    payload: IncidentCreatedNotificationV1 = field(repr=False)
    attempt_count: int


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    disposition: DeliveryDisposition
    error_code: OutboxErrorCode | None = None
    retry_after_seconds: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, DeliveryDisposition):
            raise ValueError("delivery result contains an unsupported disposition")
        if self.disposition is DeliveryDisposition.DELIVERED:
            if self.error_code is not None or self.retry_after_seconds is not None:
                raise ValueError("successful delivery result contains failure fields")
            return
        if self.disposition is DeliveryDisposition.RETRYABLE:
            if self.error_code is not OutboxErrorCode.RETRYABLE_DELIVERY_ERROR:
                raise ValueError("retryable delivery result has an unsupported error code")
            if self.retry_after_seconds is not None and (
                isinstance(self.retry_after_seconds, bool)
                or not isinstance(self.retry_after_seconds, (int, float))
            ):
                raise ValueError("retryable delivery result has an invalid retry hint")
            return
        if self.error_code is not OutboxErrorCode.PERMANENT_DELIVERY_ERROR:
            raise ValueError("permanent delivery result has an unsupported error code")
        if self.retry_after_seconds is not None:
            raise ValueError("permanent delivery result contains a retry hint")


class DeliveryAdapter(Protocol):
    def deliver(
        self,
        request: DeliveryRequest,
        *,
        timeout_seconds: float,
    ) -> DeliveryResult: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class RandomSource(Protocol):
    def random(self) -> float: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class EqualJitterBackoff:
    """Bounded exponential backoff with injectable randomness."""

    def __init__(
        self,
        *,
        base_seconds: float,
        maximum_seconds: float,
        retry_after_cap_seconds: float,
        random_source: RandomSource | None = None,
    ) -> None:
        if base_seconds <= 0 or maximum_seconds < base_seconds:
            raise ValueError("outbox backoff bounds are invalid")
        if retry_after_cap_seconds < 0:
            raise ValueError("outbox retry-after cap is invalid")
        self._base = base_seconds
        self._maximum = maximum_seconds
        self._retry_after_cap = retry_after_cap_seconds
        self._random = random_source or random.SystemRandom()

    def delay(self, *, attempt_count: int, retry_after_seconds: float | None = None) -> float:
        exponent = max(0, min(attempt_count - 1, 30))
        cap = min(self._maximum, self._base * (2**exponent))
        delay = float(cap / 2 + self._random.random() * cap / 2)
        if retry_after_seconds is None:
            return delay
        if (
            isinstance(retry_after_seconds, bool)
            or not isinstance(retry_after_seconds, (int, float))
            or not math.isfinite(retry_after_seconds)
        ):
            return delay
        bounded = max(0.0, min(float(retry_after_seconds), self._retry_after_cap))
        return max(delay, bounded)


@dataclass(frozen=True, slots=True)
class ClaimedOutboxMessage:
    """Detached claim DTO retained by the worker, never passed whole to an adapter."""

    outbox_id: UUID
    incident_id: UUID
    destination_id: UUID
    adapter_kind: str
    notification_type: str
    payload: IncidentCreatedNotificationV1 = field(repr=False)
    attempt_count: int
    claim_token: UUID = field(repr=False)

    def delivery_request(self) -> DeliveryRequest:
        return DeliveryRequest(
            outbox_id=self.outbox_id,
            incident_id=self.incident_id,
            destination_id=self.destination_id,
            adapter_kind=self.adapter_kind,
            notification_type=self.notification_type,
            payload=self.payload,
            attempt_count=self.attempt_count,
        )


@dataclass(frozen=True, slots=True)
class ClaimResult:
    processed: bool
    message: ClaimedOutboxMessage | None = None


@dataclass(frozen=True, slots=True)
class QueueStatistics:
    pending: int
    processing: int
    delivered: int
    failed: int
    ready: int
    expired: int
    oldest_pending_age_seconds: float | None


@dataclass(frozen=True, slots=True)
class WorkerRunResult:
    processed: int
    delivered: int
    deferred: int
    failed: int
    lease_lost: int


def claim_next_message(
    session: Session,
    *,
    now: datetime,
    lease_seconds: float,
) -> ClaimResult:
    """Claim one due row and return a safe DTO after caller commit closes the Session."""

    row = session.execute(
        select(OutboxMessage, NotificationDestination)
        .join(NotificationDestination, NotificationDestination.id == OutboxMessage.destination_id)
        .where(
            OutboxMessage.status == OutboxStatus.PENDING.value,
            OutboxMessage.next_attempt_at <= now,
            OutboxMessage.attempt_count < OutboxMessage.max_attempts,
        )
        .order_by(OutboxMessage.next_attempt_at, OutboxMessage.created_at, OutboxMessage.id)
        .with_for_update(of=OutboxMessage, skip_locked=True)
        .limit(1)
    ).one_or_none()
    if row is None:
        return ClaimResult(processed=False)

    message, destination = row._tuple()
    token = uuid4()
    message.status = OutboxStatus.PROCESSING.value
    message.attempt_count += 1
    message.next_attempt_at = None
    message.claim_token = token
    message.claimed_at = now
    message.lease_expires_at = now + timedelta(seconds=lease_seconds)
    session.flush()

    if not destination.enabled:
        _fail_claimed_orm(
            session,
            message=message,
            now=now,
            error_code=OutboxErrorCode.DESTINATION_DISABLED,
        )
        return ClaimResult(processed=True)
    try:
        payload = IncidentCreatedNotificationV1.model_validate(message.payload)
    except ValidationError:
        _fail_claimed_orm(
            session,
            message=message,
            now=now,
            error_code=OutboxErrorCode.PAYLOAD_INVALID,
        )
        return ClaimResult(processed=True)

    return ClaimResult(
        processed=True,
        message=ClaimedOutboxMessage(
            outbox_id=message.id,
            incident_id=message.incident_id,
            destination_id=message.destination_id,
            adapter_kind=destination.adapter_kind,
            notification_type=message.notification_type,
            payload=payload,
            attempt_count=message.attempt_count,
            claim_token=token,
        ),
    )


def acknowledge_delivery(
    session: Session,
    *,
    outbox_id: UUID,
    claim_token: UUID,
    now: datetime,
) -> None:
    changed = session.execute(
        update(OutboxMessage)
        .where(
            OutboxMessage.id == outbox_id,
            OutboxMessage.status == OutboxStatus.PROCESSING.value,
            OutboxMessage.claim_token == claim_token,
        )
        .values(
            status=OutboxStatus.DELIVERED.value,
            claim_token=None,
            claimed_at=None,
            lease_expires_at=None,
            next_attempt_at=None,
            delivered_at=now,
            failed_at=None,
            last_error_code=None,
            last_error=None,
            updated_at=now,
        )
        .returning(OutboxMessage.id)
    ).scalar_one_or_none()
    if changed is None:
        raise LeaseLostError("outbox claim is no longer owned")


def reschedule_delivery(
    session: Session,
    *,
    outbox_id: UUID,
    claim_token: UUID,
    now: datetime,
    delay_seconds: float,
    error_code: OutboxErrorCode,
) -> OutboxStatus:
    """Retry or fail an owned claim, depending on its persisted attempt limit."""

    exhausted = OutboxMessage.attempt_count >= OutboxMessage.max_attempts
    new_status = case(
        (exhausted, OutboxStatus.FAILED.value),
        else_=OutboxStatus.PENDING.value,
    )
    changed = session.execute(
        update(OutboxMessage)
        .where(
            OutboxMessage.id == outbox_id,
            OutboxMessage.status == OutboxStatus.PROCESSING.value,
            OutboxMessage.claim_token == claim_token,
        )
        .values(
            status=new_status,
            claim_token=None,
            claimed_at=None,
            lease_expires_at=None,
            next_attempt_at=case(
                (exhausted, None),
                else_=now + timedelta(seconds=delay_seconds),
            ),
            failed_at=case((exhausted, now), else_=None),
            last_error_code=case(
                (exhausted, OutboxErrorCode.ATTEMPTS_EXHAUSTED.value),
                else_=error_code.value,
            ),
            last_error=case(
                (exhausted, _safe_error(OutboxErrorCode.ATTEMPTS_EXHAUSTED)),
                else_=_safe_error(error_code),
            ),
            updated_at=now,
        )
        .returning(OutboxMessage.status)
    ).scalar_one_or_none()
    if changed is None:
        raise LeaseLostError("outbox claim is no longer owned")
    return OutboxStatus(changed)


def fail_delivery_permanently(
    session: Session,
    *,
    outbox_id: UUID,
    claim_token: UUID,
    now: datetime,
    error_code: OutboxErrorCode,
) -> None:
    changed = session.execute(
        update(OutboxMessage)
        .where(
            OutboxMessage.id == outbox_id,
            OutboxMessage.status == OutboxStatus.PROCESSING.value,
            OutboxMessage.claim_token == claim_token,
        )
        .values(
            status=OutboxStatus.FAILED.value,
            claim_token=None,
            claimed_at=None,
            lease_expires_at=None,
            next_attempt_at=None,
            failed_at=now,
            last_error_code=error_code.value,
            last_error=_safe_error(error_code),
            updated_at=now,
        )
        .returning(OutboxMessage.id)
    ).scalar_one_or_none()
    if changed is None:
        raise LeaseLostError("outbox claim is no longer owned")


def recover_expired_claims(session: Session, *, now: datetime) -> tuple[int, int]:
    """Recover all expired leases without resetting lifetime attempt counters."""

    exhausted = OutboxMessage.attempt_count >= OutboxMessage.max_attempts
    recovered_rows = session.execute(
        update(OutboxMessage)
        .where(
            OutboxMessage.status == OutboxStatus.PROCESSING.value,
            OutboxMessage.lease_expires_at <= now,
        )
        .values(
            status=case(
                (exhausted, OutboxStatus.FAILED.value),
                else_=OutboxStatus.PENDING.value,
            ),
            claim_token=None,
            claimed_at=None,
            lease_expires_at=None,
            next_attempt_at=case((exhausted, None), else_=now),
            failed_at=case((exhausted, now), else_=None),
            last_error_code=case(
                (exhausted, OutboxErrorCode.ATTEMPTS_EXHAUSTED.value),
                else_=OutboxErrorCode.LEASE_EXPIRED.value,
            ),
            last_error=case(
                (exhausted, _safe_error(OutboxErrorCode.ATTEMPTS_EXHAUSTED)),
                else_=_safe_error(OutboxErrorCode.LEASE_EXPIRED),
            ),
            updated_at=now,
        )
        .returning(OutboxMessage.status)
    ).scalars()
    statuses = list(recovered_rows)
    return statuses.count(OutboxStatus.PENDING.value), statuses.count(OutboxStatus.FAILED.value)


def queue_statistics(session: Session, *, now: datetime) -> QueueStatistics:
    counts = dict(
        session.execute(select(OutboxMessage.status, func.count()).group_by(OutboxMessage.status))
        .tuples()
        .all()
    )
    ready = session.scalar(
        select(func.count())
        .select_from(OutboxMessage)
        .where(
            OutboxMessage.status == OutboxStatus.PENDING.value,
            OutboxMessage.next_attempt_at <= now,
        )
    )
    expired = session.scalar(
        select(func.count())
        .select_from(OutboxMessage)
        .where(
            OutboxMessage.status == OutboxStatus.PROCESSING.value,
            OutboxMessage.lease_expires_at <= now,
        )
    )
    oldest_pending_at = session.scalar(
        select(func.min(OutboxMessage.created_at)).where(
            OutboxMessage.status == OutboxStatus.PENDING.value
        )
    )
    oldest_pending_age_seconds = (
        None if oldest_pending_at is None else max(0.0, (now - oldest_pending_at).total_seconds())
    )
    return QueueStatistics(
        pending=int(counts.get(OutboxStatus.PENDING.value, 0)),
        processing=int(counts.get(OutboxStatus.PROCESSING.value, 0)),
        delivered=int(counts.get(OutboxStatus.DELIVERED.value, 0)),
        failed=int(counts.get(OutboxStatus.FAILED.value, 0)),
        ready=int(ready or 0),
        expired=int(expired or 0),
        oldest_pending_age_seconds=oldest_pending_age_seconds,
    )


def requeue_failed_message(
    session: Session,
    *,
    outbox_id: UUID,
    confirmation: UUID,
    additional_attempts: int,
    now: datetime,
) -> OutboxMessage:
    """Perform one confirmed, bounded failed→pending transition with audit."""

    if confirmation != outbox_id:
        raise OutboxOperationError("outbox requeue confirmation does not match")
    if type(additional_attempts) is not int or not 1 <= additional_attempts <= 5:
        raise OutboxOperationError("additional attempts must be between 1 and 5")
    message = session.execute(
        select(OutboxMessage).where(OutboxMessage.id == outbox_id).with_for_update()
    ).scalar_one_or_none()
    if message is None or message.status != OutboxStatus.FAILED.value:
        raise OutboxOperationError("outbox message is not available for requeue")
    to_max_attempts = message.max_attempts + additional_attempts
    if to_max_attempts > 20:
        raise OutboxOperationError("outbox maximum attempts would exceed the safe limit")

    from_attempt_count = message.attempt_count
    from_max_attempts = message.max_attempts
    message.status = OutboxStatus.PENDING.value
    message.max_attempts = to_max_attempts
    message.next_attempt_at = now
    message.claim_token = None
    message.claimed_at = None
    message.lease_expires_at = None
    message.delivered_at = None
    message.failed_at = None
    message.last_error_code = None
    message.last_error = None
    message.updated_at = now
    record_local_cli_action(
        session,
        action="outbox.failed_requeued",
        target_type="outbox_message",
        target_id=message.id,
        details={
            "from_attempt_count": from_attempt_count,
            "from_max_attempts": from_max_attempts,
            "to_max_attempts": to_max_attempts,
        },
    )
    session.flush()
    return message


class OutboxWorker:
    """Claim one row at a time and deliver with no open database transaction."""

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        adapters: Mapping[str, DeliveryAdapter],
        clock: Clock | None = None,
        backoff: EqualJitterBackoff,
        lease_seconds: float,
        adapter_timeout_seconds: float,
        poll_seconds: float,
        recovery_interval_seconds: float,
    ) -> None:
        _validate_worker_timings(
            lease_seconds=lease_seconds,
            adapter_timeout_seconds=adapter_timeout_seconds,
            poll_seconds=poll_seconds,
            recovery_interval_seconds=recovery_interval_seconds,
        )
        self._session_factory = session_factory
        self._adapters = dict(adapters)
        self._clock = clock or SystemClock()
        self._backoff = backoff
        self._lease_seconds = lease_seconds
        self._adapter_timeout_seconds = adapter_timeout_seconds
        self._poll_seconds = poll_seconds
        self._recovery_interval_seconds = recovery_interval_seconds
        self._stop = Event()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def request_stop(self) -> None:
        self._stop.set()

    def install_signal_handlers(self) -> None:
        def handle_signal(_signum: int, _frame: FrameType | None) -> None:
            logger.info("outbox_shutdown_requested")
            self.request_stop()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

    def run(self) -> None:
        self.install_signal_handlers()
        self._recover()
        next_recovery_at = self._clock.now() + timedelta(seconds=self._recovery_interval_seconds)
        logger.info("outbox_worker_started")
        try:
            while not self._stop.is_set():
                now = self._clock.now()
                if now >= next_recovery_at:
                    self._recover(now=now)
                    next_recovery_at = now + timedelta(seconds=self._recovery_interval_seconds)
                result = self.run_once(limit=1, recover=False)
                if result.processed == 0:
                    remaining_until_recovery = max(
                        0.0,
                        (next_recovery_at - self._clock.now()).total_seconds(),
                    )
                    wait_seconds = min(self._poll_seconds, remaining_until_recovery)
                    if wait_seconds > 0:
                        self._stop.wait(wait_seconds)
        finally:
            logger.info("outbox_worker_stopped")

    def run_once(self, *, limit: int = 1, recover: bool = True) -> WorkerRunResult:
        if not 1 <= limit <= 100:
            raise OutboxOperationError("outbox run-once limit must be between 1 and 100")
        if recover:
            self._recover()
        delivered = deferred = failed = lease_lost = processed = 0
        while processed < limit and not self._stop.is_set():
            with self._session_factory.begin() as session:
                claim = claim_next_message(
                    session,
                    now=self._clock.now(),
                    lease_seconds=self._lease_seconds,
                )
            if not claim.processed:
                break
            processed += 1
            if claim.message is None:
                failed += 1
                continue
            outcome = self._deliver_claim(claim.message)
            if outcome is OutboxStatus.DELIVERED:
                delivered += 1
            elif outcome is OutboxStatus.PENDING:
                deferred += 1
            elif outcome is OutboxStatus.FAILED:
                failed += 1
            else:
                lease_lost += 1
        return WorkerRunResult(processed, delivered, deferred, failed, lease_lost)

    def _deliver_claim(self, claim: ClaimedOutboxMessage) -> OutboxStatus | None:
        adapter = self._adapters.get(claim.adapter_kind)
        if adapter is None:
            return self._complete_permanent(
                claim,
                OutboxErrorCode.DESTINATION_UNCONFIGURED,
            )
        try:
            result: object = adapter.deliver(
                claim.delivery_request(),
                timeout_seconds=self._adapter_timeout_seconds,
            )
        except RetryableFailure as failure:
            return self._complete_retry(
                claim,
                error_code=OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
                retry_after_seconds=failure.retry_after_seconds,
            )
        except Exception:
            logger.error(
                "outbox_adapter_failed outbox_id=%s destination_id=%s attempt=%d",
                claim.outbox_id,
                claim.destination_id,
                claim.attempt_count,
            )
            return self._complete_retry(
                claim,
                error_code=OutboxErrorCode.ADAPTER_UNEXPECTED_ERROR,
                retry_after_seconds=None,
            )

        try:
            if not isinstance(result, DeliveryResult):
                return self._complete_retry(
                    claim,
                    error_code=OutboxErrorCode.ADAPTER_UNEXPECTED_ERROR,
                    retry_after_seconds=None,
                )
            if result.disposition is DeliveryDisposition.DELIVERED:
                with self._session_factory.begin() as session:
                    acknowledge_delivery(
                        session,
                        outbox_id=claim.outbox_id,
                        claim_token=claim.claim_token,
                        now=self._clock.now(),
                    )
                return OutboxStatus.DELIVERED
            if result.disposition is DeliveryDisposition.PERMANENT:
                return self._complete_permanent(
                    claim,
                    OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
                )
            return self._complete_retry(
                claim,
                error_code=OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
                retry_after_seconds=result.retry_after_seconds,
            )
        except LeaseLostError:
            logger.warning(
                "outbox_lease_lost outbox_id=%s destination_id=%s",
                claim.outbox_id,
                claim.destination_id,
            )
            return None

    def _complete_retry(
        self,
        claim: ClaimedOutboxMessage,
        *,
        error_code: OutboxErrorCode,
        retry_after_seconds: float | None,
    ) -> OutboxStatus | None:
        delay = self._backoff.delay(
            attempt_count=claim.attempt_count,
            retry_after_seconds=retry_after_seconds,
        )
        try:
            with self._session_factory.begin() as session:
                return reschedule_delivery(
                    session,
                    outbox_id=claim.outbox_id,
                    claim_token=claim.claim_token,
                    now=self._clock.now(),
                    delay_seconds=delay,
                    error_code=error_code,
                )
        except LeaseLostError:
            logger.warning(
                "outbox_lease_lost outbox_id=%s destination_id=%s",
                claim.outbox_id,
                claim.destination_id,
            )
            return None

    def _complete_permanent(
        self,
        claim: ClaimedOutboxMessage,
        error_code: OutboxErrorCode,
    ) -> OutboxStatus | None:
        try:
            with self._session_factory.begin() as session:
                fail_delivery_permanently(
                    session,
                    outbox_id=claim.outbox_id,
                    claim_token=claim.claim_token,
                    now=self._clock.now(),
                    error_code=error_code,
                )
            return OutboxStatus.FAILED
        except LeaseLostError:
            logger.warning(
                "outbox_lease_lost outbox_id=%s destination_id=%s",
                claim.outbox_id,
                claim.destination_id,
            )
            return None

    def _recover(self, *, now: datetime | None = None) -> tuple[int, int]:
        with self._session_factory.begin() as session:
            recovered, failed = recover_expired_claims(
                session,
                now=now or self._clock.now(),
            )
        if recovered or failed:
            logger.info("outbox_leases_recovered pending=%d failed=%d", recovered, failed)
        return recovered, failed


def _fail_claimed_orm(
    session: Session,
    *,
    message: OutboxMessage,
    now: datetime,
    error_code: OutboxErrorCode,
) -> None:
    message.status = OutboxStatus.FAILED.value
    message.claim_token = None
    message.claimed_at = None
    message.lease_expires_at = None
    message.next_attempt_at = None
    message.failed_at = now
    message.last_error_code = error_code.value
    message.last_error = _safe_error(error_code)
    message.updated_at = now
    session.flush()


def _safe_error(error_code: OutboxErrorCode) -> str:
    return _ERROR_MESSAGES[error_code]


def _validate_worker_timings(
    *,
    lease_seconds: float,
    adapter_timeout_seconds: float,
    poll_seconds: float,
    recovery_interval_seconds: float,
) -> None:
    values = {
        "lease": lease_seconds,
        "adapter timeout": adapter_timeout_seconds,
        "poll interval": poll_seconds,
        "recovery interval": recovery_interval_seconds,
    }
    for name, value in values.items():
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError(f"outbox {name} must be a finite positive number")
        if value <= 0:
            raise ValueError(f"outbox {name} must be positive")
    if lease_seconds <= adapter_timeout_seconds:
        raise ValueError("outbox lease must exceed adapter timeout")
    if recovery_interval_seconds > lease_seconds:
        raise ValueError("outbox recovery interval must not exceed lease")
