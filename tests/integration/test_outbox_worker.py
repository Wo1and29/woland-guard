"""PostgreSQL integration and concurrency tests for the stage 6C outbox worker."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, null, select, update
from sqlalchemy.exc import DBAPIError

from woland_guard_control_plane.application.outbox import build_incident_created_payload
from woland_guard_control_plane.application.outbox_worker import (
    ClaimResult,
    DeliveryAdapter,
    DeliveryDisposition,
    DeliveryRequest,
    DeliveryResult,
    EqualJitterBackoff,
    LeaseLostError,
    OutboxOperationError,
    OutboxWorker,
    RetryableFailure,
    acknowledge_delivery,
    claim_next_message,
    queue_statistics,
    recover_expired_claims,
    requeue_failed_message,
)
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    DetectionRuleVersion,
    Incident,
    NotificationDestination,
    OutboxErrorCode,
    OutboxMessage,
    OutboxStatus,
    Server,
)

pytestmark = pytest.mark.integration


@dataclass(frozen=True, slots=True)
class SeededOutbox:
    outbox_id: UUID
    incident_id: UUID
    destination_id: UUID
    claim_token: UUID | None


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


class FixedRandom:
    def random(self) -> float:
        return 0.5


class ScriptedAdapter:
    def __init__(
        self,
        results: list[DeliveryResult] | None = None,
        *,
        callback: Callable[[DeliveryRequest], None] | None = None,
        failure: BaseException | None = None,
    ) -> None:
        self.results = results or [DeliveryResult(DeliveryDisposition.DELIVERED)]
        self.callback = callback
        self.failure = failure
        self.requests: list[DeliveryRequest] = []

    def deliver(
        self,
        request: DeliveryRequest,
        *,
        timeout_seconds: float,
    ) -> DeliveryResult:
        assert timeout_seconds == 5
        self.requests.append(request)
        if self.callback is not None:
            self.callback(request)
        if self.failure is not None:
            raise self.failure
        return self.results.pop(0)


class SimulatedProcessCrash(BaseException):
    """Bypass normal Exception handling to model process death after side effect."""


def _seed_outbox(
    *,
    now: datetime,
    destination_enabled: bool = True,
    status: OutboxStatus = OutboxStatus.PENDING,
    attempt_count: int = 0,
    max_attempts: int = 5,
    payload: dict[str, object] | None = None,
    idempotency_key: str | None = None,
) -> SeededOutbox:
    unique = uuid4().hex
    claim_token = uuid4() if status is OutboxStatus.PROCESSING else None
    with get_session_factory().begin() as session:
        server = Server(name=f"outbox-{unique}", hostname=f"{unique}.invalid")
        rule = DetectionRuleVersion(
            rule_key=f"outbox_rule_{unique}",
            version=1,
            schema_version=1,
            enabled=True,
            severity="high",
            checksum=unique.ljust(64, "0"),
            definition={},
            is_active=False,
        )
        destination = NotificationDestination(
            adapter_kind="telegram",
            enabled=destination_enabled,
            minimum_severity="low",
            created_at=now,
            updated_at=now,
        )
        session.add_all((server, rule, destination))
        session.flush()
        incident = Incident(
            server_id=server.id,
            rule_version_id=rule.id,
            rule_key=rule.rule_key,
            rule_version=1,
            severity="high",
            status="new",
            title="Synthetic outbox incident",
            explanation="Synthetic explanation",
            recommendation="Synthetic recommendation",
            correlation={},
            correlation_hash="a" * 64,
            rule_snapshot={},
            first_seen_at=now,
            last_seen_at=now,
            event_count=1,
            created_at=now,
            updated_at=now,
        )
        session.add(incident)
        session.flush()
        safe_payload = build_incident_created_payload(incident).model_dump(mode="json")
        message = OutboxMessage(
            notification_type="incident.created",
            incident_id=incident.id,
            destination_id=destination.id,
            payload_schema_version=1,
            payload=payload or safe_payload,
            idempotency_key=(
                idempotency_key
                if idempotency_key is not None
                else f"incident.created:{incident.id}:{destination.id}"
            ),
            status=status.value,
            attempt_count=attempt_count,
            max_attempts=max_attempts,
            next_attempt_at=(
                now if status is OutboxStatus.PENDING else cast(datetime | None, null())
            ),
            claim_token=claim_token,
            claimed_at=now if status is OutboxStatus.PROCESSING else None,
            lease_expires_at=(
                now + timedelta(seconds=10) if status is OutboxStatus.PROCESSING else None
            ),
            delivered_at=now if status is OutboxStatus.DELIVERED else None,
            failed_at=now if status is OutboxStatus.FAILED else None,
            last_error_code=(
                OutboxErrorCode.PERMANENT_DELIVERY_ERROR.value
                if status is OutboxStatus.FAILED
                else None
            ),
            last_error=(
                "Delivery was rejected permanently." if status is OutboxStatus.FAILED else None
            ),
            created_at=now,
            updated_at=now,
        )
        session.add(message)
        session.flush()
        return SeededOutbox(message.id, incident.id, destination.id, claim_token)


def _worker(
    *,
    clock: MutableClock,
    adapter: DeliveryAdapter | None,
    retry_after_cap: float = 30,
) -> OutboxWorker:
    adapters = {"telegram": adapter} if adapter is not None else {}
    return OutboxWorker(
        session_factory=get_session_factory(),
        adapters=adapters,
        clock=clock,
        backoff=EqualJitterBackoff(
            base_seconds=4,
            maximum_seconds=10,
            retry_after_cap_seconds=retry_after_cap,
            random_source=FixedRandom(),
        ),
        lease_seconds=10,
        adapter_timeout_seconds=5,
        poll_seconds=0.01,
        recovery_interval_seconds=5,
    )


def _wait_for_status(outbox_id: UUID, expected: OutboxStatus) -> OutboxMessage:
    deadline = datetime.now(UTC) + timedelta(seconds=10)
    while datetime.now(UTC) < deadline:
        with get_session_factory()() as session:
            message = session.get(OutboxMessage, outbox_id)
            if message is not None and message.status == expected.value:
                session.expunge(message)
                return message
        Event().wait(0.01)
    raise AssertionError(f"outbox row did not reach expected status {expected.value}")


def test_long_running_worker_periodically_recovers_lease_after_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(
        now=now,
        status=OutboxStatus.PROCESSING,
        attempt_count=1,
        max_attempts=1,
    )
    clock = MutableClock(now)
    worker = _worker(clock=clock, adapter=None)
    startup_recovery_finished = Event()
    original_recover = worker._recover

    def observed_recover(*, now: datetime | None = None) -> tuple[int, int]:
        result = original_recover(now=now)
        startup_recovery_finished.set()
        return result

    monkeypatch.setattr(worker, "install_signal_handlers", lambda: None)
    monkeypatch.setattr(worker, "_recover", observed_recover)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(worker.run)
        assert startup_recovery_finished.wait(timeout=10)
        clock.advance(11)
        recovered = _wait_for_status(seeded.outbox_id, OutboxStatus.FAILED)
        worker.request_stop()
        future.result(timeout=10)

    assert recovered.last_error_code == OutboxErrorCode.ATTEMPTS_EXHAUSTED.value


def test_periodic_recovery_is_not_starved_by_continuous_pending_backlog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    expired = _seed_outbox(
        now=now,
        status=OutboxStatus.PROCESSING,
        attempt_count=1,
        max_attempts=1,
    )
    for _ in range(10):
        _seed_outbox(now=now)
    clock = MutableClock(now)
    first_delivery_entered = Event()
    release_first_delivery = Event()

    def block_first_delivery(_request: DeliveryRequest) -> None:
        if not first_delivery_entered.is_set():
            first_delivery_entered.set()
            assert release_first_delivery.wait(timeout=10)

    adapter = ScriptedAdapter(
        [DeliveryResult(DeliveryDisposition.DELIVERED) for _ in range(10)],
        callback=block_first_delivery,
    )
    worker = _worker(clock=clock, adapter=adapter)
    startup_recovery_finished = Event()
    original_recover = worker._recover

    def observed_recover(*, now: datetime | None = None) -> tuple[int, int]:
        result = original_recover(now=now)
        startup_recovery_finished.set()
        return result

    monkeypatch.setattr(worker, "install_signal_handlers", lambda: None)
    monkeypatch.setattr(worker, "_recover", observed_recover)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(worker.run)
        assert startup_recovery_finished.wait(timeout=10)
        assert first_delivery_entered.wait(timeout=10)
        clock.advance(11)
        release_first_delivery.set()
        recovered = _wait_for_status(expired.outbox_id, OutboxStatus.FAILED)
        worker.request_stop()
        future.result(timeout=10)

    assert recovered.last_error_code == OutboxErrorCode.ATTEMPTS_EXHAUSTED.value
    assert len(adapter.requests) >= 1


def test_two_workers_never_receive_the_same_row() -> None:
    now = datetime.now(UTC)
    _seed_outbox(now=now)
    entered = Event()
    release = Event()

    def block_after_claim(_request: DeliveryRequest) -> None:
        entered.set()
        assert release.wait(timeout=10)

    adapter = ScriptedAdapter(callback=block_after_claim)
    first = _worker(clock=MutableClock(now), adapter=adapter)
    second = _worker(clock=MutableClock(now), adapter=adapter)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(first.run_once, limit=1)
        assert entered.wait(timeout=10)
        second_result = second.run_once(limit=1)
        release.set()
        first_result = first_future.result(timeout=10)

    assert first_result.processed == 1
    assert first_result.delivered == 1
    assert second_result.processed == 0
    assert len(adapter.requests) == 1


def test_adapter_runs_after_claim_transaction_is_committed_and_closed() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)

    def take_row_lock(_request: DeliveryRequest) -> None:
        with get_session_factory().begin() as independent_session:
            locked_id = independent_session.scalar(
                select(OutboxMessage.id)
                .where(OutboxMessage.id == seeded.outbox_id)
                .with_for_update(nowait=True)
            )
            assert locked_id == seeded.outbox_id

    adapter = ScriptedAdapter(callback=take_row_lock)
    result = _worker(clock=MutableClock(now), adapter=adapter).run_once()

    assert result.delivered == 1


def test_wrong_claim_token_cannot_acknowledge_processing_row() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    with get_session_factory().begin() as session:
        claim = claim_next_message(session, now=now, lease_seconds=10)
    assert isinstance(claim, ClaimResult)
    assert claim.message is not None

    with pytest.raises(LeaseLostError):
        with get_session_factory().begin() as session:
            acknowledge_delivery(
                session,
                outbox_id=seeded.outbox_id,
                claim_token=uuid4(),
                now=now,
            )

    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.status == OutboxStatus.PROCESSING.value


def test_old_worker_cannot_acknowledge_after_lease_recovery_and_new_claim() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    with get_session_factory().begin() as session:
        first = claim_next_message(session, now=now, lease_seconds=10).message
    assert first is not None
    later = now + timedelta(seconds=11)
    with get_session_factory().begin() as session:
        assert recover_expired_claims(session, now=later) == (1, 0)
    with get_session_factory().begin() as session:
        second = claim_next_message(session, now=later, lease_seconds=10).message
    assert second is not None
    assert second.claim_token != first.claim_token

    with pytest.raises(LeaseLostError):
        with get_session_factory().begin() as session:
            acknowledge_delivery(
                session,
                outbox_id=seeded.outbox_id,
                claim_token=first.claim_token,
                now=later,
            )
    with get_session_factory().begin() as session:
        acknowledge_delivery(
            session,
            outbox_id=seeded.outbox_id,
            claim_token=second.claim_token,
            now=later,
        )


def test_crash_after_external_side_effect_before_acknowledge_allows_repeat() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    effects: list[UUID] = []

    def record_side_effect(request: DeliveryRequest) -> None:
        effects.append(request.outbox_id)

    crashing = ScriptedAdapter(
        callback=record_side_effect,
        failure=SimulatedProcessCrash(),
    )
    clock = MutableClock(now)
    with pytest.raises(SimulatedProcessCrash):
        _worker(clock=clock, adapter=crashing).run_once()

    clock.advance(11)
    delivered = ScriptedAdapter(callback=record_side_effect)
    result = _worker(clock=clock, adapter=delivered).run_once()

    assert result.delivered == 1
    assert effects == [seeded.outbox_id, seeded.outbox_id]


def test_retry_after_is_bounded_and_successful_retry_clears_error() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    adapter = ScriptedAdapter(
        [
            DeliveryResult(
                DeliveryDisposition.RETRYABLE,
                OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
                retry_after_seconds=100_000,
            ),
            DeliveryResult(DeliveryDisposition.DELIVERED),
        ]
    )
    clock = MutableClock(now)
    worker = _worker(clock=clock, adapter=adapter, retry_after_cap=30)

    first = worker.run_once()
    assert first.deferred == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.next_attempt_at == now + timedelta(seconds=30)
        assert message.last_error_code == OutboxErrorCode.RETRYABLE_DELIVERY_ERROR.value

    clock.advance(30)
    second = worker.run_once()
    assert second.delivered == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.status == OutboxStatus.DELIVERED.value
        assert message.last_error_code is None
        assert message.last_error is None


def test_expected_retryable_failure_uses_retryable_error_code() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    adapter = ScriptedAdapter(failure=RetryableFailure(retry_after_seconds=8))

    result = _worker(clock=MutableClock(now), adapter=adapter).run_once()

    assert result.deferred == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.last_error_code == OutboxErrorCode.RETRYABLE_DELIVERY_ERROR.value
        assert message.next_attempt_at == now + timedelta(seconds=8)


def test_unexpected_adapter_exception_uses_distinct_safe_error_code() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    adapter = ScriptedAdapter(failure=RuntimeError("synthetic-raw-adapter-detail"))

    result = _worker(clock=MutableClock(now), adapter=adapter).run_once()

    assert result.deferred == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.last_error_code == OutboxErrorCode.ADAPTER_UNEXPECTED_ERROR.value
        assert message.last_error == "Delivery adapter failed unexpectedly."


def test_permanent_failure_is_not_retried() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    adapter = ScriptedAdapter(
        [
            DeliveryResult(
                DeliveryDisposition.PERMANENT,
                OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
            )
        ]
    )
    worker = _worker(clock=MutableClock(now), adapter=adapter)

    assert worker.run_once().failed == 1
    assert worker.run_once().processed == 0
    assert len(adapter.requests) == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.status == OutboxStatus.FAILED.value


def test_retry_at_max_attempts_becomes_failed() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now, max_attempts=1)
    adapter = ScriptedAdapter(
        [
            DeliveryResult(
                DeliveryDisposition.RETRYABLE,
                OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            )
        ]
    )

    assert _worker(clock=MutableClock(now), adapter=adapter).run_once().failed == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.attempt_count == 1
        assert message.last_error_code == OutboxErrorCode.ATTEMPTS_EXHAUSTED.value


@pytest.mark.parametrize(
    "failure",
    [RetryableFailure(), RuntimeError("synthetic-unexpected-adapter-failure")],
)
def test_adapter_exception_at_max_attempts_becomes_exhausted(
    failure: BaseException,
) -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now, max_attempts=1)
    adapter = ScriptedAdapter(failure=failure)

    assert _worker(clock=MutableClock(now), adapter=adapter).run_once().failed == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.last_error_code == OutboxErrorCode.ATTEMPTS_EXHAUSTED.value
        assert message.last_error == "Delivery attempt limit was exhausted."


@pytest.mark.parametrize(
    ("enabled", "adapter_configured", "expected_code"),
    [
        (False, True, OutboxErrorCode.DESTINATION_DISABLED),
        (True, False, OutboxErrorCode.DESTINATION_UNCONFIGURED),
    ],
)
def test_disabled_or_unconfigured_destination_fails_without_external_call(
    enabled: bool,
    adapter_configured: bool,
    expected_code: OutboxErrorCode,
) -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now, destination_enabled=enabled)
    adapter = ScriptedAdapter()
    result = _worker(
        clock=MutableClock(now),
        adapter=adapter if adapter_configured else None,
    ).run_once()

    assert result.failed == 1
    assert adapter.requests == []
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.last_error_code == expected_code.value


@pytest.mark.parametrize(
    ("field_name", "new_value"),
    [
        ("notification_type", "incident.changed"),
        ("incident_id", UUID("10000000-0000-4000-8000-000000000001")),
        ("destination_id", UUID("20000000-0000-4000-8000-000000000002")),
        ("payload_schema_version", 2),
        ("payload", {"schema_version": 1, "changed": True}),
        ("idempotency_key", "incident.created:changed:changed"),
        ("created_at", datetime(2030, 1, 1, tzinfo=UTC)),
    ],
)
def test_postgresql_rejects_every_immutable_envelope_field(
    field_name: str,
    new_value: object,
) -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)

    with pytest.raises(DBAPIError, match="outbox envelope is immutable"):
        with get_session_factory().begin() as session:
            session.execute(
                update(OutboxMessage)
                .where(OutboxMessage.id == seeded.outbox_id)
                .values({field_name: new_value, "updated_at": now})
            )


def test_postgresql_and_application_reject_invalid_state_transitions() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    with pytest.raises(DBAPIError, match="outbox state transition is not allowed"):
        with get_session_factory().begin() as session:
            session.execute(
                update(OutboxMessage)
                .where(OutboxMessage.id == seeded.outbox_id)
                .values(
                    status=OutboxStatus.DELIVERED.value,
                    next_attempt_at=None,
                    delivered_at=now,
                    updated_at=now,
                )
            )
    with pytest.raises(OutboxOperationError):
        with get_session_factory().begin() as session:
            requeue_failed_message(
                session,
                outbox_id=seeded.outbox_id,
                confirmation=seeded.outbox_id,
                additional_attempts=1,
                now=now,
            )


@pytest.mark.parametrize(
    "idempotency_key",
    [
        f"incident.created:{'-' * 36}:{'-' * 36}",
        "incident.created:11111111222243338444555555555555:"
        "aaaaaaaaBBBB4ccc8dddeeeeeeeeeeee".lower(),
        "incident.created:11111111-2222-4333-8444-555555555555:"
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        "incident.created:1111111-12222-4333-8444-555555555555:"
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "incident.created:11111111-2222-4333-8444-555555555555:"
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeeex",
        "incident.updated:11111111-2222-4333-8444-555555555555:"
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    ],
)
def test_postgresql_rejects_noncanonical_outbox_idempotency_keys(
    idempotency_key: str,
) -> None:
    with pytest.raises(DBAPIError, match="idempotency_key_format"):
        _seed_outbox(now=datetime.now(UTC), idempotency_key=idempotency_key)


def test_manual_requeue_is_bounded_and_atomic_with_audit() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(
        now=now,
        status=OutboxStatus.FAILED,
        attempt_count=5,
        max_attempts=5,
    )

    with get_session_factory().begin() as session:
        message = requeue_failed_message(
            session,
            outbox_id=seeded.outbox_id,
            confirmation=seeded.outbox_id,
            additional_attempts=2,
            now=now + timedelta(seconds=1),
        )
        assert message.max_attempts == 7

    with get_session_factory()() as session:
        persisted_message = session.get(OutboxMessage, seeded.outbox_id)
        audit = session.execute(select(AuditLogEntry)).scalar_one()
        assert persisted_message is not None
        assert persisted_message.status == OutboxStatus.PENDING.value
        assert persisted_message.attempt_count == 5
        assert persisted_message.max_attempts == 7
        assert persisted_message.failed_at is None
        assert persisted_message.last_error is None
        assert audit.action == "outbox.failed_requeued"
        assert audit.actor_type == "local_cli"
        assert audit.target_type == "outbox_message"
        assert audit.details == {
            "from_attempt_count": 5,
            "from_max_attempts": 5,
            "to_max_attempts": 7,
        }


def test_manual_requeue_requires_exact_confirmation_and_leaves_no_audit() -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(
        now=now,
        status=OutboxStatus.FAILED,
        attempt_count=5,
        max_attempts=5,
    )

    with pytest.raises(OutboxOperationError):
        with get_session_factory().begin() as session:
            requeue_failed_message(
                session,
                outbox_id=seeded.outbox_id,
                confirmation=uuid4(),
                additional_attempts=1,
                now=now,
            )

    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.status == OutboxStatus.FAILED.value
        assert session.scalar(select(func.count()).select_from(AuditLogEntry)) == 0


def test_adapter_exception_secret_is_not_persisted_or_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "synthetic-secret-canary-never-store"
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    adapter = ScriptedAdapter(failure=RuntimeError(canary))

    with caplog.at_level("ERROR"):
        result = _worker(clock=MutableClock(now), adapter=adapter).run_once()

    assert result.deferred == 1
    assert canary not in caplog.text
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert canary not in str(message.last_error)
        assert canary not in str(message.last_error_code)
        assert canary not in str(message.payload)
        assert message.last_error_code == OutboxErrorCode.ADAPTER_UNEXPECTED_ERROR.value


def test_queue_statistics_reports_oldest_pending_age_without_sensitive_fields() -> None:
    now = datetime.now(UTC)
    with get_session_factory()() as session:
        empty = queue_statistics(session, now=now)
    assert empty.oldest_pending_age_seconds is None

    _seed_outbox(now=now + timedelta(seconds=10))
    with get_session_factory()() as session:
        future_created = queue_statistics(session, now=now)
    assert future_created.oldest_pending_age_seconds == 0

    _seed_outbox(now=now - timedelta(seconds=40))
    _seed_outbox(now=now - timedelta(seconds=10))
    with get_session_factory()() as session:
        populated = queue_statistics(session, now=now)

    assert populated.oldest_pending_age_seconds == 40
    assert populated.oldest_pending_age_seconds >= 0
    assert not hasattr(populated, "payload")
    assert not hasattr(populated, "last_error")
    assert not hasattr(populated, "destination")


def test_cooperative_stop_finishes_current_attempt_without_claiming_another() -> None:
    now = datetime.now(UTC)
    _seed_outbox(now=now)
    _seed_outbox(now=now)
    entered = Event()
    release = Event()

    def block(_request: DeliveryRequest) -> None:
        entered.set()
        assert release.wait(timeout=10)

    adapter = ScriptedAdapter(callback=block)
    worker = _worker(clock=MutableClock(now), adapter=adapter)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(worker.run_once, limit=2)
        assert entered.wait(timeout=10)
        worker.request_stop()
        release.set()
        result = future.result(timeout=10)

    assert result.processed == 1
    assert result.delivered == 1
    with get_session_factory()() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(OutboxMessage)
                .where(OutboxMessage.status == OutboxStatus.PENDING.value)
            )
            == 1
        )
