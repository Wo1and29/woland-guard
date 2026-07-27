"""Unit tests for deterministic retry policy and safe delivery boundaries."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy.orm import Session, sessionmaker

from woland_guard_control_plane.application.outbox import IncidentCreatedNotificationV1
from woland_guard_control_plane.application.outbox_worker import (
    ClaimedOutboxMessage,
    DeliveryDisposition,
    DeliveryResult,
    EqualJitterBackoff,
    OutboxWorker,
)
from woland_guard_control_plane.infrastructure.database.models import OutboxErrorCode


class FixedRandom:
    def __init__(self, value: float) -> None:
        self._value = value

    def random(self) -> float:
        return self._value


def test_equal_jitter_is_deterministic_bounded_and_exponential() -> None:
    backoff = EqualJitterBackoff(
        base_seconds=4,
        maximum_seconds=10,
        retry_after_cap_seconds=30,
        random_source=FixedRandom(0.5),
    )

    assert backoff.delay(attempt_count=1) == 3
    assert backoff.delay(attempt_count=2) == 6
    assert backoff.delay(attempt_count=30) == 7.5


@pytest.mark.parametrize(
    ("retry_after", "expected"),
    [(100_000.0, 30.0), (-10.0, 3.0), (float("inf"), 3.0), (True, 3.0)],
)
def test_retry_after_is_safely_bounded(
    retry_after: float,
    expected: float,
) -> None:
    backoff = EqualJitterBackoff(
        base_seconds=4,
        maximum_seconds=10,
        retry_after_cap_seconds=30,
        random_source=FixedRandom(0.5),
    )
    assert backoff.delay(attempt_count=1, retry_after_seconds=retry_after) == expected


def test_delivery_result_accepts_only_exact_valid_shapes() -> None:
    assert DeliveryResult(DeliveryDisposition.DELIVERED).error_code is None
    assert (
        DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            retry_after_seconds=5,
        ).retry_after_seconds
        == 5
    )
    assert (
        DeliveryResult(
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
        ).retry_after_seconds
        is None
    )
    for error_code in (
        OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
        OutboxErrorCode.TELEGRAM_RUNTIME_COPY_INVALID,
        OutboxErrorCode.TELEGRAM_RUNTIME_COPY_UNAVAILABLE,
        OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID,
        OutboxErrorCode.TELEGRAM_STAGING_FILE_MISSING,
    ):
        assert DeliveryResult(DeliveryDisposition.RETRYABLE, error_code).error_code is error_code
    for error_code in (
        OutboxErrorCode.DESTINATION_UNCONFIGURED,
        OutboxErrorCode.PAYLOAD_INVALID,
    ):
        assert DeliveryResult(DeliveryDisposition.PERMANENT, error_code).error_code is error_code


@pytest.mark.parametrize(
    ("disposition", "error_code", "retry_after_seconds"),
    [
        (
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
            None,
        ),
        (
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            None,
        ),
        (
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
            1.0,
        ),
        (
            DeliveryDisposition.DELIVERED,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            None,
        ),
        (DeliveryDisposition.DELIVERED, None, 1.0),
        (DeliveryDisposition.RETRYABLE, None, None),
        (
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            True,
        ),
        (
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            -1.0,
        ),
        (
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            float("nan"),
        ),
        (
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            float("inf"),
        ),
        (
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.ADAPTER_UNEXPECTED_ERROR,
            None,
        ),
        (
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.DESTINATION_DISABLED,
            None,
        ),
    ],
)
def test_delivery_result_rejects_every_invalid_combination(
    disposition: DeliveryDisposition,
    error_code: OutboxErrorCode | None,
    retry_after_seconds: float | None,
) -> None:
    with pytest.raises(ValueError):
        DeliveryResult(disposition, error_code, retry_after_seconds)


def test_delivery_result_closed_matrix_covers_every_persisted_error_code() -> None:
    retryable = {
        OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
        OutboxErrorCode.TELEGRAM_STAGING_FILE_MISSING,
        OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID,
        OutboxErrorCode.TELEGRAM_RUNTIME_COPY_UNAVAILABLE,
        OutboxErrorCode.TELEGRAM_RUNTIME_COPY_INVALID,
        OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
    }
    permanent = {
        OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
        OutboxErrorCode.DESTINATION_UNCONFIGURED,
        OutboxErrorCode.PAYLOAD_INVALID,
    }
    for disposition in DeliveryDisposition:
        for error_code in [None, *OutboxErrorCode]:
            for retry_after in (None, 1.0):
                expected_valid = (
                    (
                        disposition is DeliveryDisposition.DELIVERED
                        and error_code is None
                        and retry_after is None
                    )
                    or (disposition is DeliveryDisposition.RETRYABLE and error_code in retryable)
                    or (
                        disposition is DeliveryDisposition.PERMANENT
                        and error_code in permanent
                        and retry_after is None
                    )
                )
                if expected_valid:
                    DeliveryResult(disposition, error_code, retry_after)
                else:
                    with pytest.raises(ValueError):
                        DeliveryResult(disposition, error_code, retry_after)


def _worker_with_timings(**overrides: float) -> OutboxWorker:
    timings = {
        "lease_seconds": 60.0,
        "adapter_timeout_seconds": 30.0,
        "poll_seconds": 2.0,
        "recovery_interval_seconds": 30.0,
    }
    timings.update(overrides)
    return OutboxWorker(
        session_factory=sessionmaker(class_=Session),
        adapters={},
        backoff=EqualJitterBackoff(
            base_seconds=1,
            maximum_seconds=2,
            retry_after_cap_seconds=10,
            random_source=FixedRandom(0.5),
        ),
        lease_seconds=timings["lease_seconds"],
        adapter_timeout_seconds=timings["adapter_timeout_seconds"],
        poll_seconds=timings["poll_seconds"],
        recovery_interval_seconds=timings["recovery_interval_seconds"],
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"lease_seconds": 0.0},
        {"lease_seconds": -1.0},
        {"adapter_timeout_seconds": 0.0},
        {"adapter_timeout_seconds": -1.0},
        {"lease_seconds": 30.0, "adapter_timeout_seconds": 30.0},
        {"poll_seconds": 0.0},
        {"poll_seconds": -1.0},
        {"recovery_interval_seconds": 0.0},
        {"recovery_interval_seconds": -1.0},
        {"lease_seconds": 60.0, "recovery_interval_seconds": 61.0},
    ],
)
def test_worker_constructor_rejects_invalid_timing_invariants(
    overrides: dict[str, float],
) -> None:
    with pytest.raises(ValueError):
        _worker_with_timings(**overrides)


def test_worker_constructor_accepts_valid_timing_boundary() -> None:
    assert (
        _worker_with_timings(
            lease_seconds=60,
            adapter_timeout_seconds=30,
            poll_seconds=0.1,
            recovery_interval_seconds=60,
        ).stopping
        is False
    )


def test_claim_token_and_payload_are_absent_from_adapter_request_and_reprs() -> None:
    payload = IncidentCreatedNotificationV1(
        incident_id=UUID("11111111-2222-4333-8444-555555555555"),
        server_id=UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        rule_key="synthetic_rule",
        rule_version=1,
        severity="high",
        title="Safe title",
        created_at=datetime(2026, 7, 26, tzinfo=UTC),
    )
    token = UUID("99999999-8888-4777-8666-555555555555")
    claim = ClaimedOutboxMessage(
        outbox_id=UUID("10000000-0000-4000-8000-000000000001"),
        incident_id=payload.incident_id,
        destination_id=UUID("20000000-0000-4000-8000-000000000002"),
        adapter_kind="telegram",
        notification_type="incident.created",
        payload=payload,
        attempt_count=1,
        claim_token=token,
    )
    request = claim.delivery_request()

    assert not hasattr(request, "claim_token")
    assert str(token) not in repr(claim)
    assert "Safe title" not in repr(claim)
    assert "Safe title" not in repr(request)
