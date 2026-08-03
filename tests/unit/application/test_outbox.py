"""Unit tests for safe immutable notification envelopes."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from woland_guard_control_plane.application.outbox import (
    IncidentCreatedNotificationV1,
    build_incident_created_payload,
    outbox_idempotency_key,
)
from woland_guard_control_plane.infrastructure.database.models import Incident

_INCIDENT_ID = UUID("11111111-2222-4333-8444-555555555555")
_SERVER_ID = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
_DESTINATION_ID = UUID("99999999-8888-4777-8666-555555555555")


def _incident() -> Incident:
    return Incident(
        id=_INCIDENT_ID,
        server_id=_SERVER_ID,
        rule_version_id=UUID("12345678-1234-4234-8234-123456789abc"),
        rule_key="synthetic_rule",
        rule_version=2,
        severity="high",
        status="new",
        title="Synthetic incident title",
        explanation="Synthetic explanation",
        recommendation="Synthetic recommendation",
        correlation={"source_ip": "not-copied"},
        correlation_hash="a" * 64,
        rule_snapshot={"event_payload": "not-copied"},
        first_seen_at=datetime(2026, 7, 26, tzinfo=UTC),
        last_seen_at=datetime(2026, 7, 26, tzinfo=UTC),
        event_count=1,
        created_at=datetime(2026, 7, 26, tzinfo=UTC),
    )


def test_incident_payload_contains_only_the_exact_safe_allowlist() -> None:
    payload = build_incident_created_payload(_incident()).model_dump(mode="json")

    assert set(payload) == {
        "schema_version",
        "notification_type",
        "incident_id",
        "server_id",
        "rule_key",
        "rule_version",
        "severity",
        "title",
        "title_en",
        "created_at",
    }
    serialized = str(payload)
    assert "not-copied" not in serialized
    assert "correlation" not in serialized
    assert "event_payload" not in serialized


def test_payload_is_frozen_and_forbids_extra_fields() -> None:
    payload = build_incident_created_payload(_incident())
    with pytest.raises(ValidationError):
        IncidentCreatedNotificationV1.model_validate(
            {**payload.model_dump(), "credential": "synthetic-canary"}
        )
    with pytest.raises(ValidationError):
        payload.title = "changed"


def test_payload_rejects_nul_and_naive_timestamp() -> None:
    valid = build_incident_created_payload(_incident()).model_dump()
    with pytest.raises(ValidationError):
        IncidentCreatedNotificationV1.model_validate({**valid, "title": "bad\x00title"})
    with pytest.raises(ValidationError):
        IncidentCreatedNotificationV1.model_validate({**valid, "created_at": datetime(2026, 7, 26)})


def test_idempotency_key_is_canonical_and_destination_scoped() -> None:
    assert (
        outbox_idempotency_key(
            incident_id=_INCIDENT_ID,
            destination_id=_DESTINATION_ID,
        )
        == f"incident.created:{_INCIDENT_ID}:{_DESTINATION_ID}"
    )
