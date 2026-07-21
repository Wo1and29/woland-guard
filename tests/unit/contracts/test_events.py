"""Tests for the normalized event contract version 1."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from woland_guard_contracts import EventBatchV1, EventSource, NormalizedEventV1


def make_event() -> NormalizedEventV1:
    """Build a synthetic event without real infrastructure data."""

    occurred_at = datetime(2026, 1, 1, 12, tzinfo=UTC)
    return NormalizedEventV1(
        occurred_at=occurred_at,
        collected_at=occurred_at + timedelta(seconds=1),
        source=EventSource.JOURNALD,
        event_type="ssh.authentication_failed",
        actor="synthetic-user",
        source_ip=IPv4Address("192.0.2.10"),
        attributes={"attempt": 1, "accepted": False},
    )


def test_event_contract_serializes_versioned_normalized_event() -> None:
    """The contract emits JSON-compatible, explicitly versioned data."""

    event = make_event()

    payload = event.model_dump(mode="json")

    assert payload["schema_version"] == 1
    assert payload["source"] == "journald"
    assert payload["source_ip"] == "192.0.2.10"


def test_event_contract_rejects_naive_timestamps() -> None:
    """Timestamps without a timezone cannot cross the component boundary."""

    naive_timestamp = datetime(2026, 1, 1, 12)

    with pytest.raises(ValidationError):
        NormalizedEventV1(
            occurred_at=naive_timestamp,
            collected_at=naive_timestamp,
            event_type="ssh.authentication_failed",
        )


def test_event_contract_rejects_reverse_timestamp_order() -> None:
    """Collection cannot precede the source occurrence time."""

    occurred_at = datetime(2026, 1, 1, 12, tzinfo=UTC)

    with pytest.raises(ValidationError, match="collected_at"):
        NormalizedEventV1(
            occurred_at=occurred_at,
            collected_at=occurred_at - timedelta(seconds=1),
            event_type="ssh.authentication_failed",
        )


def test_batch_rejects_duplicate_event_ids() -> None:
    """A delivery batch cannot contain the same agent event twice."""

    event = make_event()

    with pytest.raises(ValidationError, match="event_id"):
        EventBatchV1(
            sent_at=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
            events=(event, event),
        )


def test_event_contract_rejects_nul_in_actor() -> None:
    """Actor text containing U+0000 cannot reach PostgreSQL JSONB."""

    occurred_at = datetime(2026, 1, 1, 12, tzinfo=UTC)

    with pytest.raises(ValidationError, match=r"U\+0000"):
        NormalizedEventV1(
            occurred_at=occurred_at,
            collected_at=occurred_at,
            event_type="ssh.authentication_failed",
            actor="synthetic\x00actor",
        )


def test_event_contract_rejects_nul_in_summary() -> None:
    """Summary text containing U+0000 is rejected rather than normalized."""

    occurred_at = datetime(2026, 1, 1, 12, tzinfo=UTC)

    with pytest.raises(ValidationError, match=r"U\+0000"):
        NormalizedEventV1(
            occurred_at=occurred_at,
            collected_at=occurred_at,
            event_type="ssh.authentication_failed",
            summary="synthetic\x00summary",
        )


def test_event_contract_rejects_nul_in_nested_attribute_value() -> None:
    """Recursive lists and dictionaries cannot hide a NUL string value."""

    occurred_at = datetime(2026, 1, 1, 12, tzinfo=UTC)

    with pytest.raises(ValidationError, match=r"U\+0000"):
        NormalizedEventV1(
            occurred_at=occurred_at,
            collected_at=occurred_at,
            event_type="ssh.authentication_failed",
            attributes={"outer": [{"inner": "synthetic\x00value"}]},
        )


def test_event_contract_rejects_nul_in_nested_attribute_key() -> None:
    """Recursive dictionary keys containing U+0000 are rejected."""

    occurred_at = datetime(2026, 1, 1, 12, tzinfo=UTC)

    with pytest.raises(ValidationError, match=r"U\+0000"):
        NormalizedEventV1(
            occurred_at=occurred_at,
            collected_at=occurred_at,
            event_type="ssh.authentication_failed",
            attributes={"outer": {"inner\x00key": "synthetic"}},
        )
