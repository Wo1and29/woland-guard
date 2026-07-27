"""Plain-text allowlisted Telegram message formatting."""

from datetime import UTC, datetime
from uuid import UUID

import pytest

from woland_guard_control_plane.application.outbox import IncidentCreatedNotificationV1
from woland_guard_control_plane.infrastructure.telegram.message import (
    TelegramMessageError,
    format_incident_created_message,
)


def _payload(*, title: str = "Synthetic incident") -> IncidentCreatedNotificationV1:
    return IncidentCreatedNotificationV1(
        incident_id=UUID("10000000-0000-4000-8000-000000000001"),
        server_id=UUID("20000000-0000-4000-8000-000000000002"),
        rule_key="synthetic_rule",
        rule_version=2,
        severity="high",
        title=title,
        created_at=datetime(2026, 7, 27, tzinfo=UTC),
    )


def test_formatter_contains_only_safe_incident_summary() -> None:
    text = format_incident_created_message(_payload())
    assert "Synthetic incident" in text
    assert "synthetic_rule" in text
    assert "parse_mode" not in text
    for forbidden in ("actor", "source_ip", "attributes", "correlation", "evidence"):
        assert forbidden not in text


def test_formatter_rejects_control_characters() -> None:
    with pytest.raises(TelegramMessageError):
        format_incident_created_message(_payload(title="unsafe\nline"))
