"""Plain-text allowlisted Telegram message formatting."""

from datetime import UTC, datetime
from uuid import UUID

import pytest

from woland_guard_control_plane.application.outbox import IncidentCreatedNotificationV1
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
from woland_guard_control_plane.infrastructure.telegram.callbacks import parse_incident_action
from woland_guard_control_plane.infrastructure.telegram.message import (
    TelegramMessageError,
    build_incident_action_keyboard,
    format_incident_created_message,
)

INCIDENT_ID = UUID("10000000-0000-4000-8000-000000000001")


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


def test_keyboard_encodes_all_three_status_buttons_at_version_one() -> None:
    keyboard = build_incident_action_keyboard(
        incident_id=INCIDENT_ID,
        dashboard_origin="https://guard.example.invalid",
    )

    status_row, dashboard_row = keyboard["inline_keyboard"]
    decoded_statuses = {
        parse_incident_action(button["callback_data"]).target_status for button in status_row
    }
    assert decoded_statuses == {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    }
    for button in status_row:
        decoded = parse_incident_action(button["callback_data"])
        assert decoded.incident_id == INCIDENT_ID
        assert decoded.expected_version == 1

    assert len(dashboard_row) == 1
    assert (
        dashboard_row[0]["url"]
        == f"https://guard.example.invalid/dashboard/incidents/{INCIDENT_ID}"
    )
    assert "callback_data" not in dashboard_row[0]


@pytest.mark.parametrize(
    "origin",
    [
        "http://guard.example.invalid",  # not HTTPS
        "https://guard.example.invalid/",  # trailing path
        "https://guard.example.invalid/dashboard",  # non-empty path
        "https://guard.example.invalid?x=1",  # query string
        "",
        "not-a-url",
    ],
)
def test_keyboard_rejects_a_malformed_dashboard_origin(origin: str) -> None:
    with pytest.raises(TelegramMessageError):
        build_incident_action_keyboard(incident_id=INCIDENT_ID, dashboard_origin=origin)
