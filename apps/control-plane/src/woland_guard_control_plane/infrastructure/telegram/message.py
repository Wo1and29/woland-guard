"""Minimal plain-text Telegram notification formatting."""

import unicodedata
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from woland_guard_control_plane.application.outbox import IncidentCreatedNotificationV1
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
from woland_guard_control_plane.infrastructure.telegram.callbacks import (
    encode_decide_block,
    encode_incident_action,
    encode_propose_block,
)

TELEGRAM_TEXT_LIMIT = 4096
_NEWLY_CREATED_INCIDENT_VERSION = 1
_ACTION_BUTTONS: tuple[tuple[str, IncidentStatus], ...] = (
    ("Принять в работу", IncidentStatus.INVESTIGATING),
    ("Ложное срабатывание", IncidentStatus.FALSE_POSITIVE),
    ("Закрыть", IncidentStatus.RESOLVED),
)


class TelegramMessageError(ValueError):
    """Safe formatter error without reflecting payload values."""


def build_incident_action_keyboard(
    *,
    incident_id: UUID,
    dashboard_origin: str,
) -> dict[str, Any]:
    """Build the inline keyboard attached to a freshly created incident notice.

    Every status button encodes ``expected_version=1``: this notification is only
    ever sent inside the same ingestion transaction that creates the incident and
    its version-1 baseline history (ADR-0005 §9), so the incident's real version
    at send time is always 1. A stale button (status already changed elsewhere)
    is rejected by ``transition_incident``'s own optimistic-lock check, not by
    anything client-side.

    The "prepare an IP block" button is unconditional: ``IncidentCreatedNotificationV1``
    deliberately excludes correlation data (it is a broadcast payload, not scoped to
    one operator), so this function has no way to know whether the incident actually
    has a correlated source address. Pressing the button on an incident without one
    is rejected safely by the router, not filtered out here (ADR-0015).
    """

    parsed = urlsplit(dashboard_origin)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query:
        raise TelegramMessageError("Telegram dashboard origin is invalid.")
    status_row = [
        {
            "text": label,
            "callback_data": encode_incident_action(
                incident_id=incident_id,
                target_status=status,
                expected_version=_NEWLY_CREATED_INCIDENT_VERSION,
            ),
        }
        for label, status in _ACTION_BUTTONS
    ]
    block_row = [
        {
            "text": "Подготовить блокировку IP",
            "callback_data": encode_propose_block(incident_id=incident_id),
        }
    ]
    dashboard_row = [
        {
            "text": "Открыть панель",
            "url": f"{dashboard_origin}/dashboard/incidents/{incident_id}",
        }
    ]
    return {"inline_keyboard": [status_row, block_row, dashboard_row]}


def build_block_decision_keyboard(plan_id: UUID) -> dict[str, Any]:
    """Build the inline keyboard attached to a block-plan follow-up message."""

    return {
        "inline_keyboard": [
            [
                {
                    "text": "Подтвердить",
                    "callback_data": encode_decide_block(plan_id=plan_id, approve=True),
                },
                {
                    "text": "Отклонить",
                    "callback_data": encode_decide_block(plan_id=plan_id, approve=False),
                },
            ]
        ]
    }


def format_incident_created_message(payload: IncidentCreatedNotificationV1) -> str:
    """Format only the allowlisted immutable incident summary."""

    _require_safe_line(payload.title)
    _require_safe_line(payload.rule_key)
    created_at = payload.created_at.isoformat()
    text = "\n".join(
        (
            "Woland Guard: новый инцидент",
            f"Критичность: {payload.severity.upper()}",
            f"Заголовок: {payload.title}",
            f"Правило: {payload.rule_key} v{payload.rule_version}",
            f"Инцидент: {payload.incident_id}",
            f"Сервер: {payload.server_id}",
            f"Создан: {created_at}",
        )
    )
    if not 1 <= len(text) <= TELEGRAM_TEXT_LIMIT:
        raise TelegramMessageError("Telegram notification text is invalid.")
    return text


def _require_safe_line(value: str) -> None:
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise TelegramMessageError("Telegram notification text is invalid.")
    if "\n" in value or "\r" in value or "\u2028" in value or "\u2029" in value:
        raise TelegramMessageError("Telegram notification text is invalid.")
