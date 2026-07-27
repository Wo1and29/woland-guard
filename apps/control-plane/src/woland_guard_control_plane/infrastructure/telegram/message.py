"""Minimal plain-text Telegram notification formatting."""

import unicodedata

from woland_guard_control_plane.application.outbox import IncidentCreatedNotificationV1

TELEGRAM_TEXT_LIMIT = 4096


class TelegramMessageError(ValueError):
    """Safe formatter error without reflecting payload values."""


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
