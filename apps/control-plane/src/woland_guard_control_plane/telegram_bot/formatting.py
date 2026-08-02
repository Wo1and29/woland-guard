"""Plain-text rendering of allowlisted fields for inbound Telegram replies.

Every reply is assembled from fixed strings and explicit database columns. Operator
input is never echoed back, and stored values are bounded and stripped of control
characters before they reach the outgoing message.
"""

from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Final

from woland_guard_control_plane.application.dashboard_overview import DashboardOverview
from woland_guard_control_plane.application.incident_queries import DashboardIncidentSummary
from woland_guard_control_plane.application.server_queries import ServerSummary

FIELD_MAX_CHARS: Final = 80
MESSAGE_MAX_CHARS: Final = 3_500
_PLACEHOLDER: Final = "-"

HELP_TEXT: Final = (
    "Woland Guard\n"
    "\n"
    "/status - сводка по серверам и инцидентам\n"
    "/servers - список контролируемых серверов\n"
    "/incidents - последние инциденты\n"
    "/critical - активные критические инциденты\n"
    "/help - эта справка\n"
    "\n"
    "Бот доступен только связанным операторам и отвечает только в личном чате."
)

UNLINKED_TEMPLATE: Final = (
    "Этот аккаунт не связан с оператором Woland Guard.\n"
    "Ваш Telegram ID: {telegram_user_id}\n"
    "Передайте его администратору для связывания через локальный CLI."
)

FORBIDDEN_TEXT: Final = "Недостаточно прав для этой команды."
UNKNOWN_COMMAND_TEXT: Final = "Неизвестная команда. Отправьте /help."
UNAVAILABLE_TEXT: Final = "Данные временно недоступны. Повторите позже."


def safe_field(value: object, *, limit: int = FIELD_MAX_CHARS) -> str:
    """Return one bounded single-line representation without control characters."""

    if value is None:
        return _PLACEHOLDER
    text = str(value)
    cleaned = "".join(
        character
        for character in text
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
    ).strip()
    if not cleaned:
        return _PLACEHOLDER
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def format_timestamp(value: datetime | None) -> str:
    """Render one UTC timestamp at minute resolution."""

    if value is None:
        return _PLACEHOLDER
    return value.strftime("%Y-%m-%d %H:%M UTC")


def format_overview(overview: DashboardOverview) -> str:
    """Render the aggregate counters shown by /status."""

    lines = [
        "Состояние Woland Guard",
        "",
        f"Серверы: {overview.servers.total}"
        f" (активных {overview.servers.active}, неактивных {overview.servers.inactive})",
        f"Открытых инцидентов: {overview.incidents.active}",
        f"Из них критических: {overview.incidents.critical_active}",
        "",
        "Очередь уведомлений:",
        f"  ожидают: {overview.notifications.pending}",
        f"  в работе: {overview.notifications.processing}",
        f"  доставлены: {overview.notifications.delivered}",
        f"  неуспешные: {overview.notifications.failed}",
    ]
    return _bounded("\n".join(lines))


def format_servers(servers: tuple[ServerSummary, ...], *, truncated: bool) -> str:
    """Render one bounded server list."""

    if not servers:
        return "Серверы не зарегистрированы."
    lines = ["Серверы:", ""]
    for server in servers:
        state = "активен" if server.is_active else "неактивен"
        lines.append(f"• {safe_field(server.name)} ({state})")
        lines.append(f"  хост: {safe_field(server.hostname)}")
        lines.append(f"  открытых инцидентов: {server.active_incident_count}")
        lines.append(f"  последнее событие: {format_timestamp(server.last_event_at)}")
        lines.append("")
    if truncated:
        lines.append("Показаны не все записи. Полный список — в Dashboard.")
    return _bounded("\n".join(lines).strip())


def format_incidents(
    incidents: tuple[DashboardIncidentSummary, ...],
    *,
    truncated: bool,
    empty_text: str,
) -> str:
    """Render one bounded incident list."""

    if not incidents:
        return empty_text
    lines = ["Инциденты:", ""]
    for incident in incidents:
        lines.append(f"• [{safe_field(incident.severity, limit=16)}] {safe_field(incident.title)}")
        lines.append(f"  сервер: {safe_field(incident.server_name)}")
        lines.append(f"  статус: {safe_field(incident.status, limit=32)}")
        lines.append(f"  событий: {incident.event_count}")
        lines.append(f"  последнее: {format_timestamp(incident.last_seen_at)}")
        lines.append(f"  id: {incident.id}")
        lines.append("")
    if truncated:
        lines.append("Показаны не все записи. Полный список — в Dashboard.")
    return _bounded("\n".join(lines).strip())


def _bounded(text: str) -> str:
    if len(text) <= MESSAGE_MAX_CHARS:
        return text
    return text[: MESSAGE_MAX_CHARS - 1] + "…"
