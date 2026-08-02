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
from woland_guard_control_plane.application.incident_workflow import TransitionOutcome
from woland_guard_control_plane.application.ip_block_policy import BlockTargetRejectionReason
from woland_guard_control_plane.application.ip_blocks import DecideIpBlockStatus, IpBlockPlanSummary
from woland_guard_control_plane.application.server_queries import ServerSummary
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus

FIELD_MAX_CHARS: Final = 80
MESSAGE_MAX_CHARS: Final = 3_500
CALLBACK_ANSWER_MAX_CHARS: Final = 200
_PLACEHOLDER: Final = "-"

_STATUS_LABELS: Final[dict[str, str]] = {
    IncidentStatus.NEW.value: "новый",
    IncidentStatus.INVESTIGATING.value: "в работе",
    IncidentStatus.RESOLVED.value: "закрыт",
    IncidentStatus.FALSE_POSITIVE.value: "ложное срабатывание",
}

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

CALLBACK_UNLINKED_TEXT: Final = "Аккаунт не связан с оператором. Обратитесь к администратору."
CALLBACK_FORBIDDEN_TEXT: Final = "Недостаточно прав для этого действия."
CALLBACK_INVALID_TEXT: Final = "Некорректный запрос."
CALLBACK_RATE_LIMITED_TEXT: Final = "Слишком много запросов. Повторите позже."

REASON_INVALID_TEXT: Final = (
    "Причина некорректна (1–1000 символов, без управляющих символов). "
    "Действие отменено — нажмите кнопку ещё раз."
)
REASON_EXPIRED_TEXT: Final = "Время ожидания причины истекло. Нажмите кнопку в уведомлении ещё раз."

INCIDENT_NOT_FOUND_TEXT: Final = "Инцидент не найден."
INCIDENT_STALE_VERSION_TEXT: Final = (
    "Инцидент уже был изменён. Откройте панель, чтобы увидеть текущий статус."
)
INCIDENT_TRANSITION_NOT_ALLOWED_TEXT: Final = "Переход недоступен из текущего статуса инцидента."

IP_BLOCK_DISABLED_TEXT: Final = "Функция блокировки IP отключена на этом сервере."
IP_BLOCK_NO_SOURCE_ADDRESS_TEXT: Final = "У инцидента нет адреса источника для блокировки."
IP_BLOCK_PROPOSED_TEXT: Final = "План подготовлен, детали отправлены отдельным сообщением."
IP_BLOCK_REUSED_TEXT: Final = "План уже подготовлен ранее, детали отправлены отдельным сообщением."
IP_BLOCK_PLAN_NOT_FOUND_TEXT: Final = "План не найден."
IP_BLOCK_ALREADY_DECIDED_TEXT: Final = "План уже был обработан ранее."
IP_BLOCK_EXPIRED_TEXT: Final = "Срок действия плана истёк. Подготовьте блокировку заново."
IP_BLOCK_SAME_OPERATOR_TEXT: Final = "Подтвердить план может только другой оператор."
IP_BLOCK_NOW_BLOCKED_TEXT: Final = (
    "Адрес больше нельзя блокировать (allowlist или защищённый диапазон изменились). "
    "План автоматически отклонён."
)
IP_BLOCK_APPROVED_TEXT: Final = (
    "План подтверждён. Блокировка НЕ выполнена: control plane не исполняет команды, "
    "это только подтверждение плана."
)
IP_BLOCK_REJECTED_TEXT: Final = "План отклонён."

_BLOCK_REJECTION_TEXTS: Final[dict[BlockTargetRejectionReason, str]] = {
    BlockTargetRejectionReason.NOT_AN_ADDRESS: "Адрес источника инцидента некорректен.",
    BlockTargetRejectionReason.NOT_CANONICAL: "Адрес источника инцидента некорректен.",
    BlockTargetRejectionReason.NEVER_BLOCK: "Этот адрес защищён от блокировки.",
    BlockTargetRejectionReason.ALLOWLISTED: "Этот адрес в allowlist и не может быть заблокирован.",
}

_DECIDE_OUTCOME_TEXTS: Final[dict[DecideIpBlockStatus, str]] = {
    DecideIpBlockStatus.APPROVED: IP_BLOCK_APPROVED_TEXT,
    DecideIpBlockStatus.REJECTED: IP_BLOCK_REJECTED_TEXT,
    DecideIpBlockStatus.PLAN_NOT_FOUND: IP_BLOCK_PLAN_NOT_FOUND_TEXT,
    DecideIpBlockStatus.ALREADY_DECIDED: IP_BLOCK_ALREADY_DECIDED_TEXT,
    DecideIpBlockStatus.EXPIRED: IP_BLOCK_EXPIRED_TEXT,
    DecideIpBlockStatus.SAME_OPERATOR: IP_BLOCK_SAME_OPERATOR_TEXT,
    DecideIpBlockStatus.NOW_BLOCKED: IP_BLOCK_NOW_BLOCKED_TEXT,
}


def format_reason_prompt(target_status: IncidentStatus) -> str:
    """Ask for the terminal-status reason as a follow-up private message."""

    label = _STATUS_LABELS[target_status.value]
    return (
        f"Действие «{label}» требует причины.\n"
        "Отправьте её одним сообщением (1–1000 символов).\n"
        "Любая команда, например /help, отменяет действие."
    )


def format_block_rejection(reason: BlockTargetRejectionReason) -> str:
    """Render one closed, fixed reason without ever reflecting the address."""

    return _BLOCK_REJECTION_TEXTS[reason]


def format_block_proposal_message(plan: IpBlockPlanSummary) -> str:
    """Render the follow-up message sent after a plan is created or reused.

    This is the one place the correlated address is disclosed in Telegram --
    only here, only to the operator who pressed the button, only in a private
    chat, and only after ``PROPOSE_IP_BLOCK`` was already checked (ADR-0015).
    """

    command_text = " ".join(plan.command_argv)
    lines = (
        "Предложена блокировка IP (ничего не выполнено)",
        "",
        f"Адрес: {plan.ip_address}",
        f"Инцидент: {plan.incident_id}",
        f"Команда: {command_text}",
        f"Истекает: {format_timestamp(plan.expires_at)}",
        "",
        "Подтвердить может оператор с ролью admin. Отклонить может любой аналитик.",
    )
    return _bounded("\n".join(lines))


def format_block_decision_outcome(status: DecideIpBlockStatus) -> str:
    """Render one closed decision outcome; APPROVED always states nothing ran."""

    return _DECIDE_OUTCOME_TEXTS[status]


def format_transition_outcome(
    outcome: TransitionOutcome,
    *,
    target_status: IncidentStatus,
) -> str:
    """Render one bounded, single-purpose transition result for Telegram."""

    label = _STATUS_LABELS[target_status.value]
    if outcome.http_status == 200:
        if outcome.replayed:
            return f"Уже выполнено ранее: статус «{label}»."
        return f"Статус изменён: «{label}»."
    if outcome.http_status == 404:
        return INCIDENT_NOT_FOUND_TEXT
    if outcome.conflict_type == "stale_version":
        return INCIDENT_STALE_VERSION_TEXT
    if outcome.conflict_type == "transition_not_allowed":
        return INCIDENT_TRANSITION_NOT_ALLOWED_TEXT
    if outcome.conflict_type == "idempotency_key_reused":
        return "Действие уже выполняется. Повторите позже."
    return "Не удалось изменить статус. Повторите позже."


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
