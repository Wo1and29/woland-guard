"""Bilingual catalog for every operator-facing Telegram string.

Kept separate from the Dashboard catalog on purpose: the two surfaces share no
strings, only the `Language` primitive. Values that are wire identifiers -- rule
keys, severities, UUIDs, the raw `nft` argv -- are never translated.

Callback-answer strings must stay under `CALLBACK_ANSWER_MAX_CHARS` in both
languages; `tests/unit/telegram_bot` asserts this for the whole catalog.
"""

from __future__ import annotations

from typing import Final

from woland_guard_control_plane.language import DEFAULT_LANGUAGE, Language, normalize_language

_STRINGS: Final[dict[str, dict[Language, str]]] = {
    # status labels
    "status.new": {"ru": "новый", "en": "new"},
    "status.investigating": {"ru": "в работе", "en": "investigating"},
    "status.resolved": {"ru": "закрыт", "en": "resolved"},
    "status.false_positive": {"ru": "ложное срабатывание", "en": "false positive"},
    # help and access
    "help": {
        "ru": (
            "Woland Guard\n"
            "\n"
            "/status - сводка по серверам и инцидентам\n"
            "/servers - список контролируемых серверов\n"
            "/incidents - последние инциденты\n"
            "/critical - активные критические инциденты\n"
            "/lang ru|en - язык ответов бота\n"
            "/help - эта справка\n"
            "\n"
            "Бот доступен только связанным операторам и отвечает только в личном чате."
        ),
        "en": (
            "Woland Guard\n"
            "\n"
            "/status - server and incident summary\n"
            "/servers - monitored servers\n"
            "/incidents - recent incidents\n"
            "/critical - active critical incidents\n"
            "/lang ru|en - language of the bot's replies\n"
            "/help - this help\n"
            "\n"
            "The bot answers linked operators only, and only in a private chat."
        ),
    },
    "unlinked": {
        "ru": (
            "Этот аккаунт не связан с оператором Woland Guard.\n"
            "Ваш Telegram ID: {telegram_user_id}\n"
            "Передайте его администратору для связывания через локальный CLI."
        ),
        "en": (
            "This account is not linked to a Woland Guard operator.\n"
            "Your Telegram ID: {telegram_user_id}\n"
            "Send it to an administrator to be linked through the local CLI."
        ),
    },
    "forbidden": {
        "ru": "Недостаточно прав для этой команды.",
        "en": "Insufficient permissions for this command.",
    },
    "unknown_command": {
        "ru": "Неизвестная команда. Отправьте /help.",
        "en": "Unknown command. Send /help.",
    },
    "unavailable": {
        "ru": "Данные временно недоступны. Повторите позже.",
        "en": "Data is temporarily unavailable. Try again later.",
    },
    # language switch
    "language.usage": {
        "ru": "Использование: /lang ru или /lang en",
        "en": "Usage: /lang ru or /lang en",
    },
    "language.changed": {
        "ru": "Язык ответов бота: русский.",
        "en": "The bot will reply in English.",
    },
    # callback answers
    "callback.unlinked": {
        "ru": "Аккаунт не связан с оператором. Обратитесь к администратору.",
        "en": "This account is not linked to an operator. Contact an administrator.",
    },
    "callback.forbidden": {
        "ru": "Недостаточно прав для этого действия.",
        "en": "Insufficient permissions for this action.",
    },
    "callback.invalid": {"ru": "Некорректный запрос.", "en": "Invalid request."},
    "callback.rate_limited": {
        "ru": "Слишком много запросов. Повторите позже.",
        "en": "Too many requests. Try again later.",
    },
    # terminal-status reason dialogue
    "reason.invalid": {
        "ru": (
            "Причина некорректна (1–1000 символов, без управляющих символов). "
            "Действие отменено — нажмите кнопку ещё раз."
        ),
        "en": (
            "The reason is invalid (1-1000 characters, no control characters). "
            "The action was cancelled - press the button again."
        ),
    },
    "reason.expired": {
        "ru": "Время ожидания причины истекло. Нажмите кнопку в уведомлении ещё раз.",
        "en": "The reason prompt expired. Press the button in the notification again.",
    },
    "reason.prompt": {
        "ru": (
            "Действие «{label}» требует причины.\n"
            "Отправьте её одним сообщением (1–1000 символов).\n"
            "Любая команда, например /help, отменяет действие."
        ),
        "en": (
            'The "{label}" action requires a reason.\n'
            "Send it as a single message (1-1000 characters).\n"
            "Any command, for example /help, cancels the action."
        ),
    },
    # incident transitions
    "incident.not_found": {"ru": "Инцидент не найден.", "en": "Incident not found."},
    "incident.stale_version": {
        "ru": "Инцидент уже был изменён. Откройте панель, чтобы увидеть текущий статус.",
        "en": "The incident already changed. Open the Dashboard to see its current status.",
    },
    "incident.transition_not_allowed": {
        "ru": "Переход недоступен из текущего статуса инцидента.",
        "en": "That transition is not allowed from the incident's current status.",
    },
    "incident.already_applied": {
        "ru": "Уже выполнено ранее: статус «{label}».",
        "en": 'Already applied earlier: status "{label}".',
    },
    "incident.status_changed": {
        "ru": "Статус изменён: «{label}».",
        "en": 'Status changed to "{label}".',
    },
    "incident.in_progress": {
        "ru": "Действие уже выполняется. Повторите позже.",
        "en": "The action is already running. Try again later.",
    },
    "incident.transition_failed": {
        "ru": "Не удалось изменить статус. Повторите позже.",
        "en": "Could not change the status. Try again later.",
    },
    # IP block plans
    "ip_block.disabled": {
        "ru": "Функция блокировки IP отключена на этом сервере.",
        "en": "IP blocking is disabled on this deployment.",
    },
    "ip_block.no_source_address": {
        "ru": "У инцидента нет адреса источника для блокировки.",
        "en": "This incident has no source address to block.",
    },
    "ip_block.proposed": {
        "ru": "План подготовлен, детали отправлены отдельным сообщением.",
        "en": "The plan is ready; details were sent in a separate message.",
    },
    "ip_block.reused": {
        "ru": "План уже подготовлен ранее, детали отправлены отдельным сообщением.",
        "en": "A plan already existed; details were sent in a separate message.",
    },
    "ip_block.plan_not_found": {"ru": "План не найден.", "en": "Plan not found."},
    "ip_block.already_decided": {
        "ru": "План уже был обработан ранее.",
        "en": "This plan was already decided.",
    },
    "ip_block.expired": {
        "ru": "Срок действия плана истёк. Подготовьте блокировку заново.",
        "en": "The plan expired. Prepare the block again.",
    },
    "ip_block.same_operator": {
        "ru": "Подтвердить план может только другой оператор.",
        "en": "Only a different operator can approve this plan.",
    },
    "ip_block.now_blocked": {
        "ru": (
            "Адрес больше нельзя блокировать (allowlist или защищённый диапазон изменились). "
            "План автоматически отклонён."
        ),
        "en": (
            "This address can no longer be blocked (the allowlist or a protected range "
            "changed). The plan was rejected automatically."
        ),
    },
    "ip_block.approved": {
        "ru": (
            "План подтверждён. Блокировка НЕ выполнена: control plane не исполняет команды, "
            "это только подтверждение плана."
        ),
        "en": (
            "Plan approved. The block was NOT applied: the control plane never executes "
            "commands, this only records the approval."
        ),
    },
    "ip_block.rejected": {"ru": "План отклонён.", "en": "Plan rejected."},
    "ip_block.reject.not_an_address": {
        "ru": "Адрес источника инцидента некорректен.",
        "en": "The incident's source address is invalid.",
    },
    "ip_block.reject.never_block": {
        "ru": "Этот адрес защищён от блокировки.",
        "en": "This address is protected from blocking.",
    },
    "ip_block.reject.allowlisted": {
        "ru": "Этот адрес в allowlist и не может быть заблокирован.",
        "en": "This address is allowlisted and cannot be blocked.",
    },
    # block proposal follow-up
    "proposal.heading": {
        "ru": "Предложена блокировка IP (ничего не выполнено)",
        "en": "IP block proposed (nothing was executed)",
    },
    "proposal.address": {"ru": "Адрес:", "en": "Address:"},
    "proposal.incident": {"ru": "Инцидент:", "en": "Incident:"},
    "proposal.command": {"ru": "Команда:", "en": "Command:"},
    "proposal.expires": {"ru": "Истекает:", "en": "Expires:"},
    "proposal.approval_note": {
        "ru": "Подтвердить может оператор с ролью admin. Отклонить может любой аналитик.",
        "en": "An admin can approve it. Any analyst can reject it.",
    },
    # /status
    "overview.heading": {"ru": "Состояние Woland Guard", "en": "Woland Guard status"},
    "overview.servers": {"ru": "Серверы:", "en": "Servers:"},
    "overview.servers_detail": {
        "ru": "активных {active}, неактивных {inactive}",
        "en": "{active} active, {inactive} inactive",
    },
    "overview.open_incidents": {"ru": "Открытых инцидентов:", "en": "Open incidents:"},
    "overview.critical": {"ru": "Из них критических:", "en": "Critical among them:"},
    "overview.queue": {"ru": "Очередь уведомлений:", "en": "Notification queue:"},
    "overview.pending": {"ru": "ожидают:", "en": "pending:"},
    "overview.processing": {"ru": "в работе:", "en": "processing:"},
    "overview.delivered": {"ru": "доставлены:", "en": "delivered:"},
    "overview.failed": {"ru": "неуспешные:", "en": "failed:"},
    # /servers
    "servers.empty": {"ru": "Серверы не зарегистрированы.", "en": "No servers are registered."},
    "servers.heading": {"ru": "Серверы:", "en": "Servers:"},
    "servers.active": {"ru": "активен", "en": "active"},
    "servers.inactive": {"ru": "неактивен", "en": "inactive"},
    "servers.host": {"ru": "хост:", "en": "host:"},
    "servers.open_incidents": {"ru": "открытых инцидентов:", "en": "open incidents:"},
    "servers.last_event": {"ru": "последнее событие:", "en": "last event:"},
    # /incidents and /critical
    "incidents.heading": {"ru": "Инциденты:", "en": "Incidents:"},
    "incidents.empty": {"ru": "Инцидентов пока нет.", "en": "No incidents yet."},
    "incidents.empty_critical": {
        "ru": "Активных критических инцидентов нет.",
        "en": "No active critical incidents.",
    },
    "incidents.server": {"ru": "сервер:", "en": "server:"},
    "incidents.status": {"ru": "статус:", "en": "status:"},
    "incidents.events": {"ru": "событий:", "en": "events:"},
    "incidents.last": {"ru": "последнее:", "en": "last:"},
    "incidents.id": {"ru": "id:", "en": "id:"},
    "list.truncated": {
        "ru": "Показаны не все записи. Полный список — в Dashboard.",
        "en": "Not all records are shown. The full list is in the Dashboard.",
    },
    # outbound incident notification and its keyboard
    "notification.heading": {
        "ru": "Woland Guard: новый инцидент",
        "en": "Woland Guard: new incident",
    },
    "notification.severity": {"ru": "Критичность:", "en": "Severity:"},
    "notification.title": {"ru": "Заголовок:", "en": "Title:"},
    "notification.rule": {"ru": "Правило:", "en": "Rule:"},
    "notification.incident": {"ru": "Инцидент:", "en": "Incident:"},
    "notification.server": {"ru": "Сервер:", "en": "Server:"},
    "notification.created": {"ru": "Создан:", "en": "Created:"},
    "button.investigating": {"ru": "Принять в работу", "en": "Take it"},
    "button.false_positive": {"ru": "Ложное срабатывание", "en": "False positive"},
    "button.resolved": {"ru": "Закрыть", "en": "Resolve"},
    "button.propose_block": {"ru": "Подготовить блокировку IP", "en": "Prepare IP block"},
    "button.open_dashboard": {"ru": "Открыть панель", "en": "Open Dashboard"},
    "button.approve": {"ru": "Подтвердить", "en": "Approve"},
    "button.reject": {"ru": "Отклонить", "en": "Reject"},
}


def tg(lang: str, key: str) -> str:
    """Look up one Telegram string; an unknown key renders as itself, never raises."""

    entry = _STRINGS.get(key)
    if entry is None:
        return key
    return entry.get(normalize_language(lang), entry[DEFAULT_LANGUAGE])


def catalog_keys() -> tuple[str, ...]:
    """Expose the key set so tests can assert catalog-wide invariants."""

    return tuple(_STRINGS)
