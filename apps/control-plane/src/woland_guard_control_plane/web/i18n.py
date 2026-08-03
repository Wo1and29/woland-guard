"""Minimal two-language (ru/en) string catalog for Dashboard templates,
`WebError` details, and the `web.presentation` projections.

Only static UI copy and safe presentation strings live here. Data values
(severity, status, rule keys, enum options) are never translated — they are
wire identifiers, not prose.
"""

from __future__ import annotations

from typing import Literal

from fastapi import Request

from woland_guard_control_plane.web.security import LANG_COOKIE_NAME

Language = Literal["ru", "en"]
SUPPORTED_LANGUAGES: tuple[Language, ...] = ("ru", "en")
DEFAULT_LANGUAGE: Language = "ru"

_STRINGS: dict[str, dict[Language, str]] = {
    # common shell
    "common.skip_to_content": {"ru": "К основному содержанию", "en": "Skip to main content"},
    "common.logout": {"ru": "Выйти", "en": "Log out"},
    "common.nav_label": {"ru": "Основная навигация", "en": "Primary navigation"},
    "common.operator_label": {"ru": "Оператор:", "en": "Operator:"},
    "common.role_label": {"ru": "роль:", "en": "role:"},
    "common.apply": {"ru": "Применить", "en": "Apply"},
    "common.next_page": {"ru": "Следующая страница", "en": "Next page"},
    "common.back_to_start": {"ru": "К началу", "en": "Back to start"},
    "common.pagination_label": {"ru": "Пагинация", "en": "Pagination"},
    "common.empty_state": {"ru": "Данных пока нет.", "en": "No data yet."},
    # nav
    "nav.overview": {"ru": "Обзор", "en": "Overview"},
    "nav.servers": {"ru": "Серверы", "en": "Servers"},
    "nav.incidents": {"ru": "Инциденты", "en": "Incidents"},
    "nav.rules": {"ru": "Правила", "en": "Rules"},
    "nav.audit": {"ru": "Аудит", "en": "Audit"},
    # shared table headers
    "th.created": {"ru": "Создан", "en": "Created"},
    "th.severity": {"ru": "Severity", "en": "Severity"},
    "th.status": {"ru": "Статус", "en": "Status"},
    "th.incident": {"ru": "Инцидент", "en": "Incident"},
    "th.server": {"ru": "Сервер", "en": "Server"},
    "th.evidence": {"ru": "Evidence", "en": "Evidence"},
    "th.event_uuid": {"ru": "Event UUID", "en": "Event UUID"},
    "th.type": {"ru": "Тип", "en": "Type"},
    "th.source": {"ru": "Источник", "en": "Source"},
    "th.occurred": {"ru": "Occurred", "en": "Occurred"},
    "th.collected": {"ru": "Collected", "en": "Collected"},
    "th.linked": {"ru": "Linked", "en": "Linked"},
    "th.time": {"ru": "Время", "en": "Time"},
    "th.actor": {"ru": "Actor", "en": "Actor"},
    "th.action": {"ru": "Action", "en": "Action"},
    "th.target": {"ru": "Target", "en": "Target"},
    "th.request_id": {"ru": "Request ID", "en": "Request ID"},
    "th.details": {"ru": "Details", "en": "Details"},
    # shared filter labels
    "filter.severity": {"ru": "Severity", "en": "Severity"},
    "filter.sort": {"ru": "Сортировка", "en": "Sort"},
    "filter.page_size": {"ru": "Размер", "en": "Page size"},
    "filter.rule_key": {"ru": "Rule key", "en": "Rule key"},
    "sort.created_desc": {"ru": "Новые сначала", "en": "Newest first"},
    "sort.created_asc": {"ru": "Старые сначала", "en": "Oldest first"},
    # overview
    "overview.title": {"ru": "Обзор — Woland Guard", "en": "Overview — Woland Guard"},
    "overview.servers_card": {"ru": "Серверы", "en": "Servers"},
    "overview.total": {"ru": "Всего:", "en": "Total:"},
    "overview.active_config": {"ru": "Активны в конфигурации:", "en": "Active in configuration:"},
    "overview.inactive_config": {
        "ru": "Отключены в конфигурации:",
        "en": "Inactive in configuration:",
    },
    "overview.active_incidents_card": {"ru": "Активные инциденты", "en": "Active incidents"},
    "overview.new_and_investigating": {
        "ru": "New и investigating:",
        "en": "New and investigating:",
    },
    "overview.critical_active": {
        "ru": "Критические среди активных:",
        "en": "Critical among active:",
    },
    "overview.notifications_card": {"ru": "Очередь уведомлений", "en": "Notification queue"},
    "overview.pending": {"ru": "Pending:", "en": "Pending:"},
    "overview.processing": {"ru": "Processing:", "en": "Processing:"},
    "overview.ready": {"ru": "Ready:", "en": "Ready:"},
    "overview.expired": {"ru": "Expired claims:", "en": "Expired claims:"},
    "overview.failed": {"ru": "Failed:", "en": "Failed:"},
    "overview.delivered": {"ru": "Delivered, исторически:", "en": "Delivered, historically:"},
    "overview.oldest_pending_age": {
        "ru": "Возраст старейшей pending-записи:",
        "en": "Age of the oldest pending record:",
    },
    "overview.no_pending": {"ru": "нет pending-записей", "en": "no pending records"},
    "overview.seconds_suffix": {"ru": "с", "en": "s"},
    "overview.recent_incidents": {"ru": "Последние инциденты", "en": "Recent incidents"},
    # incidents list
    "incidents.title": {"ru": "Инциденты — Woland Guard", "en": "Incidents — Woland Guard"},
    "incidents.list_label": {"ru": "Список инцидентов", "en": "Incident list"},
    "filter.q_title_rule": {"ru": "Префикс title/rule key", "en": "Title/rule key prefix"},
    "filter.incident_uuid": {"ru": "Точный incident UUID", "en": "Exact incident UUID"},
    "filter.server_uuid": {"ru": "Точный server UUID", "en": "Exact server UUID"},
    "filter.statuses": {"ru": "Статусы", "en": "Statuses"},
    # incident detail
    "incident.title_word": {"ru": "Инцидент", "en": "Incident"},
    "dl.id": {"ru": "ID", "en": "ID"},
    "dl.rule": {"ru": "Rule", "en": "Rule"},
    "dl.first_seen": {"ru": "Первое событие", "en": "First event"},
    "dl.last_seen": {"ru": "Последнее событие", "en": "Last event"},
    "incident.explanation": {"ru": "Объяснение", "en": "Explanation"},
    "incident.recommendation": {"ru": "Рекомендация", "en": "Recommendation"},
    "incident.actions": {"ru": "Действия", "en": "Actions"},
    "form.new_status": {"ru": "Новый статус", "en": "New status"},
    "form.reason": {"ru": "Причина", "en": "Reason"},
    "form.reason_required_note": {
        "ru": "Для resolved и false_positive причина обязательна.",
        "en": "A reason is required for resolved and false_positive.",
    },
    "form.change_status": {"ru": "Изменить статус", "en": "Change status"},
    "incident.terminal_status": {
        "ru": "Статус терминальный; переходы недоступны.",
        "en": "Status is terminal; no transitions are available.",
    },
    "incident.add_comment": {"ru": "Добавить комментарий", "en": "Add a comment"},
    "incident.comment_notice": {
        "ru": (
            "Не вставляйте пароли, токены и другие секреты. "
            "Комментарий сохраняется без возможности редактирования."
        ),
        "en": (
            "Do not paste passwords, tokens, or other secrets. "
            "Comments cannot be edited once saved."
        ),
    },
    "form.comment_label": {"ru": "Комментарий", "en": "Comment"},
    "form.save_comment": {"ru": "Сохранить комментарий", "en": "Save comment"},
    "incident.comments": {"ru": "Комментарии", "en": "Comments"},
    "incident.next_comments_page": {
        "ru": "Следующая страница комментариев",
        "en": "Next page of comments",
    },
    "incident.evidence": {"ru": "Evidence", "en": "Evidence"},
    "incident.evidence_label": {"ru": "Evidence инцидента", "en": "Incident evidence"},
    "incident.next_evidence_page": {
        "ru": "Следующая страница evidence",
        "en": "Next page of evidence",
    },
    "incident.status_history": {"ru": "История статусов", "en": "Status history"},
    "incident.reason_prefix": {"ru": "Причина:", "en": "Reason:"},
    "incident.baseline": {"ru": "baseline", "en": "baseline"},
    "incident.next_history_page": {
        "ru": "Следующая страница истории",
        "en": "Next page of history",
    },
    # servers
    "servers.title": {"ru": "Серверы — Woland Guard", "en": "Servers — Woland Guard"},
    "servers.notice": {
        "ru": "Active/inactive — сохранённая конфигурация, а не проверка доступности.",
        "en": "Active/inactive is the stored configuration, not a reachability check.",
    },
    "filter.name_hostname": {"ru": "Префикс имени или hostname", "en": "Name or hostname prefix"},
    "filter.uuid": {"ru": "Точный UUID", "en": "Exact UUID"},
    "filter.state": {"ru": "Состояние", "en": "State"},
    "state.all": {"ru": "Все", "en": "All"},
    "sort.name_asc": {"ru": "Имя ↑", "en": "Name ↑"},
    "sort.name_desc": {"ru": "Имя ↓", "en": "Name ↓"},
    "server.hostname": {"ru": "Hostname:", "en": "Hostname:"},
    "server.config_state": {"ru": "Состояние конфигурации:", "en": "Configuration state:"},
    "server.last_event": {"ru": "Последнее событие:", "en": "Last event:"},
    "server.active_incidents": {"ru": "Активных инцидентов:", "en": "Active incidents:"},
    "server.detail_title_word": {"ru": "Сервер", "en": "Server"},
    "server.hostname_dl": {"ru": "Hostname", "en": "Hostname"},
    "server.description": {"ru": "Описание", "en": "Description"},
    "server.config_state_dl": {"ru": "Состояние конфигурации", "en": "Configuration state"},
    "server.total_incidents": {"ru": "Инциденты всего", "en": "Total incidents"},
    "server.active_dl": {"ru": "Активные", "en": "Active"},
    "server.critical_active_dl": {"ru": "Критические активные", "en": "Critical active"},
    "server.notice2": {
        "ru": (
            "Состояние конфигурации и время события не являются healthcheck "
            "или online/offline статусом."
        ),
        "en": (
            "Configuration state and event time are not a healthcheck or an online/offline status."
        ),
    },
    # rules
    "rules.title": {"ru": "Правила — Woland Guard", "en": "Rules — Woland Guard"},
    "rules.h1": {"ru": "Активные версии правил", "en": "Active rule versions"},
    "filter.rule_key_prefix": {"ru": "Префикс rule key", "en": "Rule key prefix"},
    "filter.enabled": {"ru": "Enabled", "en": "Enabled"},
    "filter.condition": {"ru": "Condition", "en": "Condition"},
    "sort.rule_key_asc": {"ru": "Rule key ↑", "en": "Rule key ↑"},
    "sort.rule_key_desc": {"ru": "Rule key ↓", "en": "Rule key ↓"},
    "rule.severity_label": {"ru": "Severity:", "en": "Severity:"},
    "rule.condition_label": {"ru": "Condition:", "en": "Condition:"},
    "rule.threshold_label": {"ru": "Threshold:", "en": "Threshold:"},
    "rule.window_label": {"ru": ", window:", "en": ", window:"},
    "rule.seconds_unit": {"ru": " s", "en": " s"},
    "rule.distinct_label": {"ru": "Distinct:", "en": "Distinct:"},
    "rule.min_events_label": {"ru": ", минимум событий:", "en": ", minimum events:"},
    "rule.lookback_label": {"ru": "Lookback:", "en": "Lookback:"},
    "rule.mitre_label": {"ru": "MITRE:", "en": "MITRE:"},
    "rule.not_specified": {"ru": "не указано", "en": "not specified"},
    # audit
    "audit.title": {"ru": "Аудит — Woland Guard", "en": "Audit — Woland Guard"},
    "audit.h1": {"ru": "Audit log", "en": "Audit log"},
    "filter.actor_type": {"ru": "Actor type", "en": "Actor type"},
    "filter.action": {"ru": "Action", "en": "Action"},
    "filter.target_type": {"ru": "Target type", "en": "Target type"},
    "filter.target_uuid": {"ru": "Target UUID", "en": "Target UUID"},
    "filter.date_from": {"ru": "От даты UTC", "en": "From date UTC"},
    "filter.date_to": {"ru": "До даты UTC (не включая)", "en": "To date UTC (exclusive)"},
    # auth
    "auth.title": {"ru": "Вход — Woland Guard", "en": "Sign in — Woland Guard"},
    "auth.h1": {"ru": "Вход оператора", "en": "Operator sign-in"},
    "auth.api_key_label": {"ru": "API-ключ оператора", "en": "Operator API key"},
    "auth.login_button": {"ru": "Войти", "en": "Log in"},
    # errors
    "errors.error_word": {"ru": "Ошибка", "en": "Error"},
    "errors.request_id": {"ru": "Request ID:", "en": "Request ID:"},
    "errors.back_to_login": {"ru": "Вернуться ко входу", "en": "Back to sign-in"},
    "errors.request_cannot_be_processed": {
        "ru": "Запрос не может быть обработан.",
        "en": "The request could not be processed.",
    },
    # WebError detail strings (raised across the web layer, rendered in errors/*.html)
    "err.login_required": {"ru": "Требуется вход.", "en": "Sign-in required."},
    "err.service_unavailable": {
        "ru": "Сервис временно недоступен.",
        "en": "Service temporarily unavailable.",
    },
    "err.insufficient_permissions": {
        "ru": "Недостаточно прав для Dashboard.",
        "en": "Insufficient permissions for the Dashboard.",
    },
    "err.request_rejected": {"ru": "Запрос отклонён.", "en": "Request rejected."},
    "err.invalid_form": {"ru": "Некорректная форма.", "en": "Invalid form submission."},
    "err.invalid_audit_filters": {
        "ru": "Некорректные audit filters.",
        "en": "Invalid audit filters.",
    },
    "err.invalid_cursor": {"ru": "Некорректный cursor.", "en": "Invalid cursor."},
    "err.invalid_credentials": {"ru": "Неверные учётные данные.", "en": "Invalid credentials."},
    "err.too_many_login_attempts": {
        "ru": "Слишком много попыток входа.",
        "en": "Too many sign-in attempts.",
    },
    "err.logout_unavailable": {
        "ru": "Выход временно недоступен.",
        "en": "Sign-out temporarily unavailable.",
    },
    "err.login_service_unavailable": {
        "ru": "Сервис входа временно недоступен.",
        "en": "Sign-in service temporarily unavailable.",
    },
    "err.reauth_required": {"ru": "Требуется повторный вход.", "en": "Please sign in again."},
    "err.invalid_search_params": {
        "ru": "Некорректные параметры поиска.",
        "en": "Invalid search parameters.",
    },
    "err.incident_not_found": {"ru": "Инцидент не найден.", "en": "Incident not found."},
    "err.invalid_evidence_page_size": {
        "ru": "Некорректный размер страницы evidence.",
        "en": "Invalid evidence page size.",
    },
    "err.invalid_evidence_cursor": {
        "ru": "Некорректный evidence cursor.",
        "en": "Invalid evidence cursor.",
    },
    "err.invalid_transition_data": {
        "ru": "Некорректные данные перехода.",
        "en": "Invalid transition data.",
    },
    "err.incident_mutation_unavailable": {
        "ru": "Изменение инцидента временно недоступно.",
        "en": "Incident update temporarily unavailable.",
    },
    "err.invalid_comment": {"ru": "Некорректный комментарий.", "en": "Invalid comment."},
    "err.comment_unavailable": {
        "ru": "Комментарий временно недоступен.",
        "en": "Comment temporarily unavailable.",
    },
    "err.incident_conflict": {
        "ru": "Операция конфликтует с текущим состоянием инцидента.",
        "en": "The operation conflicts with the incident's current state.",
    },
    "err.internal_error": {"ru": "Внутренняя ошибка.", "en": "Internal error."},
    "err.server_not_found": {"ru": "Сервер не найден.", "en": "Server not found."},
    "err.invalid_request_params": {
        "ru": "Некорректные параметры запроса.",
        "en": "Invalid request parameters.",
    },
    "err.page_not_found": {"ru": "Страница не найдена.", "en": "Page not found."},
    "err.method_not_allowed": {"ru": "Метод не разрешён.", "en": "Method not allowed."},
    "err.rules_unavailable": {
        "ru": "Данные правил временно недоступны.",
        "en": "Rule data temporarily unavailable.",
    },
    # web.presentation projections
    "presentation.no_data": {"ru": "Нет данных", "en": "No data"},
    "presentation.local_cli": {"ru": "Локальный CLI", "en": "Local CLI"},
    "presentation.yes": {"ru": "да", "en": "yes"},
    "presentation.no": {"ru": "нет", "en": "no"},
    "audit.details_unavailable": {"ru": "Детали недоступны", "en": "Details unavailable"},
}


def normalize_language(value: str | None) -> Language:
    if value == "ru":
        return "ru"
    if value == "en":
        return "en"
    return DEFAULT_LANGUAGE


def current_language(request: Request) -> Language:
    return normalize_language(request.cookies.get(LANG_COOKIE_NAME))


def t(lang: str, key: str) -> str:
    """Look up one UI string; an unknown key renders as itself, never raises."""

    entry = _STRINGS.get(key)
    if entry is None:
        return key
    return entry.get(normalize_language(lang), entry[DEFAULT_LANGUAGE])
