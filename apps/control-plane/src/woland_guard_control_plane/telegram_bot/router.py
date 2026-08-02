"""Default-deny dispatch from one inbound Telegram message to one safe reply."""

from __future__ import annotations

from datetime import datetime
from typing import Final

from sqlalchemy.orm import Session, sessionmaker

from woland_guard_control_plane.application.dashboard_overview import get_dashboard_overview
from woland_guard_control_plane.application.incident_queries import (
    IncidentDashboardFilters,
    IncidentDashboardSort,
    list_dashboard_incidents,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.rbac import Permission, role_has_permission
from woland_guard_control_plane.application.server_queries import (
    ServerFilters,
    ServerSort,
    list_servers,
)
from woland_guard_control_plane.application.telegram_identity import authenticate_telegram_user
from woland_guard_control_plane.infrastructure.telegram.updates import TelegramMessage
from woland_guard_control_plane.telegram_bot import formatting

_QUERY_PAGE_SIZE: Final = 25
_ACTIVE_STATUSES: Final = ("new", "investigating")


class TelegramCommandRouter:
    """Route one private-chat command from a linked operator to a bounded reply."""

    __slots__ = ("_result_limit", "_rate_limiter", "_session_factory")

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        rate_limiter: FixedWindowRateLimiter,
        result_limit: int,
    ) -> None:
        if not 1 <= result_limit <= _QUERY_PAGE_SIZE:
            raise ValueError("telegram result limit must fit one query page")
        self._session_factory = session_factory
        self._rate_limiter = rate_limiter
        self._result_limit = result_limit

    def handle(self, message: TelegramMessage, *, now: datetime) -> str | None:
        """Return the reply text, or None when the message must be ignored silently."""

        sender = message.sender
        if sender is None or sender.is_bot or not message.is_private:
            return None
        if message.text is None:
            return None
        command = _parse_command(message.text)
        if command is None:
            return None
        if self._rate_limiter.consume(str(sender.id)) is not None:
            return None

        with self._session_factory.begin() as session:
            principal = authenticate_telegram_user(
                session,
                telegram_user_id=sender.id,
                now=now,
            )
            if principal is None:
                return formatting.UNLINKED_TEMPLATE.format(telegram_user_id=sender.id)
            if command == "/help":
                return formatting.HELP_TEXT
            if not role_has_permission(principal.role, Permission.VIEW_INCIDENTS):
                return formatting.FORBIDDEN_TEXT
            return self._dispatch(session, command=command, principal=principal, now=now)

    def _dispatch(
        self,
        session: Session,
        *,
        command: str,
        principal: OperatorPrincipal,
        now: datetime,
    ) -> str:
        del principal
        if command == "/status":
            return formatting.format_overview(get_dashboard_overview(session, now=now))
        if command == "/servers":
            page = list_servers(
                session,
                filters=ServerFilters(),
                sort=ServerSort.NAME_ASC,
                page_size=_QUERY_PAGE_SIZE,
                cursor=None,
            )
            shown = page.items[: self._result_limit]
            return formatting.format_servers(
                shown,
                truncated=len(page.items) > len(shown) or page.next_cursor is not None,
            )
        if command == "/incidents":
            return self._incidents(
                session,
                filters=IncidentDashboardFilters(),
                empty_text="Инцидентов пока нет.",
            )
        if command == "/critical":
            return self._incidents(
                session,
                filters=IncidentDashboardFilters(
                    statuses=_ACTIVE_STATUSES,
                    severities=("critical",),
                ),
                empty_text="Активных критических инцидентов нет.",
            )
        return formatting.UNKNOWN_COMMAND_TEXT

    def _incidents(
        self,
        session: Session,
        *,
        filters: IncidentDashboardFilters,
        empty_text: str,
    ) -> str:
        page = list_dashboard_incidents(
            session,
            filters=filters,
            sort=IncidentDashboardSort.CREATED_DESC,
            page_size=_QUERY_PAGE_SIZE,
            cursor=None,
        )
        shown = page.items[: self._result_limit]
        return formatting.format_incidents(
            shown,
            truncated=len(page.items) > len(shown) or page.next_cursor is not None,
            empty_text=empty_text,
        )


def _parse_command(text: str) -> str | None:
    """Return one canonical command token, or None when the text is not a command."""

    stripped = text.strip()
    if not stripped.startswith("/"):
        return None
    token = stripped.split(maxsplit=1)[0]
    mention = token.find("@")
    if mention != -1:
        token = token[:mention]
    lowered = token.lower()
    if len(lowered) > 32 or not lowered[1:].isalpha():
        return None
    return lowered
