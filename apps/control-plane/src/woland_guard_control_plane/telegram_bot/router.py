"""Default-deny dispatch from one inbound Telegram update to one safe reply.

Message handling opens a database session for any private, non-bot text -- not
only recognized commands -- because a pending terminal-status reason prompt
(see ``pending_actions.py``) can only be detected by asking the database. This
is a deliberate widening from 9A, where a non-command message was ignored
before any database access. The per-account rate limiter still runs first and
bounds the resulting load; see ADR-0014.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from woland_guard_control_plane.application.dashboard_overview import get_dashboard_overview
from woland_guard_control_plane.application.incident_queries import (
    IncidentDashboardFilters,
    IncidentDashboardSort,
    list_dashboard_incidents,
)
from woland_guard_control_plane.application.incident_workflow import (
    NormalizedTransition,
    TransitionValidationError,
    canonical_transition_hash,
    is_transition_allowed,
    normalize_reason,
    transition_incident,
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
from woland_guard_control_plane.infrastructure.database.models import Incident, IncidentStatus
from woland_guard_control_plane.infrastructure.telegram.callbacks import (
    CallbackDataError,
    parse_incident_action,
)
from woland_guard_control_plane.infrastructure.telegram.updates import (
    TelegramCallbackQuery,
    TelegramMessage,
)
from woland_guard_control_plane.telegram_bot import formatting
from woland_guard_control_plane.telegram_bot.pending_actions import (
    delete_pending_action,
    load_pending_action,
    store_pending_action,
)

_QUERY_PAGE_SIZE: Final = 25
_ACTIVE_STATUSES: Final = ("new", "investigating")


@dataclass(frozen=True, slots=True)
class CallbackAnswer:
    """One bounded answerCallbackQuery reply, visible only to the presser."""

    text: str
    show_alert: bool


class TelegramCommandRouter:
    """Route one private-chat update from a linked operator to a bounded reply."""

    __slots__ = (
        "_pending_action_ttl_seconds",
        "_rate_limiter",
        "_result_limit",
        "_session_factory",
    )

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        rate_limiter: FixedWindowRateLimiter,
        result_limit: int,
        pending_action_ttl_seconds: int,
    ) -> None:
        if not 1 <= result_limit <= _QUERY_PAGE_SIZE:
            raise ValueError("telegram result limit must fit one query page")
        if pending_action_ttl_seconds < 1:
            raise ValueError("telegram pending action TTL must be positive")
        self._session_factory = session_factory
        self._rate_limiter = rate_limiter
        self._result_limit = result_limit
        self._pending_action_ttl_seconds = pending_action_ttl_seconds

    def handle(self, message: TelegramMessage, *, now: datetime, update_id: int) -> str | None:
        """Return the reply text, or None when the message must be ignored silently."""

        sender = message.sender
        if sender is None or sender.is_bot or not message.is_private:
            return None
        if message.text is None:
            return None
        if self._rate_limiter.consume(str(sender.id)) is not None:
            return None

        command = _parse_command(message.text)
        with self._session_factory.begin() as session:
            principal = authenticate_telegram_user(
                session,
                telegram_user_id=sender.id,
                now=now,
            )
            if principal is None:
                return formatting.UNLINKED_TEMPLATE.format(telegram_user_id=sender.id)
            if command is not None:
                # Any recognized command cancels a pending reason prompt rather than
                # being silently swallowed by it.
                delete_pending_action(session, telegram_user_id=sender.id)
                if command == "/help":
                    return formatting.HELP_TEXT
                if not role_has_permission(principal.role, Permission.VIEW_INCIDENTS):
                    return formatting.FORBIDDEN_TEXT
                return self._dispatch(session, command=command, principal=principal, now=now)
            lookup = load_pending_action(session, telegram_user_id=sender.id, now=now)
            if lookup.action is None:
                return formatting.REASON_EXPIRED_TEXT if lookup.was_expired else None
            delete_pending_action(session, telegram_user_id=sender.id)
            try:
                reason = normalize_reason(message.text)
            except TransitionValidationError:
                return formatting.REASON_INVALID_TEXT
            return self._apply_transition(
                session,
                principal=principal,
                incident_id=lookup.action.incident_id,
                target_status=lookup.action.target_status,
                expected_version=lookup.action.expected_version,
                reason=reason,
                idempotency_key=f"tg-msg-{update_id}",
                request_id=f"telegram-msg-{update_id}",
                now=now,
            )

    def handle_callback_query(
        self,
        callback_query: TelegramCallbackQuery,
        *,
        now: datetime,
    ) -> CallbackAnswer:
        """Return the answerCallbackQuery reply for one inline-button press.

        ``callback_query.data`` is whatever the client sends back, not necessarily
        a value this process ever put on a button -- it is parsed and validated as
        untrusted input before anything else happens.
        """

        sender = callback_query.sender
        if sender is None or sender.is_bot or callback_query.data is None:
            return CallbackAnswer(formatting.CALLBACK_INVALID_TEXT, True)
        try:
            action = parse_incident_action(callback_query.data)
        except CallbackDataError:
            return CallbackAnswer(formatting.CALLBACK_INVALID_TEXT, True)
        if self._rate_limiter.consume(str(sender.id)) is not None:
            return CallbackAnswer(formatting.CALLBACK_RATE_LIMITED_TEXT, True)

        with self._session_factory.begin() as session:
            principal = authenticate_telegram_user(
                session,
                telegram_user_id=sender.id,
                now=now,
            )
            if principal is None:
                return CallbackAnswer(formatting.CALLBACK_UNLINKED_TEXT, True)
            if not role_has_permission(principal.role, Permission.TRANSITION_INCIDENTS):
                return CallbackAnswer(formatting.CALLBACK_FORBIDDEN_TEXT, True)
            if action.target_status is IncidentStatus.INVESTIGATING:
                text = self._apply_transition(
                    session,
                    principal=principal,
                    incident_id=action.incident_id,
                    target_status=action.target_status,
                    expected_version=action.expected_version,
                    reason=None,
                    idempotency_key=_callback_idempotency_key(callback_query.id),
                    request_id=f"telegram-cb-{callback_query.id}",
                    now=now,
                )
                return CallbackAnswer(text, False)
            # Terminal statuses require a reason, so the transition itself is applied
            # later, once the reason arrives. Check now anyway -- otherwise a stale
            # button or an already-disallowed transition would only be reported after
            # the user typed out a reason for something that could never have applied.
            precheck_error = self._precheck_transition(
                session,
                incident_id=action.incident_id,
                target_status=action.target_status,
                expected_version=action.expected_version,
            )
            if precheck_error is not None:
                return CallbackAnswer(precheck_error, False)
            store_pending_action(
                session,
                telegram_user_id=sender.id,
                incident_id=action.incident_id,
                target_status=action.target_status,
                expected_version=action.expected_version,
                ttl_seconds=self._pending_action_ttl_seconds,
                now=now,
            )
            return CallbackAnswer(formatting.format_reason_prompt(action.target_status), True)

    def _apply_transition(
        self,
        session: Session,
        *,
        principal: OperatorPrincipal,
        incident_id: UUID,
        target_status: IncidentStatus,
        expected_version: int,
        reason: str | None,
        idempotency_key: str,
        request_id: str,
        now: datetime,
    ) -> str:
        normalized = NormalizedTransition(
            target_status=target_status,
            expected_version=expected_version,
            reason=reason,
        )
        request_hash = canonical_transition_hash(incident_id, normalized)
        outcome = transition_incident(
            session,
            actor=principal,
            incident_id=incident_id,
            transition=normalized,
            idempotency_key=idempotency_key,
            canonical_request_hash=request_hash,
            request_id=request_id,
            now=now,
        )
        return formatting.format_transition_outcome(outcome, target_status=target_status)

    def _precheck_transition(
        self,
        session: Session,
        *,
        incident_id: UUID,
        target_status: IncidentStatus,
        expected_version: int,
    ) -> str | None:
        """Return an error reply if the eventual transition can already be ruled out.

        This is a plain read, not a locked authoritative check -- ``transition_incident``
        still re-validates everything atomically once the reason actually arrives, so a
        race after this point is caught there, not here. This only spares the user from
        typing out a reason for a transition that is already known to be impossible.
        """

        incident = session.scalar(select(Incident).where(Incident.id == incident_id))
        if incident is None:
            return formatting.INCIDENT_NOT_FOUND_TEXT
        if incident.lock_version != expected_version:
            return formatting.INCIDENT_STALE_VERSION_TEXT
        if not is_transition_allowed(IncidentStatus(incident.status), target_status):
            return formatting.INCIDENT_TRANSITION_NOT_ALLOWED_TEXT
        return None

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


def _callback_idempotency_key(callback_query_id: str) -> str:
    """Hash the provider id to a fixed-length key regardless of its raw length."""

    digest = hashlib.sha256(callback_query_id.encode("utf-8")).hexdigest()
    return f"tg-cb-{digest}"


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
