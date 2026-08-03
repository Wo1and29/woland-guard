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
from typing import Any, Final
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
from woland_guard_control_plane.application.ip_blocks import (
    DecideIpBlockStatus,
    ProposeIpBlockStatus,
    approve_ip_block,
    propose_ip_block,
    reject_ip_block,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.rbac import Permission, role_has_permission
from woland_guard_control_plane.application.server_queries import (
    ServerFilters,
    ServerSort,
    list_servers,
)
from woland_guard_control_plane.application.telegram_identity import (
    authenticate_telegram_user,
    set_telegram_language,
    stored_telegram_language,
)
from woland_guard_control_plane.infrastructure.database.models import Incident, IncidentStatus
from woland_guard_control_plane.infrastructure.telegram.callbacks import (
    CallbackDataError,
    DecideBlockCallback,
    ProposeBlockCallback,
    parse_callback_data,
)
from woland_guard_control_plane.infrastructure.telegram.message import (
    build_block_decision_keyboard,
)
from woland_guard_control_plane.infrastructure.telegram.updates import (
    TelegramCallbackQuery,
    TelegramMessage,
)
from woland_guard_control_plane.language import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    Language,
    language_from_client_tag,
    normalize_language,
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
class IpBlockRuntimeSettings:
    """Bounded runtime configuration for the propose/approve/reject flow."""

    enabled: bool
    require_second_operator: bool
    plan_ttl_seconds: int
    nft_table: str
    nft_set_v4: str
    nft_set_v6: str


@dataclass(frozen=True, slots=True)
class CallbackAnswer:
    """One bounded answerCallbackQuery reply, visible only to the presser.

    ``follow_up_text``/``follow_up_keyboard`` are set only for a propose-block
    result: ``answerCallbackQuery`` is capped at 200 characters and cannot carry
    a keyboard, so the plan's details and its approve/reject buttons are sent as
    a separate message in the same chat.
    """

    text: str
    show_alert: bool
    follow_up_text: str | None = None
    follow_up_keyboard: dict[str, Any] | None = None


class TelegramCommandRouter:
    """Route one private-chat update from a linked operator to a bounded reply."""

    __slots__ = (
        "_ip_block_settings",
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
        ip_block_settings: IpBlockRuntimeSettings,
    ) -> None:
        if not 1 <= result_limit <= _QUERY_PAGE_SIZE:
            raise ValueError("telegram result limit must fit one query page")
        if pending_action_ttl_seconds < 1:
            raise ValueError("telegram pending action TTL must be positive")
        self._session_factory = session_factory
        self._rate_limiter = rate_limiter
        self._result_limit = result_limit
        self._pending_action_ttl_seconds = pending_action_ttl_seconds
        self._ip_block_settings = ip_block_settings

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
        client_language = language_from_client_tag(sender.language_code)
        with self._session_factory.begin() as session:
            principal = authenticate_telegram_user(
                session,
                telegram_user_id=sender.id,
                now=now,
            )
            if principal is None:
                # No operator, so no stored preference exists: the account's own
                # language tag is the only signal, and this is the first message a
                # new user ever sees, so it matters that it is comprehensible.
                return formatting.unlinked_text(
                    client_language or DEFAULT_LANGUAGE,
                    telegram_user_id=sender.id,
                )
            lang = self._reply_language(session, sender_id=sender.id, client=client_language)
            if command is not None:
                # Any recognized command cancels a pending reason prompt rather than
                # being silently swallowed by it.
                delete_pending_action(session, telegram_user_id=sender.id)
                if command == "/help":
                    return formatting.help_text(lang)
                if command == "/lang":
                    return self._set_language(
                        session,
                        sender_id=sender.id,
                        argument=_parse_command_argument(message.text),
                        current=lang,
                    )
                if not role_has_permission(principal.role, Permission.VIEW_INCIDENTS):
                    return formatting.forbidden_text(lang)
                return self._dispatch(
                    session, command=command, principal=principal, lang=lang, now=now
                )
            lookup = load_pending_action(session, telegram_user_id=sender.id, now=now)
            if lookup.action is None:
                return formatting.reason_expired_text(lang) if lookup.was_expired else None
            delete_pending_action(session, telegram_user_id=sender.id)
            try:
                reason = normalize_reason(message.text)
            except TransitionValidationError:
                return formatting.reason_invalid_text(lang)
            return self._apply_transition(
                session,
                principal=principal,
                incident_id=lookup.action.incident_id,
                target_status=lookup.action.target_status,
                expected_version=lookup.action.expected_version,
                reason=reason,
                idempotency_key=f"tg-msg-{update_id}",
                request_id=f"telegram-msg-{update_id}",
                lang=lang,
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
        # Resolved before any database work so that the replies which deliberately
        # short-circuit ahead of it -- malformed data, rate limiting -- are still
        # rendered in the language the client asked for.
        client_language = None if sender is None else language_from_client_tag(sender.language_code)
        early_language = client_language or DEFAULT_LANGUAGE
        if sender is None or sender.is_bot or callback_query.data is None:
            return CallbackAnswer(formatting.callback_invalid_text(early_language), True)
        try:
            action = parse_callback_data(callback_query.data)
        except CallbackDataError:
            return CallbackAnswer(formatting.callback_invalid_text(early_language), True)
        if self._rate_limiter.consume(str(sender.id)) is not None:
            return CallbackAnswer(formatting.callback_rate_limited_text(early_language), True)

        if isinstance(action, ProposeBlockCallback):
            return self._handle_propose_block(
                action, callback_query, sender_id=sender.id, client=client_language, now=now
            )
        if isinstance(action, DecideBlockCallback):
            return self._handle_decide_block(
                action, callback_query, sender_id=sender.id, client=client_language, now=now
            )

        with self._session_factory.begin() as session:
            principal = authenticate_telegram_user(
                session,
                telegram_user_id=sender.id,
                now=now,
            )
            if principal is None:
                return CallbackAnswer(formatting.callback_unlinked_text(early_language), True)
            lang = self._reply_language(session, sender_id=sender.id, client=client_language)
            if not role_has_permission(principal.role, Permission.TRANSITION_INCIDENTS):
                return CallbackAnswer(formatting.callback_forbidden_text(lang), True)
            if action.target_status is IncidentStatus.INVESTIGATING:
                text = self._apply_transition(
                    session,
                    principal=principal,
                    incident_id=action.incident_id,
                    target_status=action.target_status,
                    expected_version=action.expected_version,
                    reason=None,
                    idempotency_key=_callback_idempotency_key(callback_query.id),
                    request_id=_callback_request_id(callback_query.id),
                    lang=lang,
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
                lang=lang,
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
            return CallbackAnswer(formatting.format_reason_prompt(lang, action.target_status), True)

    def _reply_language(
        self,
        session: Session,
        *,
        sender_id: int,
        client: Language | None,
    ) -> Language:
        """Resolve one conversation's language: saved choice, else client tag, else default."""

        stored = stored_telegram_language(session, telegram_user_id=sender_id)
        if stored is not None:
            return stored
        return client or DEFAULT_LANGUAGE

    def _set_language(
        self,
        session: Session,
        *,
        sender_id: int,
        argument: str | None,
        current: Language,
    ) -> str:
        """Apply /lang, answering in the newly chosen language on success."""

        if argument is None or argument.casefold() not in SUPPORTED_LANGUAGES:
            return formatting.language_usage_text(current)
        chosen = normalize_language(argument.casefold())
        if not set_telegram_language(session, telegram_user_id=sender_id, language=chosen):
            return formatting.language_usage_text(current)
        return formatting.language_changed_text(chosen)

    def _handle_propose_block(
        self,
        action: ProposeBlockCallback,
        callback_query: TelegramCallbackQuery,
        *,
        sender_id: int,
        client: Language | None,
        now: datetime,
    ) -> CallbackAnswer:
        """Propose blocking one incident's correlated source address.

        The plan's details can only be delivered as a follow-up message, which
        needs a chat to send it to -- ``callback_query.message`` is optional in
        the Bot API contract, so a callback that somehow arrives without one is
        rejected rather than silently dropping the plan's details.
        """

        early_language = client or DEFAULT_LANGUAGE
        if not self._ip_block_settings.enabled:
            return CallbackAnswer(formatting.ip_block_disabled_text(early_language), True)
        if callback_query.message is None:
            return CallbackAnswer(formatting.callback_invalid_text(early_language), True)

        lang = early_language
        with self._session_factory.begin() as session:
            principal = authenticate_telegram_user(session, telegram_user_id=sender_id, now=now)
            if principal is None:
                return CallbackAnswer(formatting.callback_unlinked_text(early_language), True)
            lang = self._reply_language(session, sender_id=sender_id, client=client)
            if not role_has_permission(principal.role, Permission.PROPOSE_IP_BLOCK):
                return CallbackAnswer(formatting.callback_forbidden_text(lang), True)
            result = propose_ip_block(
                session,
                actor=principal,
                incident_id=action.incident_id,
                request_id=_callback_request_id(callback_query.id),
                plan_ttl_seconds=self._ip_block_settings.plan_ttl_seconds,
                nft_table=self._ip_block_settings.nft_table,
                nft_set_v4=self._ip_block_settings.nft_set_v4,
                nft_set_v6=self._ip_block_settings.nft_set_v6,
                now=now,
            )

        if result.status is ProposeIpBlockStatus.INCIDENT_NOT_FOUND:
            return CallbackAnswer(formatting.incident_not_found_text(lang), True)
        if result.status is ProposeIpBlockStatus.NO_SOURCE_ADDRESS:
            return CallbackAnswer(formatting.ip_block_no_source_address_text(lang), True)
        if result.status is ProposeIpBlockStatus.REJECTED:
            if result.rejection_reason is None:
                return CallbackAnswer(formatting.callback_invalid_text(lang), True)
            return CallbackAnswer(
                formatting.format_block_rejection(lang, result.rejection_reason), True
            )

        if result.plan is None:
            return CallbackAnswer(formatting.callback_invalid_text(lang), True)
        ack_text = (
            formatting.ip_block_proposed_text(lang)
            if result.status is ProposeIpBlockStatus.CREATED
            else formatting.ip_block_reused_text(lang)
        )
        return CallbackAnswer(
            ack_text,
            False,
            follow_up_text=formatting.format_block_proposal_message(lang, result.plan),
            follow_up_keyboard=build_block_decision_keyboard(lang, result.plan.plan_id),
        )

    def _handle_decide_block(
        self,
        action: DecideBlockCallback,
        callback_query: TelegramCallbackQuery,
        *,
        sender_id: int,
        client: Language | None,
        now: datetime,
    ) -> CallbackAnswer:
        """Approve or reject one still-live plan.

        Approving requires ``APPROVE_IP_BLOCK`` (admin only); rejecting only
        requires ``PROPOSE_IP_BLOCK`` -- walking back your own or a colleague's
        proposal is the safe direction and does not need a second admin (ADR-0015).
        """

        early_language = client or DEFAULT_LANGUAGE
        if not self._ip_block_settings.enabled:
            return CallbackAnswer(formatting.ip_block_disabled_text(early_language), True)
        required_permission = (
            Permission.APPROVE_IP_BLOCK if action.approve else Permission.PROPOSE_IP_BLOCK
        )
        request_id = _callback_request_id(callback_query.id)

        lang = early_language
        with self._session_factory.begin() as session:
            principal = authenticate_telegram_user(session, telegram_user_id=sender_id, now=now)
            if principal is None:
                return CallbackAnswer(formatting.callback_unlinked_text(early_language), True)
            lang = self._reply_language(session, sender_id=sender_id, client=client)
            if not role_has_permission(principal.role, required_permission):
                return CallbackAnswer(formatting.callback_forbidden_text(lang), True)
            if action.approve:
                result = approve_ip_block(
                    session,
                    actor=principal,
                    plan_id=action.plan_id,
                    request_id=request_id,
                    require_second_operator=self._ip_block_settings.require_second_operator,
                    now=now,
                )
            else:
                result = reject_ip_block(
                    session,
                    actor=principal,
                    plan_id=action.plan_id,
                    request_id=request_id,
                    now=now,
                )

        show_alert = result.status not in (
            DecideIpBlockStatus.APPROVED,
            DecideIpBlockStatus.REJECTED,
        )
        return CallbackAnswer(
            formatting.format_block_decision_outcome(lang, result.status), show_alert
        )

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
        lang: Language,
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
        return formatting.format_transition_outcome(lang, outcome, target_status=target_status)

    def _precheck_transition(
        self,
        session: Session,
        *,
        incident_id: UUID,
        target_status: IncidentStatus,
        expected_version: int,
        lang: Language,
    ) -> str | None:
        """Return an error reply if the eventual transition can already be ruled out.

        This is a plain read, not a locked authoritative check -- ``transition_incident``
        still re-validates everything atomically once the reason actually arrives, so a
        race after this point is caught there, not here. This only spares the user from
        typing out a reason for a transition that is already known to be impossible.
        """

        incident = session.scalar(select(Incident).where(Incident.id == incident_id))
        if incident is None:
            return formatting.incident_not_found_text(lang)
        if incident.lock_version != expected_version:
            return formatting.incident_stale_version_text(lang)
        if not is_transition_allowed(IncidentStatus(incident.status), target_status):
            return formatting.incident_transition_not_allowed_text(lang)
        return None

    def _dispatch(
        self,
        session: Session,
        *,
        command: str,
        principal: OperatorPrincipal,
        lang: Language,
        now: datetime,
    ) -> str:
        del principal
        if command == "/status":
            return formatting.format_overview(lang, get_dashboard_overview(session, now=now))
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
                lang,
                shown,
                truncated=len(page.items) > len(shown) or page.next_cursor is not None,
            )
        if command == "/incidents":
            return self._incidents(
                session,
                filters=IncidentDashboardFilters(),
                lang=lang,
                empty_text=formatting.incidents_empty_text(lang),
            )
        if command == "/critical":
            return self._incidents(
                session,
                filters=IncidentDashboardFilters(
                    statuses=_ACTIVE_STATUSES,
                    severities=("critical",),
                ),
                lang=lang,
                empty_text=formatting.critical_incidents_empty_text(lang),
            )
        return formatting.unknown_command_text(lang)

    def _incidents(
        self,
        session: Session,
        *,
        filters: IncidentDashboardFilters,
        lang: Language,
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
            lang,
            shown,
            truncated=len(page.items) > len(shown) or page.next_cursor is not None,
            empty_text=empty_text,
        )


def _parse_command_argument(text: str) -> str | None:
    """Return the single bounded argument token after a command, if any.

    Only the first token is read and its length is capped: this feeds a closed
    allowlist comparison, never a message, so nothing here is ever echoed back.
    """

    parts = text.strip().split(maxsplit=2)
    if len(parts) < 2:
        return None
    argument = parts[1]
    return argument if len(argument) <= 16 else None


def _callback_idempotency_key(callback_query_id: str) -> str:
    """Hash the provider id to a fixed-length key regardless of its raw length."""

    digest = hashlib.sha256(callback_query_id.encode("utf-8")).hexdigest()
    return f"tg-cb-{digest}"


def _callback_request_id(callback_query_id: str) -> str:
    """Hash the provider id to fit the 64-character ``request_id`` column width.

    ``callback_query.id`` is bounded at 128 characters by the inbound Bot API
    contract, wider than the ``request_id`` columns it is recorded into -- a
    plain ``f"telegram-cb-{callback_query_id}"`` could overflow them. The
    64-character hex digest fits exactly.
    """

    return hashlib.sha256(callback_query_id.encode("utf-8")).hexdigest()


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
