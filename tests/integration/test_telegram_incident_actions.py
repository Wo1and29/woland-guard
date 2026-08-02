"""Callback-button incident transitions and the terminal-status reason prompt."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from tests.integration.test_dashboard_queries import _create_incident_with_evidence
from woland_guard_control_plane.application.incident_workflow import (
    NormalizedTransition,
    canonical_transition_hash,
    transition_incident,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.telegram_identity import link_telegram_user
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    Incident,
    IncidentHistoryEntry,
    IncidentStatus,
    OperatorAuthMethodType,
    OperatorRole,
)
from woland_guard_control_plane.infrastructure.telegram.callbacks import encode_incident_action
from woland_guard_control_plane.infrastructure.telegram.updates import (
    TelegramCallbackQuery,
    TelegramMessage,
)
from woland_guard_control_plane.telegram_bot import formatting
from woland_guard_control_plane.telegram_bot.router import TelegramCommandRouter

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
TELEGRAM_USER_ID = 6_161_616_161
PENDING_ACTION_TTL_SECONDS = 300


def _router(*, ttl_seconds: int = PENDING_ACTION_TTL_SECONDS) -> TelegramCommandRouter:
    return TelegramCommandRouter(
        get_session_factory(),
        rate_limiter=FixedWindowRateLimiter(max_requests=100, window_seconds=60),
        result_limit=10,
        pending_action_ttl_seconds=ttl_seconds,
    )


def _link(operator_id: object, *, telegram_user_id: int = TELEGRAM_USER_ID) -> None:
    with get_session_factory().begin() as session:
        link_telegram_user(
            session,
            operator_id=operator_id,  # type: ignore[arg-type]
            telegram_user_id=telegram_user_id,
        )


def _callback(
    incident_id: UUID,
    status: IncidentStatus,
    *,
    version: int = 1,
    callback_id: str = "cb-1",
    sender_id: int = TELEGRAM_USER_ID,
) -> TelegramCallbackQuery:
    return TelegramCallbackQuery.model_validate(
        {
            "id": callback_id,
            "from": {"id": sender_id, "is_bot": False},
            "message": {
                "message_id": 1,
                "chat": {"id": sender_id, "type": "private"},
            },
            "data": encode_incident_action(
                incident_id=incident_id,
                target_status=status,
                expected_version=version,
            ),
        }
    )


def _incident_status(incident_id: UUID) -> str:
    with get_session_factory()() as session:
        stored = session.get(Incident, incident_id)
        assert stored is not None
        return stored.status


def test_investigating_button_transitions_immediately(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()

    answer = _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.INVESTIGATING),
        now=NOW,
    )

    assert answer.show_alert is False
    assert "изменён" in answer.text
    assert _incident_status(incident_id) == "investigating"


def test_investigating_button_replay_is_idempotent(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()
    callback = _callback(incident_id, IncidentStatus.INVESTIGATING, callback_id="cb-replay")

    first = _router().handle_callback_query(callback, now=NOW)
    second = _router().handle_callback_query(callback, now=NOW)

    assert "изменён" in first.text
    assert "Уже выполнено" in second.text
    assert _incident_status(incident_id) == "investigating"


def test_second_press_with_a_matching_version_reports_not_allowed(
    register_operator: OperatorFactory,
) -> None:
    """A version that matches, but a transition the state machine still refuses."""

    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()
    _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.INVESTIGATING, callback_id="cb-a"),
        now=NOW,
    )
    assert _incident_status(incident_id) == "investigating"

    # The incident is now at version 2; investigating -> investigating is refused by
    # the state machine itself, not by a stale optimistic-lock version.
    answer = _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.INVESTIGATING, version=2, callback_id="cb-b"),
        now=NOW,
    )

    assert "недоступен" in answer.text
    assert _incident_status(incident_id) == "investigating"


def test_terminal_button_precheck_reports_not_allowed_without_asking_for_a_reason(
    register_operator: OperatorFactory,
) -> None:
    """A terminal-status button must not prompt for a reason it can never apply."""

    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()
    router = _router()
    router.handle_callback_query(
        _callback(incident_id, IncidentStatus.RESOLVED, callback_id="cb-a"),
        now=NOW,
    )
    router.handle(
        TelegramMessage.model_validate(
            {
                "message_id": 2,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "closing as a synthetic test fixture",
            }
        ),
        now=NOW,
        update_id=600,
    )
    assert _incident_status(incident_id) == "resolved"

    # resolved has no outgoing transitions at all, including to itself.
    answer = router.handle_callback_query(
        _callback(incident_id, IncidentStatus.RESOLVED, version=2, callback_id="cb-b"),
        now=NOW,
    )

    assert "недоступен" in answer.text
    assert answer.show_alert is False


def test_resolved_button_prompts_then_applies_the_reason(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()

    prompt = _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.RESOLVED),
        now=NOW,
    )
    assert prompt.show_alert is True
    assert "закрыт" in prompt.text
    assert _incident_status(incident_id) == "new"

    reply = _router().handle(
        TelegramMessage.model_validate(
            {
                "message_id": 2,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "Confirmed as a synthetic false alarm during review.",
            }
        ),
        now=NOW,
        update_id=100,
    )

    assert reply is not None
    assert "изменён" in reply
    assert _incident_status(incident_id) == "resolved"
    with get_session_factory()() as session:
        history = session.scalars(
            select(IncidentHistoryEntry)
            .where(IncidentHistoryEntry.incident_id == incident_id)
            .order_by(IncidentHistoryEntry.version.desc())
        ).first()
        assert history is not None
        assert history.reason == "Confirmed as a synthetic false alarm during review."
        assert history.auth_method_type == "telegram"


def test_false_positive_button_prompts_then_applies_the_reason(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()

    _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.FALSE_POSITIVE),
        now=NOW,
    )
    reply = _router().handle(
        TelegramMessage.model_validate(
            {
                "message_id": 2,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "Benign scanner traffic, verified against the allowlist.",
            }
        ),
        now=NOW,
        update_id=101,
    )

    assert reply is not None
    assert _incident_status(incident_id) == "false_positive"


def test_command_cancels_a_pending_reason_prompt(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()
    _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.RESOLVED),
        now=NOW,
    )

    router = _router()
    help_reply = router.handle(
        TelegramMessage.model_validate(
            {
                "message_id": 2,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "/help",
            }
        ),
        now=NOW,
        update_id=200,
    )
    assert help_reply == formatting.HELP_TEXT

    # The reason prompt was cancelled: an ordinary follow-up message is now ignored.
    ignored = router.handle(
        TelegramMessage.model_validate(
            {
                "message_id": 3,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "this text arrives after the command and must not apply",
            }
        ),
        now=NOW,
        update_id=201,
    )
    assert ignored is None
    assert _incident_status(incident_id) == "new"


def test_invalid_reason_is_rejected_and_cancels_the_pending_action(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()
    router = _router()
    router.handle_callback_query(_callback(incident_id, IncidentStatus.RESOLVED), now=NOW)

    reply = router.handle(
        TelegramMessage.model_validate(
            {
                "message_id": 2,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "control\x00character",
            }
        ),
        now=NOW,
        update_id=300,
    )

    assert reply == formatting.REASON_INVALID_TEXT
    assert _incident_status(incident_id) == "new"

    # The action was cancelled, not left pending: a later valid message is ignored.
    ignored = router.handle(
        TelegramMessage.model_validate(
            {
                "message_id": 3,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "a perfectly valid reason sent too late",
            }
        ),
        now=NOW,
        update_id=301,
    )
    assert ignored is None


def test_expired_pending_action_reports_expiry_instead_of_applying(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()
    router = _router(ttl_seconds=10)
    router.handle_callback_query(_callback(incident_id, IncidentStatus.RESOLVED), now=NOW)

    reply = router.handle(
        TelegramMessage.model_validate(
            {
                "message_id": 2,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "arrives after the TTL has elapsed",
            }
        ),
        now=NOW + timedelta(seconds=11),
        update_id=400,
    )

    assert reply == formatting.REASON_EXPIRED_TEXT
    assert _incident_status(incident_id) == "new"


def test_pressing_a_second_button_replaces_the_first_pending_action(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()
    router = _router()
    router.handle_callback_query(
        _callback(incident_id, IncidentStatus.RESOLVED, callback_id="cb-first"),
        now=NOW,
    )
    router.handle_callback_query(
        _callback(incident_id, IncidentStatus.FALSE_POSITIVE, callback_id="cb-second"),
        now=NOW,
    )

    router.handle(
        TelegramMessage.model_validate(
            {
                "message_id": 2,
                "from": {"id": TELEGRAM_USER_ID, "is_bot": False},
                "chat": {"id": TELEGRAM_USER_ID, "type": "private"},
                "text": "applies to whichever action is still pending",
            }
        ),
        now=NOW,
        update_id=500,
    )

    assert _incident_status(incident_id) == "false_positive"


def test_unlinked_sender_callback_is_denied(register_operator: OperatorFactory) -> None:
    incident_id, _ = _create_incident_with_evidence()

    answer = _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.INVESTIGATING, sender_id=9_999_999),
        now=NOW,
    )

    assert answer.text == formatting.CALLBACK_UNLINKED_TEXT
    assert answer.show_alert is True
    assert _incident_status(incident_id) == "new"


def test_viewer_role_cannot_transition_via_button(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.VIEWER)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()

    answer = _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.INVESTIGATING),
        now=NOW,
    )

    assert answer.text == formatting.CALLBACK_FORBIDDEN_TEXT
    assert _incident_status(incident_id) == "new"


def test_stale_button_version_is_reported_after_an_out_of_band_change(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    incident_id, _ = _create_incident_with_evidence()

    with get_session_factory().begin() as session:
        normalized = NormalizedTransition(
            target_status=IncidentStatus.INVESTIGATING,
            expected_version=1,
            reason=None,
        )
        transition_incident(
            session,
            actor=_local_cli_principal(operator),
            incident_id=incident_id,
            transition=normalized,
            idempotency_key="out-of-band-change",
            canonical_request_hash=canonical_transition_hash(incident_id, normalized),
            request_id="test-setup",
            now=NOW,
        )

    # The button still encodes expected_version=1, matching the notification's snapshot.
    answer = _router().handle_callback_query(
        _callback(incident_id, IncidentStatus.RESOLVED, version=1),
        now=NOW,
    )

    assert "изменён" in answer.text and "панель" in answer.text
    assert _incident_status(incident_id) == "investigating"


def _local_cli_principal(operator: RegisteredOperator) -> OperatorPrincipal:
    """Impersonate an out-of-band REST/Dashboard change, not the Telegram path."""

    return OperatorPrincipal(
        operator_id=operator.operator_id,
        username=operator.username,
        role=OperatorRole.ANALYST,
        auth_method_type=OperatorAuthMethodType.OPERATOR_API_KEY,
        auth_method_id=operator.key_id,
    )
