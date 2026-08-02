"""Inbound command dispatch and offset durability against real PostgreSQL."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tests.integration.conftest import OperatorFactory
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.telegram_identity import link_telegram_user
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import OperatorRole
from woland_guard_control_plane.infrastructure.telegram.updates import TelegramMessage
from woland_guard_control_plane.telegram_bot import formatting
from woland_guard_control_plane.telegram_bot.offsets import (
    confirm_next_update_id,
    load_next_update_id,
)
from woland_guard_control_plane.telegram_bot.router import TelegramCommandRouter

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
TELEGRAM_USER_ID = 5_151_515_151


def _router() -> TelegramCommandRouter:
    return TelegramCommandRouter(
        get_session_factory(),
        rate_limiter=FixedWindowRateLimiter(max_requests=100, window_seconds=60),
        result_limit=10,
        pending_action_ttl_seconds=300,
    )


def _message(*, text: str, sender_id: int = TELEGRAM_USER_ID) -> TelegramMessage:
    return TelegramMessage.model_validate(
        {
            "message_id": 1,
            "from": {"id": sender_id, "is_bot": False},
            "chat": {"id": sender_id, "type": "private"},
            "text": text,
        }
    )


def _link(operator_id: object) -> None:
    with get_session_factory().begin() as session:
        link_telegram_user(
            session,
            operator_id=operator_id,  # type: ignore[arg-type]
            telegram_user_id=TELEGRAM_USER_ID,
        )


def test_unlinked_sender_receives_only_its_own_identifier() -> None:
    reply = _router().handle(_message(text="/status"), now=NOW, update_id=1)

    assert reply is not None
    assert str(TELEGRAM_USER_ID) in reply
    assert "не связан" in reply
    for leak in ("wgok_", "postgres", "token"):
        assert leak not in reply.lower()


def test_linked_operator_receives_help_without_data_permission(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.VIEWER)
    _link(operator.operator_id)

    assert _router().handle(_message(text="/help"), now=NOW, update_id=1) == formatting.HELP_TEXT


@pytest.mark.parametrize("command", ["/status", "/servers", "/incidents", "/critical"])
def test_linked_operator_reads_safe_aggregates(
    register_operator: OperatorFactory,
    command: str,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)

    reply = _router().handle(_message(text=command), now=NOW, update_id=1)

    assert reply is not None
    assert reply not in {formatting.FORBIDDEN_TEXT, formatting.UNKNOWN_COMMAND_TEXT}
    assert "не связан" not in reply


def test_unknown_command_from_linked_operator_is_reported_safely(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)

    reply = _router().handle(_message(text="/definitelynotacommand"), now=NOW, update_id=1)

    assert reply == formatting.UNKNOWN_COMMAND_TEXT


def test_revoked_operator_loses_access_immediately(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id)
    assert _router().handle(_message(text="/status"), now=NOW, update_id=1) is not None

    with get_session_factory().begin() as session:
        from woland_guard_control_plane.infrastructure.database.models import Operator

        stored = session.get(Operator, operator.operator_id)
        assert stored is not None
        stored.is_active = False

    reply = _router().handle(_message(text="/status"), now=NOW, update_id=1)
    assert reply is not None
    assert "не связан" in reply


def test_offset_survives_restart_and_never_moves_backwards() -> None:
    with get_session_factory()() as session:
        assert load_next_update_id(session) == 0

    with get_session_factory().begin() as session:
        confirm_next_update_id(session, next_update_id=41)
    with get_session_factory()() as session:
        assert load_next_update_id(session) == 41

    with get_session_factory().begin() as session:
        confirm_next_update_id(session, next_update_id=12)
    with get_session_factory()() as session:
        assert load_next_update_id(session) == 41

    with get_session_factory().begin() as session:
        confirm_next_update_id(session, next_update_id=99)
    with get_session_factory()() as session:
        assert load_next_update_id(session) == 99


@pytest.mark.parametrize("invalid", [-1, True])
def test_offset_rejects_values_outside_the_contract(invalid: object) -> None:
    with pytest.raises(ValueError, match="telegram offset"):
        with get_session_factory().begin() as session:
            confirm_next_update_id(session, next_update_id=invalid)  # type: ignore[arg-type]
