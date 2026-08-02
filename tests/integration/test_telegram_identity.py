"""Telegram operator links and the third authentication method on real PostgreSQL."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.integration.conftest import OperatorFactory
from woland_guard_control_plane.application.telegram_identity import (
    TelegramIdentityError,
    authenticate_telegram_user,
    link_telegram_user,
    list_telegram_links,
    revoke_telegram_link,
)
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    Operator,
    OperatorAuthMethodType,
    OperatorRole,
)

pytestmark = pytest.mark.integration

TELEGRAM_USER_ID = 4_242_424_242


def test_link_binds_one_account_and_records_audit(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)

    with get_session_factory().begin() as session:
        link = link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )

    assert link.operator_id == operator.operator_id
    assert link.telegram_user_id == TELEGRAM_USER_ID

    with get_session_factory()() as session:
        entry = session.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "operator_telegram_link.created")
        ).one()
        assert entry.target_id == link.link_id
        assert entry.details == {"operator_id": str(operator.operator_id)}
        assert entry.auth_method_type is None


def test_authenticated_principal_carries_the_telegram_auth_method(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        link = link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )

    with get_session_factory().begin() as session:
        principal = authenticate_telegram_user(session, telegram_user_id=TELEGRAM_USER_ID)

    assert principal is not None
    assert principal.operator_id == operator.operator_id
    assert principal.username == operator.username
    assert principal.role is OperatorRole.ANALYST
    assert principal.auth_method_type is OperatorAuthMethodType.TELEGRAM
    assert principal.auth_method_id == link.link_id


def test_authentication_records_last_used_at(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.VIEWER)
    moment = datetime.now(UTC) + timedelta(minutes=1)
    with get_session_factory().begin() as session:
        link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )

    with get_session_factory().begin() as session:
        assert (
            authenticate_telegram_user(
                session,
                telegram_user_id=TELEGRAM_USER_ID,
                now=moment,
            )
            is not None
        )

    with get_session_factory()() as session:
        stored = list_telegram_links(session)
    assert len(stored) == 1


@pytest.mark.parametrize("unknown_id", [1, 999_999_999, TELEGRAM_USER_ID + 1])
def test_unknown_account_is_denied(unknown_id: int) -> None:
    with get_session_factory().begin() as session:
        assert authenticate_telegram_user(session, telegram_user_id=unknown_id) is None


def test_revoked_link_is_denied_but_keeps_history(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        link = link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )

    with get_session_factory().begin() as session:
        revoke_telegram_link(session, link_id=link.link_id)

    with get_session_factory().begin() as session:
        assert authenticate_telegram_user(session, telegram_user_id=TELEGRAM_USER_ID) is None

    with get_session_factory()() as session:
        assert list_telegram_links(session) == ()
        actions = set(
            session.scalars(
                select(AuditLogEntry.action).where(
                    AuditLogEntry.action.like("operator_telegram_link.%")
                )
            )
        )
    assert actions == {"operator_telegram_link.created", "operator_telegram_link.revoked"}


def test_inactive_operator_is_denied(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )
    with get_session_factory().begin() as session:
        stored = session.get(Operator, operator.operator_id)
        assert stored is not None
        stored.is_active = False

    with get_session_factory().begin() as session:
        assert authenticate_telegram_user(session, telegram_user_id=TELEGRAM_USER_ID) is None


def test_second_active_link_for_one_account_is_rejected(
    register_operator: OperatorFactory,
) -> None:
    first = register_operator(role=OperatorRole.ANALYST)
    second = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        link_telegram_user(
            session,
            operator_id=first.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )

    with pytest.raises(TelegramIdentityError, match="already linked"):
        with get_session_factory().begin() as session:
            link_telegram_user(
                session,
                operator_id=second.operator_id,
                telegram_user_id=TELEGRAM_USER_ID,
            )


def test_second_active_link_for_one_operator_is_rejected(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )

    with pytest.raises(TelegramIdentityError, match="already has an active"):
        with get_session_factory().begin() as session:
            link_telegram_user(
                session,
                operator_id=operator.operator_id,
                telegram_user_id=TELEGRAM_USER_ID + 1,
            )


def test_relinking_after_revocation_is_allowed(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        first = link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )
    with get_session_factory().begin() as session:
        revoke_telegram_link(session, link_id=first.link_id)

    with get_session_factory().begin() as session:
        second = link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )

    assert second.link_id != first.link_id


def test_unknown_operator_and_double_revocation_are_rejected(
    register_operator: OperatorFactory,
) -> None:
    with pytest.raises(TelegramIdentityError, match="operator does not exist"):
        with get_session_factory().begin() as session:
            link_telegram_user(
                session,
                operator_id=uuid4(),
                telegram_user_id=TELEGRAM_USER_ID,
            )

    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        link = link_telegram_user(
            session,
            operator_id=operator.operator_id,
            telegram_user_id=TELEGRAM_USER_ID,
        )
    with get_session_factory().begin() as session:
        revoke_telegram_link(session, link_id=link.link_id)

    with pytest.raises(TelegramIdentityError, match="already revoked"):
        with get_session_factory().begin() as session:
            revoke_telegram_link(session, link_id=link.link_id)


@pytest.mark.parametrize("invalid", [0, -1, 2**53])
def test_out_of_range_identifiers_are_rejected(
    register_operator: OperatorFactory,
    invalid: int,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)

    with pytest.raises(TelegramIdentityError, match="positive integer"):
        with get_session_factory().begin() as session:
            link_telegram_user(
                session,
                operator_id=operator.operator_id,
                telegram_user_id=invalid,
            )
