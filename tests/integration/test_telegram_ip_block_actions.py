"""Propose/approve/reject button flow through the Telegram router, real PostgreSQL.

Nothing here ever executes ``command_argv`` -- these tests only verify that the
router wires ``ip_blocks.py`` correctly: permission checks, the follow-up
message and its keyboard, and the mandatory "nothing was executed" wording on
a successful approval.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from tests.integration.test_ip_blocks import _create_incident
from woland_guard_control_plane.application.ip_blocks import add_allowlist_entry
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.telegram_identity import link_telegram_user
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    IpBlockPlan,
    OperatorRole,
)
from woland_guard_control_plane.infrastructure.telegram.callbacks import (
    encode_decide_block,
    encode_propose_block,
)
from woland_guard_control_plane.infrastructure.telegram.updates import TelegramCallbackQuery
from woland_guard_control_plane.telegram_bot import formatting
from woland_guard_control_plane.telegram_bot.router import (
    IpBlockRuntimeSettings,
    TelegramCommandRouter,
)

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
TELEGRAM_USER_ID = 7_171_717_171
TELEGRAM_USER_ID_TWO = 7_171_717_172

_ENABLED_SETTINGS = IpBlockRuntimeSettings(
    enabled=True,
    require_second_operator=True,
    plan_ttl_seconds=3_600,
    nft_table="woland_guard",
    nft_set_v4="blocked_v4",
    nft_set_v6="blocked_v6",
)
_SINGLE_OPERATOR_SETTINGS = IpBlockRuntimeSettings(
    enabled=True,
    require_second_operator=False,
    plan_ttl_seconds=3_600,
    nft_table="woland_guard",
    nft_set_v4="blocked_v4",
    nft_set_v6="blocked_v6",
)
_DISABLED_SETTINGS = IpBlockRuntimeSettings(
    enabled=False,
    require_second_operator=True,
    plan_ttl_seconds=3_600,
    nft_table="woland_guard",
    nft_set_v4="blocked_v4",
    nft_set_v6="blocked_v6",
)


def _router(*, settings: IpBlockRuntimeSettings = _ENABLED_SETTINGS) -> TelegramCommandRouter:
    return TelegramCommandRouter(
        get_session_factory(),
        rate_limiter=FixedWindowRateLimiter(max_requests=100, window_seconds=60),
        result_limit=10,
        pending_action_ttl_seconds=300,
        ip_block_settings=settings,
    )


def _link(operator_id: object, *, telegram_user_id: int) -> None:
    with get_session_factory().begin() as session:
        link_telegram_user(
            session,
            operator_id=operator_id,  # type: ignore[arg-type]
            telegram_user_id=telegram_user_id,
        )


def _propose_callback(
    incident_id: UUID,
    *,
    callback_id: str = "cb-propose-1",
    sender_id: int = TELEGRAM_USER_ID,
    with_message: bool = True,
) -> TelegramCallbackQuery:
    payload: dict[str, object] = {
        "id": callback_id,
        "from": {"id": sender_id, "is_bot": False},
        "data": encode_propose_block(incident_id=incident_id),
    }
    if with_message:
        payload["message"] = {
            "message_id": 1,
            "chat": {"id": sender_id, "type": "private"},
        }
    return TelegramCallbackQuery.model_validate(payload)


def _decide_callback(
    plan_id: UUID,
    *,
    approve: bool,
    callback_id: str,
    sender_id: int,
) -> TelegramCallbackQuery:
    return TelegramCallbackQuery.model_validate(
        {
            "id": callback_id,
            "from": {"id": sender_id, "is_bot": False},
            "message": {
                "message_id": 2,
                "chat": {"id": sender_id, "type": "private"},
            },
            "data": encode_decide_block(plan_id=plan_id, approve=approve),
        }
    )


def _audit_count(action: str, target_id: UUID) -> int:
    with get_session_factory()() as session:
        rows = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action == action,
                AuditLogEntry.target_id == target_id,
            )
        ).all()
        return len(rows)


def test_propose_is_refused_while_the_feature_is_disabled(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)

    answer = _router(settings=_DISABLED_SETTINGS).handle_callback_query(
        _propose_callback(incident_id),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_disabled_text("ru")
    assert answer.follow_up_text is None


def test_propose_without_a_message_is_rejected_safely(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)

    answer = _router().handle_callback_query(
        _propose_callback(incident_id, with_message=False),
        now=NOW,
    )

    assert answer.text == formatting.callback_invalid_text("ru")
    assert answer.follow_up_text is None


def test_propose_requires_permission(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.VIEWER)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)

    answer = _router().handle_callback_query(_propose_callback(incident_id), now=NOW)

    assert answer.text == formatting.callback_forbidden_text("ru")


def test_propose_from_an_unlinked_account_is_refused() -> None:
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})

    answer = _router().handle_callback_query(_propose_callback(incident_id), now=NOW)

    assert answer.text == formatting.callback_unlinked_text("ru")


def test_propose_for_a_missing_incident_reports_not_found(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)

    answer = _router().handle_callback_query(_propose_callback(uuid4()), now=NOW)

    assert answer.text == formatting.incident_not_found_text("ru")


def test_propose_without_a_source_address_is_refused(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"actor": "root"})
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)

    answer = _router().handle_callback_query(_propose_callback(incident_id), now=NOW)

    assert answer.text == formatting.ip_block_no_source_address_text("ru")


def test_propose_for_a_never_block_address_is_refused(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "127.0.0.1"})
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)

    answer = _router().handle_callback_query(_propose_callback(incident_id), now=NOW)

    assert "защищён" in answer.text
    assert answer.follow_up_text is None


def test_propose_creates_a_plan_with_a_follow_up_and_keyboard(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)

    answer = _router().handle_callback_query(_propose_callback(incident_id), now=NOW)

    assert answer.text == formatting.ip_block_proposed_text("ru")
    assert answer.follow_up_text is not None
    assert "8.8.8.8" in answer.follow_up_text
    assert answer.follow_up_keyboard is not None
    buttons = answer.follow_up_keyboard["inline_keyboard"][0]
    assert [button["text"] for button in buttons] == ["Подтвердить", "Отклонить"]

    with get_session_factory()() as session:
        plan = session.scalar(select(IpBlockPlan).where(IpBlockPlan.incident_id == incident_id))
        assert plan is not None
        assert plan.status == "proposed"
    assert _audit_count("ip_block_plan.proposed", plan.id) == 1


def test_second_propose_press_reuses_the_plan_without_a_new_audit_entry(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    _link(operator.operator_id, telegram_user_id=TELEGRAM_USER_ID)
    router = _router()

    first = router.handle_callback_query(
        _propose_callback(incident_id, callback_id="cb-propose-1"), now=NOW
    )
    second = router.handle_callback_query(
        _propose_callback(incident_id, callback_id="cb-propose-2"), now=NOW
    )

    assert first.text == formatting.ip_block_proposed_text("ru")
    assert second.text == formatting.ip_block_reused_text("ru")
    with get_session_factory()() as session:
        plan = session.scalar(select(IpBlockPlan).where(IpBlockPlan.incident_id == incident_id))
        assert plan is not None
    assert _audit_count("ip_block_plan.proposed", plan.id) == 1


def _propose_and_get_plan_id(
    *,
    proposer: RegisteredOperator,
    correlation: dict[str, object] | None = None,
) -> UUID:
    incident_id, _ = _create_incident(correlation=correlation or {"source_ip": "8.8.8.8"})
    _link(proposer.operator_id, telegram_user_id=TELEGRAM_USER_ID)
    _router().handle_callback_query(_propose_callback(incident_id), now=NOW)
    with get_session_factory()() as session:
        plan = session.scalar(select(IpBlockPlan).where(IpBlockPlan.incident_id == incident_id))
        assert plan is not None
        return plan.id


def test_approve_by_a_second_operator_never_claims_execution(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    approver = register_operator(role=OperatorRole.ADMIN)
    plan_id = _propose_and_get_plan_id(proposer=proposer)
    _link(approver.operator_id, telegram_user_id=TELEGRAM_USER_ID_TWO)

    answer = _router().handle_callback_query(
        _decide_callback(
            plan_id, approve=True, callback_id="cb-approve", sender_id=TELEGRAM_USER_ID_TWO
        ),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_approved_text("ru")
    assert "НЕ выполнена" in answer.text
    assert answer.show_alert is False
    with get_session_factory()() as session:
        stored = session.get(IpBlockPlan, plan_id)
        assert stored is not None
        assert stored.status == "approved"


def test_approve_by_the_same_operator_is_refused_by_default(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ADMIN)
    plan_id = _propose_and_get_plan_id(proposer=proposer)

    answer = _router().handle_callback_query(
        _decide_callback(
            plan_id, approve=True, callback_id="cb-approve", sender_id=TELEGRAM_USER_ID
        ),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_same_operator_text("ru")


def test_single_operator_settings_allow_self_approval(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ADMIN)
    plan_id = _propose_and_get_plan_id(proposer=proposer)

    answer = _router(settings=_SINGLE_OPERATOR_SETTINGS).handle_callback_query(
        _decide_callback(
            plan_id, approve=True, callback_id="cb-approve", sender_id=TELEGRAM_USER_ID
        ),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_approved_text("ru")


def test_approve_requires_the_admin_only_permission(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    second_analyst = register_operator(role=OperatorRole.ANALYST)
    plan_id = _propose_and_get_plan_id(proposer=proposer)
    _link(second_analyst.operator_id, telegram_user_id=TELEGRAM_USER_ID_TWO)

    answer = _router().handle_callback_query(
        _decide_callback(
            plan_id, approve=True, callback_id="cb-approve", sender_id=TELEGRAM_USER_ID_TWO
        ),
        now=NOW,
    )

    assert answer.text == formatting.callback_forbidden_text("ru")


def test_reject_only_requires_the_propose_permission(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    plan_id = _propose_and_get_plan_id(proposer=proposer)

    answer = _router().handle_callback_query(
        _decide_callback(
            plan_id, approve=False, callback_id="cb-reject", sender_id=TELEGRAM_USER_ID
        ),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_rejected_text("ru")
    with get_session_factory()() as session:
        stored = session.get(IpBlockPlan, plan_id)
        assert stored is not None
        assert stored.status == "rejected"
    assert _audit_count("ip_block_plan.rejected", plan_id) == 1


def test_decide_is_refused_while_the_feature_is_disabled(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    plan_id = _propose_and_get_plan_id(proposer=proposer)

    answer = _router(settings=_DISABLED_SETTINGS).handle_callback_query(
        _decide_callback(
            plan_id, approve=False, callback_id="cb-reject", sender_id=TELEGRAM_USER_ID
        ),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_disabled_text("ru")


def test_deciding_an_already_decided_plan_is_reported(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    plan_id = _propose_and_get_plan_id(proposer=proposer)
    router = _router()
    router.handle_callback_query(
        _decide_callback(
            plan_id, approve=False, callback_id="cb-reject-1", sender_id=TELEGRAM_USER_ID
        ),
        now=NOW,
    )

    answer = router.handle_callback_query(
        _decide_callback(
            plan_id, approve=False, callback_id="cb-reject-2", sender_id=TELEGRAM_USER_ID
        ),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_already_decided_text("ru")


def test_approve_rechecks_policy_and_reports_auto_rejection(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    approver = register_operator(role=OperatorRole.ADMIN)
    plan_id = _propose_and_get_plan_id(proposer=proposer)
    _link(approver.operator_id, telegram_user_id=TELEGRAM_USER_ID_TWO)
    with get_session_factory().begin() as session:
        add_allowlist_entry(session, cidr="8.0.0.0/8", label="synthetic", reason="now trusted")

    answer = _router().handle_callback_query(
        _decide_callback(
            plan_id, approve=True, callback_id="cb-approve", sender_id=TELEGRAM_USER_ID_TWO
        ),
        now=NOW,
    )

    assert answer.text == formatting.ip_block_now_blocked_text("ru")
    with get_session_factory()() as session:
        stored = session.get(IpBlockPlan, plan_id)
        assert stored is not None
        assert stored.status == "rejected"
