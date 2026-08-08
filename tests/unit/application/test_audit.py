"""Unit tests for the centralized audit action allowlist."""

from collections.abc import Mapping
from unittest.mock import Mock
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import (
    AUDIT_ACTION_REGISTRY,
    AuditValidationError,
    record_local_cli_action,
    record_operator_action,
    validate_audit_action,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.infrastructure.database.models import (
    AuditActorType,
    OperatorAuthMethodType,
    OperatorRole,
)

_OPERATOR_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
_KEY_ID = "11111111-2222-4333-8444-555555555555"
_HISTORY_ID = "99999999-8888-4777-8666-555555555555"

_ALLOWED_ACTIONS: tuple[tuple[str, AuditActorType, str, Mapping[str, object]], ...] = (
    (
        "operator.created",
        AuditActorType.LOCAL_CLI,
        "operator",
        {"role": "admin"},
    ),
    (
        "operator_api_key.issued",
        AuditActorType.LOCAL_CLI,
        "operator_api_key",
        {"operator_id": _OPERATOR_ID},
    ),
    (
        "operator_api_key.rotated",
        AuditActorType.LOCAL_CLI,
        "operator_api_key",
        {"operator_id": _OPERATOR_ID, "replaced_key_id": _KEY_ID},
    ),
    (
        "operator_api_key.revoked",
        AuditActorType.LOCAL_CLI,
        "operator_api_key",
        {"operator_id": _OPERATOR_ID},
    ),
    (
        "incident.status_changed",
        AuditActorType.OPERATOR,
        "incident",
        {
            "from_status": "new",
            "from_version": 1,
            "history_id": _HISTORY_ID,
            "to_status": "investigating",
            "to_version": 2,
        },
    ),
    (
        "incident.comment_added",
        AuditActorType.OPERATOR,
        "incident_comment",
        {"incident_id": _OPERATOR_ID},
    ),
    (
        "operator_web_session.started",
        AuditActorType.OPERATOR,
        "operator_web_session",
        {},
    ),
    (
        "operator_web_session.ended",
        AuditActorType.OPERATOR,
        "operator_web_session",
        {},
    ),
    (
        "operator_telegram_link.created",
        AuditActorType.LOCAL_CLI,
        "operator_telegram_link",
        {"operator_id": _OPERATOR_ID},
    ),
    (
        "operator_telegram_link.revoked",
        AuditActorType.LOCAL_CLI,
        "operator_telegram_link",
        {"operator_id": _OPERATOR_ID},
    ),
    (
        "outbox.failed_requeued",
        AuditActorType.LOCAL_CLI,
        "outbox_message",
        {
            "from_attempt_count": 5,
            "from_max_attempts": 5,
            "to_max_attempts": 6,
        },
    ),
    (
        "notification_destination.created",
        AuditActorType.LOCAL_CLI,
        "notification_destination",
        {"adapter_kind": "telegram", "minimum_severity": "high"},
    ),
    (
        "notification_destination.updated",
        AuditActorType.LOCAL_CLI,
        "notification_destination",
        {
            "adapter_kind": "telegram",
            "from_minimum_severity": "high",
            "to_minimum_severity": "critical",
            "chat_id_changed": False,
            "token_file_changed": True,
        },
    ),
    (
        "notification_destination.enabled",
        AuditActorType.LOCAL_CLI,
        "notification_destination",
        {"adapter_kind": "telegram", "minimum_severity": "critical"},
    ),
    (
        "notification_destination.disabled",
        AuditActorType.LOCAL_CLI,
        "notification_destination",
        {"adapter_kind": "telegram", "minimum_severity": "critical"},
    ),
    (
        "notification_destination.disabled_by_operator",
        AuditActorType.OPERATOR,
        "notification_destination",
        {"adapter_kind": "telegram", "minimum_severity": "critical"},
    ),
    (
        "notification_destination.minimum_severity_changed_by_operator",
        AuditActorType.OPERATOR,
        "notification_destination",
        {
            "adapter_kind": "telegram",
            "from_minimum_severity": "critical",
            "to_minimum_severity": "high",
        },
    ),
    (
        "ip_block_plan.proposed",
        AuditActorType.OPERATOR,
        "ip_block_plan",
        {"incident_id": _OPERATOR_ID, "ip_address": "203.0.113.10"},
    ),
    (
        "ip_block_plan.approved",
        AuditActorType.OPERATOR,
        "ip_block_plan",
        {"ip_address": "2001:db8::10", "proposed_by_operator_id": _OPERATOR_ID},
    ),
    (
        "ip_block_plan.rejected",
        AuditActorType.OPERATOR,
        "ip_block_plan",
        {"ip_address": "203.0.113.10", "proposed_by_operator_id": _OPERATOR_ID},
    ),
    (
        "ip_block_allowlist.created",
        AuditActorType.LOCAL_CLI,
        "ip_block_allowlist_entry",
        {"cidr": "203.0.113.0/24"},
    ),
    (
        "ip_block_allowlist.revoked",
        AuditActorType.LOCAL_CLI,
        "ip_block_allowlist_entry",
        {"cidr": "203.0.113.0/24"},
    ),
)


@pytest.mark.parametrize(("action", "actor_type", "target_type", "details"), _ALLOWED_ACTIONS)
def test_all_registered_actions_accept_only_their_exact_schema(
    action: str,
    actor_type: AuditActorType,
    target_type: str,
    details: Mapping[str, object],
) -> None:
    assert (
        validate_audit_action(
            action=action,
            actor_type=actor_type,
            auth_method_type=_auth_method_for(action, actor_type),
            target_type=target_type,
            details=details,
        )
        == details
    )


def test_registry_contains_exactly_the_supported_actions() -> None:
    assert set(AUDIT_ACTION_REGISTRY) == {item[0] for item in _ALLOWED_ACTIONS}


@pytest.mark.parametrize(
    ("action", "actor_type", "target_type", "details"),
    [
        (
            "unknown.action",
            AuditActorType.LOCAL_CLI,
            "operator",
            {"role": "admin"},
        ),
        (
            "operator.created",
            AuditActorType.OPERATOR,
            "operator",
            {"role": "admin"},
        ),
        (
            "operator.created",
            AuditActorType.LOCAL_CLI,
            "operator_api_key",
            {"role": "admin"},
        ),
        (
            "operator.created",
            AuditActorType.LOCAL_CLI,
            "operator",
            {},
        ),
        (
            "operator.created",
            AuditActorType.LOCAL_CLI,
            "operator",
            {"role": "admin", "extra": "value"},
        ),
        (
            "operator.created",
            AuditActorType.LOCAL_CLI,
            "operator",
            {"role": "admin", "token": "never-reflect-this-token"},
        ),
        (
            "operator.created",
            AuditActorType.LOCAL_CLI,
            "operator",
            {"role": "admin", "secret": "never-reflect-this-secret"},
        ),
        (
            "operator_api_key.issued",
            AuditActorType.LOCAL_CLI,
            "operator_api_key",
            {"operator_id": _OPERATOR_ID.upper()},
        ),
        (
            "incident.status_changed",
            AuditActorType.OPERATOR,
            "incident",
            {
                "from_status": "new",
                "from_version": True,
                "history_id": _HISTORY_ID,
                "to_status": "resolved",
                "to_version": 2,
            },
        ),
        (
            "operator.created",
            AuditActorType.LOCAL_CLI,
            "operator",
            {"role": "owner"},
        ),
        (
            "incident.status_changed",
            AuditActorType.OPERATOR,
            "incident",
            {
                "from_status": "unknown",
                "from_version": 1,
                "history_id": _HISTORY_ID,
                "to_status": "resolved",
                "to_version": 2,
            },
        ),
        (
            "ip_block_plan.proposed",
            AuditActorType.OPERATOR,
            "ip_block_plan",
            {"incident_id": _OPERATOR_ID, "ip_address": "not-an-address"},
        ),
        (
            "ip_block_plan.proposed",
            AuditActorType.OPERATOR,
            "ip_block_plan",
            {"incident_id": _OPERATOR_ID, "ip_address": "::ffff:203.0.113.5"},
        ),
        (
            "ip_block_allowlist.created",
            AuditActorType.LOCAL_CLI,
            "ip_block_allowlist_entry",
            {"cidr": "203.0.113.5/24"},
        ),
        (
            "ip_block_allowlist.created",
            AuditActorType.LOCAL_CLI,
            "ip_block_allowlist_entry",
            {"cidr": "not-a-network"},
        ),
    ],
)
def test_invalid_audit_payloads_are_rejected_without_reflecting_values(
    action: str,
    actor_type: AuditActorType,
    target_type: str,
    details: Mapping[str, object],
) -> None:
    with pytest.raises(AuditValidationError) as captured:
        validate_audit_action(
            action=action,
            actor_type=actor_type,
            auth_method_type=_auth_method_for(action, actor_type),
            target_type=target_type,
            details=details,
        )

    message = str(captured.value)
    assert "never-reflect" not in message
    assert all(str(value) not in message for value in details.values())


def test_writer_does_not_add_model_after_validation_error() -> None:
    session = Mock(spec=Session)

    with pytest.raises(AuditValidationError):
        record_local_cli_action(
            session,
            action="operator.created",
            target_type="operator",
            target_id=UUID(_OPERATOR_ID),
            details={"role": "admin", "token": "synthetic-forbidden-value"},
        )

    session.add.assert_not_called()


def test_operator_actions_enforce_auth_method_and_history_policy_before_add() -> None:
    session = Mock(spec=Session)
    api_key_principal = OperatorPrincipal(
        operator_id=UUID(_OPERATOR_ID),
        username="synthetic-operator",
        role=OperatorRole.ADMIN,
        auth_method_type=OperatorAuthMethodType.OPERATOR_API_KEY,
        auth_method_id=UUID(_KEY_ID),
    )
    web_principal = OperatorPrincipal(
        operator_id=api_key_principal.operator_id,
        username=api_key_principal.username,
        role=api_key_principal.role,
        auth_method_type=OperatorAuthMethodType.WEB_SESSION,
        auth_method_id=UUID(_HISTORY_ID),
    )

    with pytest.raises(AuditValidationError):
        record_operator_action(
            session,
            actor=web_principal,
            action="operator_web_session.started",
            target_type="operator_web_session",
            target_id=UUID(_HISTORY_ID),
            request_id="safe-request",
            incident_history_id=None,
            details={},
        )
    with pytest.raises(AuditValidationError):
        record_operator_action(
            session,
            actor=api_key_principal,
            action="operator_web_session.started",
            target_type="operator_web_session",
            target_id=UUID(_HISTORY_ID),
            request_id="safe-request",
            incident_history_id=UUID(_HISTORY_ID),
            details={},
        )
    with pytest.raises(AuditValidationError):
        record_operator_action(
            session,
            actor=api_key_principal,
            action="incident.status_changed",
            target_type="incident",
            target_id=UUID(_OPERATOR_ID),
            request_id="safe-request",
            incident_history_id=None,
            details={
                "from_status": "new",
                "from_version": 1,
                "history_id": _HISTORY_ID,
                "to_status": "investigating",
                "to_version": 2,
            },
        )

    session.add.assert_not_called()


def _auth_method_for(
    action: str,
    actor_type: AuditActorType,
) -> OperatorAuthMethodType | None:
    if actor_type is AuditActorType.LOCAL_CLI:
        return None
    if action in {
        "operator_web_session.ended",
        "notification_destination.disabled_by_operator",
        "notification_destination.minimum_severity_changed_by_operator",
    }:
        return OperatorAuthMethodType.WEB_SESSION
    return OperatorAuthMethodType.OPERATOR_API_KEY
