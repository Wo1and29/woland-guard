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
    validate_audit_action,
)
from woland_guard_control_plane.infrastructure.database.models import AuditActorType

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
