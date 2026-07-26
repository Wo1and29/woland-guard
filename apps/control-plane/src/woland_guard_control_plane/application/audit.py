"""Strict allowlisted append-only audit writers for caller-owned transactions."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from sqlalchemy.orm import Session

from woland_guard_control_plane.application.operator_authentication import AuthenticatedOperator
from woland_guard_control_plane.infrastructure.database.models import (
    AuditActorType,
    AuditLogEntry,
    IncidentStatus,
    OperatorRole,
)

_MAX_DATABASE_INTEGER = 2_147_483_647
_FORBIDDEN_DETAIL_FIELDS = frozenset(
    {
        "authorization",
        "credential",
        "event_payload",
        "request_body",
        "secret",
        "token",
    }
)


class AuditValidationError(ValueError):
    """A safe audit schema error that never reflects client-controlled values."""


class AuditDetailType(StrEnum):
    """Closed set of scalar validators allowed in audit details."""

    UUID = "canonical_uuid"
    OPERATOR_ROLE = "operator_role"
    INCIDENT_STATUS = "incident_status"
    POSITIVE_INTEGER = "positive_integer"


@dataclass(frozen=True, slots=True)
class AuditActionSpec:
    """Exact actor, target, and required detail schema for one audit action."""

    actor_type: AuditActorType
    target_type: str
    detail_fields: Mapping[str, AuditDetailType]


def _fields(**fields: AuditDetailType) -> Mapping[str, AuditDetailType]:
    return MappingProxyType(fields)


AUDIT_ACTION_REGISTRY: Mapping[str, AuditActionSpec] = MappingProxyType(
    {
        "operator.created": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="operator",
            detail_fields=_fields(role=AuditDetailType.OPERATOR_ROLE),
        ),
        "operator_api_key.issued": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="operator_api_key",
            detail_fields=_fields(operator_id=AuditDetailType.UUID),
        ),
        "operator_api_key.rotated": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="operator_api_key",
            detail_fields=_fields(
                operator_id=AuditDetailType.UUID,
                replaced_key_id=AuditDetailType.UUID,
            ),
        ),
        "operator_api_key.revoked": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="operator_api_key",
            detail_fields=_fields(operator_id=AuditDetailType.UUID),
        ),
        "incident.status_changed": AuditActionSpec(
            actor_type=AuditActorType.OPERATOR,
            target_type="incident",
            detail_fields=_fields(
                from_status=AuditDetailType.INCIDENT_STATUS,
                from_version=AuditDetailType.POSITIVE_INTEGER,
                history_id=AuditDetailType.UUID,
                to_status=AuditDetailType.INCIDENT_STATUS,
                to_version=AuditDetailType.POSITIVE_INTEGER,
            ),
        ),
        "outbox.failed_requeued": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="outbox_message",
            detail_fields=_fields(
                from_attempt_count=AuditDetailType.POSITIVE_INTEGER,
                from_max_attempts=AuditDetailType.POSITIVE_INTEGER,
                to_max_attempts=AuditDetailType.POSITIVE_INTEGER,
            ),
        ),
    }
)

AuditDetailValue = str | int


def validate_audit_action(
    *,
    action: str,
    actor_type: AuditActorType,
    target_type: str,
    details: Mapping[str, object],
) -> dict[str, AuditDetailValue]:
    """Validate one action against the exact registry without reflecting unsafe values."""

    spec = AUDIT_ACTION_REGISTRY.get(action)
    if spec is None:
        raise AuditValidationError("audit action is not allowed")
    if actor_type is not spec.actor_type:
        raise AuditValidationError("audit actor is not allowed for action")
    if target_type != spec.target_type:
        raise AuditValidationError("audit target type is not allowed for action")
    supplied_fields = set(details)
    if any(
        not isinstance(field, str) or field.casefold() in _FORBIDDEN_DETAIL_FIELDS
        for field in supplied_fields
    ):
        raise AuditValidationError("audit details do not match action schema")
    if supplied_fields != set(spec.detail_fields):
        raise AuditValidationError("audit details do not match action schema")

    validated: dict[str, AuditDetailValue] = {}
    for field, detail_type in spec.detail_fields.items():
        validated[field] = _validate_detail_value(details[field], detail_type)
    return validated


def record_local_cli_action(
    session: Session,
    *,
    action: str,
    target_type: str,
    target_id: UUID,
    details: Mapping[str, object],
) -> AuditLogEntry:
    """Record one validated local operation without collecting OS identity data."""

    validated_details = validate_audit_action(
        action=action,
        actor_type=AuditActorType.LOCAL_CLI,
        target_type=target_type,
        details=details,
    )
    entry = AuditLogEntry(
        actor_type=AuditActorType.LOCAL_CLI.value,
        operator_id=None,
        actor_username_snapshot=None,
        auth_method_type=None,
        auth_method_id=None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        incident_history_id=None,
        request_id=None,
        details=validated_details,
    )
    session.add(entry)
    return entry


def record_operator_action(
    session: Session,
    *,
    actor: AuthenticatedOperator,
    action: str,
    target_type: str,
    target_id: UUID,
    request_id: str,
    incident_history_id: UUID | None,
    details: Mapping[str, object],
) -> AuditLogEntry:
    """Record one validated authenticated action with a generic auth-method snapshot."""

    validated_details = validate_audit_action(
        action=action,
        actor_type=AuditActorType.OPERATOR,
        target_type=target_type,
        details=details,
    )
    if incident_history_id is None or validated_details.get("history_id") != str(
        incident_history_id
    ):
        raise AuditValidationError("audit history reference does not match action schema")
    entry = AuditLogEntry(
        actor_type=AuditActorType.OPERATOR.value,
        operator_id=actor.operator_id,
        actor_username_snapshot=actor.username,
        auth_method_type="operator_api_key",
        auth_method_id=actor.key_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        incident_history_id=incident_history_id,
        request_id=request_id,
        details=validated_details,
    )
    session.add(entry)
    return entry


def _validate_detail_value(
    value: object,
    detail_type: AuditDetailType,
) -> AuditDetailValue:
    if detail_type is AuditDetailType.UUID:
        if type(value) is not str:
            raise AuditValidationError("audit detail value is invalid")
        try:
            parsed = UUID(value)
        except ValueError as error:
            raise AuditValidationError("audit detail value is invalid") from error
        if str(parsed) != value:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if detail_type is AuditDetailType.OPERATOR_ROLE:
        if type(value) is not str or value not in {role.value for role in OperatorRole}:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if detail_type is AuditDetailType.INCIDENT_STATUS:
        if type(value) is not str or value not in {status.value for status in IncidentStatus}:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if type(value) is not int or not 1 <= value <= _MAX_DATABASE_INTEGER:
        raise AuditValidationError("audit detail value is invalid")
    return value
