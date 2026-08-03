"""Strict allowlisted append-only audit writers for caller-owned transactions."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv6Address, ip_address, ip_network
from types import MappingProxyType
from uuid import UUID

from sqlalchemy.orm import Session

from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.infrastructure.database.models import (
    AuditActorType,
    AuditLogEntry,
    IncidentStatus,
    NotificationAdapterKind,
    NotificationSeverity,
    OperatorAuthMethodType,
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
    BOOLEAN = "boolean"
    NOTIFICATION_ADAPTER_KIND = "notification_adapter_kind"
    NOTIFICATION_SEVERITY = "notification_severity"
    IP_ADDRESS = "ip_address"
    IP_NETWORK = "ip_network"


class IncidentHistoryPolicy(StrEnum):
    """Closed action-specific relationship to immutable incident history."""

    REQUIRED = "required"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True, slots=True)
class AuditActionSpec:
    """Exact actor, target, and required detail schema for one audit action."""

    actor_type: AuditActorType
    target_type: str
    detail_fields: Mapping[str, AuditDetailType]
    allowed_auth_methods: frozenset[OperatorAuthMethodType] = frozenset()
    incident_history_policy: IncidentHistoryPolicy = IncidentHistoryPolicy.FORBIDDEN


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
            allowed_auth_methods=frozenset(OperatorAuthMethodType),
            incident_history_policy=IncidentHistoryPolicy.REQUIRED,
        ),
        "incident.comment_added": AuditActionSpec(
            actor_type=AuditActorType.OPERATOR,
            target_type="incident_comment",
            detail_fields=_fields(incident_id=AuditDetailType.UUID),
            allowed_auth_methods=frozenset(OperatorAuthMethodType),
        ),
        "operator_web_session.started": AuditActionSpec(
            actor_type=AuditActorType.OPERATOR,
            target_type="operator_web_session",
            detail_fields=_fields(),
            allowed_auth_methods=frozenset({OperatorAuthMethodType.OPERATOR_API_KEY}),
        ),
        "operator_web_session.ended": AuditActionSpec(
            actor_type=AuditActorType.OPERATOR,
            target_type="operator_web_session",
            detail_fields=_fields(),
            allowed_auth_methods=frozenset({OperatorAuthMethodType.WEB_SESSION}),
        ),
        "operator_telegram_link.created": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="operator_telegram_link",
            detail_fields=_fields(operator_id=AuditDetailType.UUID),
        ),
        "operator_telegram_link.revoked": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="operator_telegram_link",
            detail_fields=_fields(operator_id=AuditDetailType.UUID),
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
        "notification_destination.created": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="notification_destination",
            detail_fields=_fields(
                adapter_kind=AuditDetailType.NOTIFICATION_ADAPTER_KIND,
                minimum_severity=AuditDetailType.NOTIFICATION_SEVERITY,
            ),
        ),
        "notification_destination.updated": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="notification_destination",
            detail_fields=_fields(
                adapter_kind=AuditDetailType.NOTIFICATION_ADAPTER_KIND,
                from_minimum_severity=AuditDetailType.NOTIFICATION_SEVERITY,
                to_minimum_severity=AuditDetailType.NOTIFICATION_SEVERITY,
                chat_id_changed=AuditDetailType.BOOLEAN,
                token_file_changed=AuditDetailType.BOOLEAN,
            ),
        ),
        "notification_destination.enabled": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="notification_destination",
            detail_fields=_fields(
                adapter_kind=AuditDetailType.NOTIFICATION_ADAPTER_KIND,
                minimum_severity=AuditDetailType.NOTIFICATION_SEVERITY,
            ),
        ),
        "notification_destination.disabled": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="notification_destination",
            detail_fields=_fields(
                adapter_kind=AuditDetailType.NOTIFICATION_ADAPTER_KIND,
                minimum_severity=AuditDetailType.NOTIFICATION_SEVERITY,
            ),
        ),
        "ip_block_plan.proposed": AuditActionSpec(
            actor_type=AuditActorType.OPERATOR,
            target_type="ip_block_plan",
            detail_fields=_fields(
                incident_id=AuditDetailType.UUID,
                ip_address=AuditDetailType.IP_ADDRESS,
            ),
            allowed_auth_methods=frozenset(OperatorAuthMethodType),
        ),
        "ip_block_plan.approved": AuditActionSpec(
            actor_type=AuditActorType.OPERATOR,
            target_type="ip_block_plan",
            detail_fields=_fields(
                ip_address=AuditDetailType.IP_ADDRESS,
                proposed_by_operator_id=AuditDetailType.UUID,
            ),
            allowed_auth_methods=frozenset(OperatorAuthMethodType),
        ),
        "ip_block_plan.rejected": AuditActionSpec(
            actor_type=AuditActorType.OPERATOR,
            target_type="ip_block_plan",
            detail_fields=_fields(
                ip_address=AuditDetailType.IP_ADDRESS,
                proposed_by_operator_id=AuditDetailType.UUID,
            ),
            allowed_auth_methods=frozenset(OperatorAuthMethodType),
        ),
        "ip_block_allowlist.created": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="ip_block_allowlist_entry",
            detail_fields=_fields(cidr=AuditDetailType.IP_NETWORK),
        ),
        "ip_block_allowlist.revoked": AuditActionSpec(
            actor_type=AuditActorType.LOCAL_CLI,
            target_type="ip_block_allowlist_entry",
            detail_fields=_fields(cidr=AuditDetailType.IP_NETWORK),
        ),
    }
)

AuditDetailValue = str | int | bool


def validate_audit_action(
    *,
    action: str,
    actor_type: AuditActorType,
    auth_method_type: OperatorAuthMethodType | None,
    target_type: str,
    details: Mapping[str, object],
) -> dict[str, AuditDetailValue]:
    """Validate one action against the exact registry without reflecting unsafe values."""

    spec = AUDIT_ACTION_REGISTRY.get(action)
    if spec is None:
        raise AuditValidationError("audit action is not allowed")
    if actor_type is not spec.actor_type:
        raise AuditValidationError("audit actor is not allowed for action")
    if actor_type is AuditActorType.OPERATOR:
        if auth_method_type not in spec.allowed_auth_methods:
            raise AuditValidationError("audit authentication method is not allowed for action")
    elif auth_method_type is not None:
        raise AuditValidationError("audit authentication method is not allowed for action")
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
        auth_method_type=None,
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
    actor: OperatorPrincipal,
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
        auth_method_type=actor.auth_method_type,
        target_type=target_type,
        details=details,
    )
    spec = AUDIT_ACTION_REGISTRY[action]
    if spec.incident_history_policy is IncidentHistoryPolicy.REQUIRED:
        if incident_history_id is None or validated_details.get("history_id") != str(
            incident_history_id
        ):
            raise AuditValidationError("audit history reference does not match action schema")
    elif incident_history_id is not None:
        raise AuditValidationError("audit history reference is not allowed for action")
    entry = AuditLogEntry(
        actor_type=AuditActorType.OPERATOR.value,
        operator_id=actor.operator_id,
        actor_username_snapshot=actor.username,
        auth_method_type=actor.auth_method_type.value,
        auth_method_id=actor.auth_method_id,
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
    if detail_type is AuditDetailType.NOTIFICATION_ADAPTER_KIND:
        if type(value) is not str or value not in {kind.value for kind in NotificationAdapterKind}:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if detail_type is AuditDetailType.NOTIFICATION_SEVERITY:
        if type(value) is not str or value not in {
            severity.value for severity in NotificationSeverity
        }:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if detail_type is AuditDetailType.IP_ADDRESS:
        if type(value) is not str:
            raise AuditValidationError("audit detail value is invalid")
        try:
            parsed_address = ip_address(value)
        except ValueError as error:
            raise AuditValidationError("audit detail value is invalid") from error
        if isinstance(parsed_address, IPv6Address) and parsed_address.ipv4_mapped is not None:
            raise AuditValidationError("audit detail value is invalid")
        if str(parsed_address) != value:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if detail_type is AuditDetailType.IP_NETWORK:
        if type(value) is not str:
            raise AuditValidationError("audit detail value is invalid")
        try:
            parsed_network = ip_network(value)
        except ValueError as error:
            raise AuditValidationError("audit detail value is invalid") from error
        if str(parsed_network) != value:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if detail_type is AuditDetailType.BOOLEAN:
        if type(value) is not bool:
            raise AuditValidationError("audit detail value is invalid")
        return value
    if type(value) is not int or not 1 <= value <= _MAX_DATABASE_INTEGER:
        raise AuditValidationError("audit detail value is invalid")
    return value
