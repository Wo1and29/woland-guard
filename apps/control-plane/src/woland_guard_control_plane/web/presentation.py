"""Safe presentation-only projections for Dashboard templates."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from woland_guard_control_plane.application.audit import (
    AUDIT_ACTION_REGISTRY,
    AuditValidationError,
    validate_audit_action,
)
from woland_guard_control_plane.application.audit_queries import AuditDashboardEntry
from woland_guard_control_plane.infrastructure.database.models import (
    AuditActorType,
    OperatorAuthMethodType,
)

AUDIT_DETAILS_UNAVAILABLE = "Детали недоступны"


@dataclass(frozen=True, slots=True)
class AuditEntryView:
    id: str
    actor: str
    action: str
    target: str
    request_id: str
    created_at: str
    details: tuple[tuple[str, str], ...] | None


def utc_text(value: datetime | None) -> str:
    if value is None:
        return "Нет данных"
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dashboard timestamps require timezone")
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def audit_entry_view(entry: AuditDashboardEntry) -> AuditEntryView:
    """Revalidate details; a corrupt row keeps metadata but loses all detail values."""

    details: tuple[tuple[str, str], ...] | None = None
    try:
        if not isinstance(entry.details, Mapping) or any(
            type(key) is not str for key in entry.details
        ):
            raise AuditValidationError("invalid audit details")
        actor_type = AuditActorType(entry.actor_type)
        auth_method = (
            None
            if entry.auth_method_type is None
            else OperatorAuthMethodType(entry.auth_method_type)
        )
        validated = validate_audit_action(
            action=entry.action,
            actor_type=actor_type,
            auth_method_type=auth_method,
            target_type=entry.target_type,
            details=dict(entry.details),
        )
        spec = AUDIT_ACTION_REGISTRY[entry.action]
        details = tuple((field, _display_scalar(validated[field])) for field in spec.detail_fields)
    except (AuditValidationError, KeyError, ValueError):
        details = None
    actor = entry.actor_username or ("Локальный CLI" if entry.actor_type == "local_cli" else "—")
    return AuditEntryView(
        id=str(entry.id),
        actor=actor,
        action=entry.action,
        target=f"{entry.target_type}:{entry.target_id}",
        request_id=entry.request_id or "—",
        created_at=utc_text(entry.created_at),
        details=details,
    )


def _display_scalar(value: str | int | bool) -> str:
    if type(value) is bool:
        return "да" if value else "нет"
    return str(value)
