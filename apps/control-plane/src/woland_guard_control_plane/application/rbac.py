"""Central fixed-role authorization matrix for the single-tenant control plane."""

from enum import StrEnum

from woland_guard_control_plane.infrastructure.database.models import OperatorRole


class Permission(StrEnum):
    VIEW_INCIDENTS = "incidents:view"
    TRANSITION_INCIDENTS = "incidents:transition"
    VIEW_AUDIT_LOG = "audit:view"
    MANAGE_OPERATORS = "operators:manage"
    MANAGE_TELEGRAM_DESTINATIONS = "telegram_destinations:manage"


ROLE_PERMISSIONS: dict[OperatorRole, frozenset[Permission]] = {
    OperatorRole.VIEWER: frozenset({Permission.VIEW_INCIDENTS}),
    OperatorRole.ANALYST: frozenset(
        {
            Permission.VIEW_INCIDENTS,
            Permission.TRANSITION_INCIDENTS,
        }
    ),
    OperatorRole.ADMIN: frozenset(Permission),
}


def role_has_permission(role: OperatorRole, permission: Permission) -> bool:
    """Return the single authoritative decision for one role and permission."""

    return permission in ROLE_PERMISSIONS[role]
