"""Provider-neutral authenticated operator identity."""

from dataclasses import dataclass
from uuid import UUID

from woland_guard_control_plane.infrastructure.database.models import (
    OperatorAuthMethodType,
    OperatorRole,
)


@dataclass(frozen=True, slots=True)
class OperatorPrincipal:
    """Detached identity shared by every human authentication mechanism."""

    operator_id: UUID
    username: str
    role: OperatorRole
    auth_method_type: OperatorAuthMethodType
    auth_method_id: UUID
