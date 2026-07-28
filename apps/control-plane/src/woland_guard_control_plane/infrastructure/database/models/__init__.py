"""Database models registered in the control-plane metadata."""

from woland_guard_control_plane.infrastructure.database.models.detection import (
    DetectionRuleVersion,
    Incident,
    IncidentEvent,
    IncidentStatus,
)
from woland_guard_control_plane.infrastructure.database.models.event import Event
from woland_guard_control_plane.infrastructure.database.models.operator import (
    Operator,
    OperatorApiKey,
    OperatorAuthMethodType,
    OperatorRole,
)
from woland_guard_control_plane.infrastructure.database.models.outbox import (
    NotificationAdapterKind,
    NotificationDestination,
    NotificationSeverity,
    OutboxErrorCode,
    OutboxMessage,
    OutboxStatus,
)
from woland_guard_control_plane.infrastructure.database.models.server import AgentApiKey, Server
from woland_guard_control_plane.infrastructure.database.models.telegram import (
    TelegramDestinationConfig,
)
from woland_guard_control_plane.infrastructure.database.models.web_session import (
    OperatorWebSession,
)
from woland_guard_control_plane.infrastructure.database.models.workflow import (
    AuditActorType,
    AuditLogEntry,
    HistoryEntryType,
    IncidentHistoryEntry,
    OperatorIdempotencyRecord,
)

__all__ = [
    "AgentApiKey",
    "AuditActorType",
    "AuditLogEntry",
    "DetectionRuleVersion",
    "Event",
    "Incident",
    "IncidentEvent",
    "IncidentHistoryEntry",
    "IncidentStatus",
    "HistoryEntryType",
    "NotificationAdapterKind",
    "NotificationDestination",
    "NotificationSeverity",
    "Operator",
    "OperatorApiKey",
    "OperatorAuthMethodType",
    "OperatorIdempotencyRecord",
    "OperatorRole",
    "OperatorWebSession",
    "OutboxErrorCode",
    "OutboxMessage",
    "OutboxStatus",
    "Server",
    "TelegramDestinationConfig",
]
