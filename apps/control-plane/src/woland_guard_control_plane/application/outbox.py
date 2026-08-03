"""Safe incident notification envelopes and atomic outbox production."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.infrastructure.database.models import (
    Incident,
    NotificationDestination,
    OutboxMessage,
)

INCIDENT_CREATED_NOTIFICATION = "incident.created"
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class IncidentCreatedNotificationV1(BaseModel):
    """Strict immutable payload that cannot include event or correlation data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    notification_type: Literal["incident.created"] = "incident.created"
    incident_id: UUID
    server_id: UUID
    rule_key: str = Field(min_length=1, max_length=100)
    rule_version: int = Field(gt=0)
    severity: Literal["low", "medium", "high", "critical"]
    title: str = Field(min_length=1, max_length=255)
    # Optional so messages enqueued before the rules carried English prose still
    # validate when the worker picks them up after an upgrade; the renderer falls
    # back to the Russian title (ADR-0017).
    title_en: str | None = Field(default=None, min_length=1, max_length=255)
    created_at: datetime

    @field_validator("rule_key", "title", "title_en")
    @classmethod
    def reject_nul(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("notification text contains a forbidden character")
        return value

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("notification timestamp must include a timezone")
        return value


def build_incident_created_payload(incident: Incident) -> IncidentCreatedNotificationV1:
    """Build an allowlisted snapshot exclusively from safe incident metadata."""

    return IncidentCreatedNotificationV1(
        incident_id=incident.id,
        server_id=incident.server_id,
        rule_key=incident.rule_key,
        rule_version=incident.rule_version,
        severity=incident.severity,  # type: ignore[arg-type]
        title=incident.title,
        title_en=incident.title_en,
        created_at=incident.created_at,
    )


def outbox_idempotency_key(*, incident_id: UUID, destination_id: UUID) -> str:
    """Return a transparent canonical key containing no credentials."""

    return f"{INCIDENT_CREATED_NOTIFICATION}:{incident_id}:{destination_id}"


def enqueue_incident_created_notifications(
    session: Session,
    *,
    incident: Incident,
    max_attempts: int = 5,
) -> int:
    """Add one outbox row per enabled destination passing the severity threshold."""

    if not 1 <= max_attempts <= 20:
        raise ValueError("outbox max attempts must be between 1 and 20")
    incident_rank = _SEVERITY_RANK[incident.severity]
    destinations = session.scalars(
        select(NotificationDestination)
        .where(NotificationDestination.enabled.is_(True))
        .order_by(NotificationDestination.id)
    ).all()
    eligible = [
        destination
        for destination in destinations
        if _SEVERITY_RANK[destination.minimum_severity] <= incident_rank
    ]
    if not eligible:
        return 0

    payload = build_incident_created_payload(incident).model_dump(mode="json")
    for destination in eligible:
        session.add(
            OutboxMessage(
                notification_type=INCIDENT_CREATED_NOTIFICATION,
                incident_id=incident.id,
                destination_id=destination.id,
                payload_schema_version=1,
                payload=payload,
                idempotency_key=outbox_idempotency_key(
                    incident_id=incident.id,
                    destination_id=destination.id,
                ),
                max_attempts=max_attempts,
            )
        )
    return len(eligible)
