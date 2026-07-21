"""PostgreSQL persistence operations for normalized event batches."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from woland_guard_contracts import NormalizedEventV1
from woland_guard_control_plane.infrastructure.database.models import Event


def insert_event_batch(
    session: Session,
    *,
    server_id: UUID,
    events: tuple[NormalizedEventV1, ...],
    persisted_at: datetime,
) -> int:
    """Insert a complete batch idempotently and return the newly stored row count."""

    values: list[dict[str, Any]] = [
        {
            "id": uuid4(),
            "server_id": server_id,
            "agent_event_id": event.event_id,
            "schema_version": event.schema_version,
            "source": event.source.value,
            "event_type": event.event_type,
            "occurred_at": event.occurred_at,
            "collected_at": event.collected_at,
            "persisted_at": persisted_at,
            "payload": event.model_dump(mode="json"),
        }
        for event in events
    ]
    statement = (
        insert(Event)
        .values(values)
        .on_conflict_do_nothing(constraint="uq_events_server_id_agent_event_id")
        .returning(Event.id)
    )
    inserted_ids = session.execute(statement).scalars().all()
    return len(inserted_ids)
