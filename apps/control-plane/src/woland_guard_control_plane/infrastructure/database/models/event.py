"""Normalized event persistence model."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class Event(Base):
    """An immutable normalized event accepted from a registered server."""

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint(
            "server_id",
            "agent_event_id",
            name="uq_events_server_id_agent_event_id",
        ),
        Index("ix_events_server_id_occurred_at", "server_id", "occurred_at"),
        Index("ix_events_event_type_occurred_at", "event_type", "occurred_at"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    server_id: Mapped[UUID] = mapped_column(ForeignKey("servers.id", ondelete="RESTRICT"))
    agent_event_id: Mapped[UUID]
    schema_version: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(100))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    persisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
