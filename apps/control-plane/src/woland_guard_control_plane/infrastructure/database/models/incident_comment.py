"""Append-only operator comments attached to incidents."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class IncidentComment(Base):
    """One immutable normalized comment with authenticated actor provenance."""

    __tablename__ = "incident_comments"
    __table_args__ = (
        CheckConstraint(
            "char_length(body) BETWEEN 1 AND 1000",
            name="body_length",
        ),
        CheckConstraint(
            "auth_method_type IN ('operator_api_key', 'web_session')",
            name="auth_method_type_allowed",
        ),
        Index(
            "ix_incident_comments_incident_created_id",
            "incident_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    operator_id: Mapped[UUID] = mapped_column(ForeignKey("operators.id", ondelete="RESTRICT"))
    actor_username_snapshot: Mapped[str] = mapped_column(String(64))
    auth_method_type: Mapped[str] = mapped_column(String(32))
    auth_method_id: Mapped[UUID]
    request_id: Mapped[str] = mapped_column(String(64))
    body: Mapped[str] = mapped_column(String(1_000))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
