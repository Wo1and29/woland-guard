"""Versioned detection rules, incidents, and immutable evidence links."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CHAR,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class IncidentStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class DetectionRuleVersion(Base):
    """Append-only rule definition; activation never rewrites its definition."""

    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="severity_allowed",
        ),
        CheckConstraint("char_length(checksum) = 64", name="checksum_length"),
        CheckConstraint(
            "is_active = false OR activated_at IS NOT NULL",
            name="active_requires_activated_at",
        ),
        UniqueConstraint("rule_key", "version", name="uq_detection_rule_versions_key_version"),
        UniqueConstraint(
            "rule_key",
            "checksum",
            name="uq_detection_rule_versions_key_checksum",
        ),
        Index(
            "uq_detection_rule_versions_active_rule_key",
            "rule_key",
            unique=True,
            postgresql_where=text("is_active = true"),
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    rule_key: Mapped[str] = mapped_column(String(100))
    version: Mapped[int] = mapped_column(Integer)
    schema_version: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean)
    severity: Mapped[str] = mapped_column(String(16))
    checksum: Mapped[str] = mapped_column(CHAR(64))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Incident(Base):
    """One active correlation bucket with an immutable rule snapshot."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="severity_allowed",
        ),
        CheckConstraint(
            "status IN ('new', 'investigating', 'resolved', 'false_positive')",
            name="status_allowed",
        ),
        CheckConstraint("event_count > 0", name="event_count_positive"),
        CheckConstraint("lock_version > 0", name="lock_version_positive"),
        CheckConstraint("char_length(correlation_hash) = 64", name="correlation_hash_length"),
        Index("ix_incidents_server_status_last_seen", "server_id", "status", "last_seen_at"),
        Index("ix_incidents_rule_key_correlation_hash", "rule_key", "correlation_hash"),
        Index("ix_incidents_created_at_id", "created_at", "id"),
        Index(
            "uq_incidents_active_server_rule_version_correlation",
            "server_id",
            "rule_version_id",
            "correlation_hash",
            unique=True,
            postgresql_where=text("status IN ('new', 'investigating')"),
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    server_id: Mapped[UUID] = mapped_column(ForeignKey("servers.id", ondelete="RESTRICT"))
    rule_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("detection_rule_versions.id", ondelete="RESTRICT")
    )
    rule_key: Mapped[str] = mapped_column(String(100))
    rule_version: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(
        String(32),
        default=IncidentStatus.NEW.value,
        server_default=IncidentStatus.NEW.value,
    )
    title: Mapped[str] = mapped_column(String(255))
    explanation: Mapped[str] = mapped_column(String(4_000))
    recommendation: Mapped[str] = mapped_column(String(4_000))
    # Nullable because incidents detected before the rules carried English prose
    # genuinely have no translation; the Dashboard falls back to the Russian
    # column rather than inventing text for historical rows.
    title_en: Mapped[str | None] = mapped_column(String(255), nullable=True)
    explanation_en: Mapped[str | None] = mapped_column(String(4_000), nullable=True)
    recommendation_en: Mapped[str | None] = mapped_column(String(4_000), nullable=True)
    correlation: Mapped[dict[str, Any]] = mapped_column(JSONB)
    correlation_hash: Mapped[str] = mapped_column(CHAR(64))
    rule_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer)
    lock_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )


class IncidentEvent(Base):
    """Unique evidence association between one incident and one stored event."""

    __tablename__ = "incident_events"
    __table_args__ = (
        PrimaryKeyConstraint("incident_id", "event_id", name="pk_incident_events"),
        Index("ix_incident_events_event_id", "event_id"),
        Index(
            "ix_incident_events_incident_linked_event",
            "incident_id",
            "linked_at",
            "event_id",
        ),
    )

    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    event_id: Mapped[UUID] = mapped_column(ForeignKey("events.id", ondelete="RESTRICT"))
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
