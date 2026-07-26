"""Immutable incident history, audit, and operator-scoped idempotency records."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class HistoryEntryType(StrEnum):
    BASELINE = "baseline"
    STATUS_TRANSITION = "status_transition"


class AuditActorType(StrEnum):
    OPERATOR = "operator"
    LOCAL_CLI = "local_cli"


class IncidentHistoryEntry(Base):
    """Append-only versioned status history for one incident."""

    __tablename__ = "incident_history"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "entry_type IN ('baseline', 'status_transition')",
            name="entry_type_allowed",
        ),
        CheckConstraint(
            "to_status IN ('new', 'investigating', 'resolved', 'false_positive')",
            name="to_status_allowed",
        ),
        CheckConstraint(
            "from_status IS NULL OR "
            "from_status IN ('new', 'investigating', 'resolved', 'false_positive')",
            name="from_status_allowed",
        ),
        CheckConstraint(
            "reason IS NULL OR (char_length(reason) BETWEEN 1 AND 1000)",
            name="reason_length",
        ),
        CheckConstraint(
            "entry_type = 'baseline' OR "
            "to_status NOT IN ('resolved', 'false_positive') OR reason IS NOT NULL",
            name="terminal_transition_requires_reason",
        ),
        CheckConstraint(
            "(entry_type = 'baseline' AND version = 1 AND from_status IS NULL "
            "AND reason IS NULL AND changed_by_operator_id IS NULL "
            "AND actor_username_snapshot IS NULL AND auth_method_type IS NULL "
            "AND auth_method_id IS NULL) OR "
            "(entry_type = 'status_transition' AND version > 1 AND from_status IS NOT NULL "
            "AND changed_by_operator_id IS NOT NULL AND actor_username_snapshot IS NOT NULL "
            "AND auth_method_type IS NOT NULL AND auth_method_id IS NOT NULL)",
            name="entry_shape",
        ),
        UniqueConstraint("incident_id", "version", name="uq_incident_history_incident_version"),
        Index("ix_incident_history_incident_version", "incident_id", "version"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    version: Mapped[int] = mapped_column(Integer)
    entry_type: Mapped[str] = mapped_column(String(32))
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(String(1_000), nullable=True)
    changed_by_operator_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"),
        nullable=True,
    )
    actor_username_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_method_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    auth_method_id: Mapped[UUID | None] = mapped_column(nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )


class AuditLogEntry(Base):
    """Append-only allowlisted record of one successful administrative action."""

    __tablename__ = "audit_log_entries"
    __table_args__ = (
        CheckConstraint("actor_type IN ('operator', 'local_cli')", name="actor_type_allowed"),
        CheckConstraint(
            "(actor_type = 'local_cli' AND operator_id IS NULL "
            "AND actor_username_snapshot IS NULL AND auth_method_type IS NULL "
            "AND auth_method_id IS NULL) OR "
            "(actor_type = 'operator' AND operator_id IS NOT NULL "
            "AND actor_username_snapshot IS NOT NULL AND auth_method_type IS NOT NULL "
            "AND auth_method_id IS NOT NULL)",
            name="actor_shape",
        ),
        CheckConstraint("action ~ '^[a-z][a-z0-9_.]{2,63}$'", name="action_format"),
        CheckConstraint(
            "target_type ~ '^[a-z][a-z0-9_]{2,31}$'",
            name="target_type_format",
        ),
        UniqueConstraint(
            "incident_history_id",
            name="uq_audit_log_entries_incident_history_id",
        ),
        Index("ix_audit_log_entries_created_id", "created_at", "id"),
        Index("ix_audit_log_entries_operator_created", "operator_id", "created_at", "id"),
        Index(
            "ix_audit_log_entries_target_created",
            "target_type",
            "target_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    actor_type: Mapped[str] = mapped_column(String(32))
    operator_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"),
        nullable=True,
    )
    actor_username_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_method_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    auth_method_id: Mapped[UUID | None] = mapped_column(nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[UUID]
    incident_history_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("incident_history.id", ondelete="RESTRICT"),
        nullable=True,
    )
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )


class OperatorIdempotencyRecord(Base):
    """Immutable completed business result scoped to one operator and client key."""

    __tablename__ = "operator_idempotency_records"
    __table_args__ = (
        CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name="key_format",
        ),
        CheckConstraint(
            "canonical_request_hash ~ '^[0-9a-f]{64}$'",
            name="request_hash_format",
        ),
        CheckConstraint("response_status IN (200, 404, 409)", name="response_status_allowed"),
        UniqueConstraint(
            "operator_id",
            "idempotency_key",
            name="uq_operator_idempotency_records_operator_key",
        ),
        Index("ix_operator_idempotency_records_created_id", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operator_id: Mapped[UUID] = mapped_column(ForeignKey("operators.id", ondelete="RESTRICT"))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    operation: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[UUID]
    canonical_request_hash: Mapped[str] = mapped_column(String(64))
    response_status: Mapped[int] = mapped_column(SmallInteger)
    response_body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
