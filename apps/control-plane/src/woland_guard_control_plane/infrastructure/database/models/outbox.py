"""Provider-neutral notification destinations and transactional outbox persistence."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class NotificationAdapterKind(StrEnum):
    """Production adapter identifiers reserved by the provider-neutral foundation."""

    TELEGRAM = "telegram"


class NotificationSeverity(StrEnum):
    """Shared routing threshold values."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OutboxStatus(StrEnum):
    """Lifecycle states required for reliable notification delivery."""

    PENDING = "pending"
    PROCESSING = "processing"
    DELIVERED = "delivered"
    FAILED = "failed"


class OutboxErrorCode(StrEnum):
    """Closed, non-sensitive failure classifications persisted by the worker."""

    ADAPTER_UNEXPECTED_ERROR = "adapter_unexpected_error"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    DESTINATION_DISABLED = "destination_disabled"
    DESTINATION_UNCONFIGURED = "destination_unconfigured"
    LEASE_EXPIRED = "lease_expired"
    PAYLOAD_INVALID = "payload_invalid"
    PERMANENT_DELIVERY_ERROR = "permanent_delivery_error"
    RETRYABLE_DELIVERY_ERROR = "retryable_delivery_error"
    TELEGRAM_PROTOCOL_ERROR = "telegram_protocol_error"
    TELEGRAM_RUNTIME_COPY_INVALID = "telegram_runtime_copy_invalid"
    TELEGRAM_RUNTIME_COPY_UNAVAILABLE = "telegram_runtime_copy_unavailable"
    TELEGRAM_STAGING_FILE_INVALID = "telegram_staging_file_invalid"
    TELEGRAM_STAGING_FILE_MISSING = "telegram_staging_file_missing"


class NotificationDestination(Base):
    """Provider-neutral routing policy separated from provider-specific configuration."""

    __tablename__ = "notification_destinations"
    __table_args__ = (
        CheckConstraint("adapter_kind IN ('telegram')", name="adapter_kind_allowed"),
        CheckConstraint(
            "minimum_severity IN ('low', 'medium', 'high', 'critical')",
            name="minimum_severity_allowed",
        ),
        Index("ix_notification_destinations_enabled_severity", "enabled", "minimum_severity"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    adapter_kind: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    minimum_severity: Mapped[str] = mapped_column(
        String(16),
        default=NotificationSeverity.LOW.value,
        server_default=NotificationSeverity.LOW.value,
    )
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


class OutboxMessage(Base):
    """An immutable notification envelope with mutable delivery lifecycle fields."""

    __tablename__ = "outbox_messages"
    __table_args__ = (
        CheckConstraint("notification_type = 'incident.created'", name="notification_type_allowed"),
        CheckConstraint("payload_schema_version = 1", name="payload_schema_version_allowed"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload_is_object"),
        CheckConstraint(
            "status IN ('pending', 'processing', 'delivered', 'failed')",
            name="status_allowed",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= max_attempts",
            name="attempt_count_range",
        ),
        CheckConstraint("max_attempts BETWEEN 1 AND 20", name="max_attempts_range"),
        CheckConstraint(
            "claim_token IS NULL OR lease_expires_at > claimed_at",
            name="lease_after_claim",
        ),
        CheckConstraint(
            "last_error_code IS NULL OR last_error_code IN ("
            "'adapter_unexpected_error', 'attempts_exhausted', 'destination_disabled', "
            "'destination_unconfigured', 'lease_expired', 'payload_invalid', "
            "'permanent_delivery_error', 'retryable_delivery_error', "
            "'telegram_protocol_error', 'telegram_runtime_copy_invalid', "
            "'telegram_runtime_copy_unavailable', 'telegram_staging_file_invalid', "
            "'telegram_staging_file_missing')",
            name="last_error_code_allowed",
        ),
        CheckConstraint(
            "(status = 'pending' AND claim_token IS NULL AND claimed_at IS NULL "
            "AND lease_expires_at IS NULL AND next_attempt_at IS NOT NULL "
            "AND delivered_at IS NULL AND failed_at IS NULL) OR "
            "(status = 'processing' AND claim_token IS NOT NULL AND claimed_at IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND next_attempt_at IS NULL "
            "AND delivered_at IS NULL AND failed_at IS NULL) OR "
            "(status = 'delivered' AND claim_token IS NULL AND claimed_at IS NULL "
            "AND lease_expires_at IS NULL AND next_attempt_at IS NULL "
            "AND delivered_at IS NOT NULL AND failed_at IS NULL "
            "AND last_error_code IS NULL AND last_error IS NULL) OR "
            "(status = 'failed' AND claim_token IS NULL AND claimed_at IS NULL "
            "AND lease_expires_at IS NULL AND next_attempt_at IS NULL "
            "AND delivered_at IS NULL AND failed_at IS NOT NULL "
            "AND last_error_code IS NOT NULL AND last_error IS NOT NULL)",
            name="state_shape",
        ),
        CheckConstraint(
            "idempotency_key ~ '^incident[.]created:"
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:"
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'",
            name="idempotency_key_format",
        ),
        UniqueConstraint(
            "notification_type",
            "incident_id",
            "destination_id",
            name="uq_outbox_messages_notification_incident_destination",
        ),
        UniqueConstraint("idempotency_key", name="uq_outbox_messages_idempotency_key"),
        Index(
            "ix_outbox_messages_pending_next_attempt",
            "next_attempt_at",
            "created_at",
            "id",
            postgresql_where=text("status = 'pending'"),
        ),
        Index(
            "ix_outbox_messages_processing_lease",
            "lease_expires_at",
            "id",
            postgresql_where=text("status = 'processing'"),
        ),
        Index("ix_outbox_messages_destination_status", "destination_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    notification_type: Mapped[str] = mapped_column(String(64))
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    destination_id: Mapped[UUID] = mapped_column(
        ForeignKey("notification_destinations.id", ondelete="RESTRICT")
    )
    payload_schema_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    idempotency_key: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(
        String(16),
        default=OutboxStatus.PENDING.value,
        server_default=OutboxStatus.PENDING.value,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, server_default="5")
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=True,
    )
    claim_token: Mapped[UUID | None] = mapped_column(nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
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
