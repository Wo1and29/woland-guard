"""Database-backed opaque web sessions for local operators."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class OperatorWebSession(Base):
    """One revocable server-side session containing only token digests."""

    __tablename__ = "operator_web_sessions"
    __table_args__ = (
        CheckConstraint(
            "octet_length(token_digest) = 32",
            name="token_digest_length",
        ),
        CheckConstraint(
            "octet_length(csrf_token_digest) = 32",
            name="csrf_token_digest_length",
        ),
        CheckConstraint(
            "created_at <= last_seen_at",
            name="last_seen_not_before_creation",
        ),
        CheckConstraint(
            "last_seen_at < idle_expires_at",
            name="idle_expiry_after_last_seen",
        ),
        CheckConstraint(
            "idle_expires_at <= absolute_expires_at",
            name="idle_not_after_absolute_expiry",
        ),
        CheckConstraint(
            "absolute_expires_at > created_at",
            name="absolute_expiry_after_creation",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="updated_not_before_creation",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="revocation_not_before_creation",
        ),
        UniqueConstraint("token_digest", name="uq_operator_web_sessions_token_digest"),
        UniqueConstraint(
            "csrf_token_digest",
            name="uq_operator_web_sessions_csrf_token_digest",
        ),
        ForeignKeyConstraint(
            ["authenticated_by_api_key_id", "operator_id"],
            ["operator_api_keys.id", "operator_api_keys.operator_id"],
            name="fk_operator_web_sessions_key_operator",
            ondelete="RESTRICT",
        ),
        Index(
            "ix_operator_web_sessions_key_revoked",
            "authenticated_by_api_key_id",
            "revoked_at",
        ),
        Index(
            "ix_operator_web_sessions_operator_active",
            "operator_id",
            "absolute_expires_at",
            postgresql_where=text("revoked_at IS NULL"),
        ),
        Index(
            "ix_operator_web_sessions_expiry",
            "absolute_expires_at",
            "idle_expires_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operator_id: Mapped[UUID] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"),
    )
    authenticated_by_api_key_id: Mapped[UUID]
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32))
    csrf_token_digest: Mapped[bytes] = mapped_column(LargeBinary(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )
