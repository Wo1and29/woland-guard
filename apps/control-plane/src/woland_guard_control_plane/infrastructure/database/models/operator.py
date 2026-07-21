"""Local operator identities and independently managed authentication keys."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class OperatorRole(StrEnum):
    """Fixed single-tenant roles used by the stage 6 RBAC matrix."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class Operator(Base):
    """A human operator identity independent from any authentication method."""

    __tablename__ = "operators"
    __table_args__ = (
        CheckConstraint(
            "username ~ '^[a-z][a-z0-9_.-]{2,63}$'",
            name="username_format",
        ),
        CheckConstraint(
            "role IN ('viewer', 'analyst', 'admin')",
            name="role_allowed",
        ),
        UniqueConstraint("username", name="uq_operators_username"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
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


class OperatorApiKey(Base):
    """One revocable authentication method belonging to an operator identity."""

    __tablename__ = "operator_api_keys"
    __table_args__ = (
        CheckConstraint(
            "octet_length(secret_hash) = 32",
            name="secret_hash_length",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="expiry_after_creation",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="revocation_not_before_creation",
        ),
        UniqueConstraint("public_id", name="uq_operator_api_keys_public_id"),
        UniqueConstraint(
            "rotated_from_id",
            name="uq_operator_api_keys_rotated_from_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operator_id: Mapped[UUID] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"),
        index=True,
    )
    public_id: Mapped[str] = mapped_column(String(32))
    secret_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rotated_from_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operator_api_keys.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
