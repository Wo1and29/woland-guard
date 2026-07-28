"""Server inventory and agent credential models."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class Server(Base):
    """A monitored Linux server owned by this single-tenant installation."""

    __tablename__ = "servers"
    __table_args__ = (UniqueConstraint("name", name="uq_servers_name"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100))
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    description: Mapped[str | None] = mapped_column(String(1_000), nullable=True)
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


class AgentApiKey(Base):
    """Persisted public identifier and digest for an agent credential."""

    __tablename__ = "agent_api_keys"
    __table_args__ = (
        CheckConstraint(
            "octet_length(secret_hash) = 32",
            name="secret_hash_length",
        ),
        UniqueConstraint("public_id", name="uq_agent_api_keys_public_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    server_id: Mapped[UUID] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"),
        index=True,
    )
    public_id: Mapped[str] = mapped_column(String(32))
    secret_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Index(
    "ix_servers_lower_name_id",
    func.lower(Server.__table__.c.name),
    Server.__table__.c.id,
)
Index(
    "ix_servers_lower_name_pattern",
    func.lower(Server.__table__.c.name).label("lower_name_pattern"),
    postgresql_ops={"lower_name_pattern": "text_pattern_ops"},
)
Index(
    "ix_servers_lower_hostname_pattern",
    func.lower(Server.__table__.c.hostname).label("lower_hostname_pattern"),
    postgresql_ops={"lower_hostname_pattern": "text_pattern_ops"},
)
