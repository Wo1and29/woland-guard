"""Proposed, never auto-executed IP block plans and the address allowlist."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class IpBlockPlan(Base):
    """One proposed, single-host block target awaiting a second operator's decision.

    Nothing in this row is ever executed by the control plane -- it only records
    what an operator proposed, the exact command that would carry it out, and
    whether another operator approved or rejected it before it expired.
    """

    __tablename__ = "ip_block_plans"
    __table_args__ = (
        CheckConstraint(
            "(family(ip_address) = 4 AND masklen(ip_address) = 32) OR "
            "(family(ip_address) = 6 AND masklen(ip_address) = 128)",
            name="ip_address_is_single_host",
        ),
        CheckConstraint(
            "status IN ('proposed', 'approved', 'rejected')",
            name="status_allowed",
        ),
        CheckConstraint("expires_at > proposed_at", name="expiry_after_proposal"),
        CheckConstraint(
            "(status = 'proposed' AND decided_by_operator_id IS NULL "
            "AND decided_at IS NULL) OR "
            "(status IN ('approved', 'rejected') AND decided_by_operator_id IS NOT NULL "
            "AND decided_at IS NOT NULL)",
            name="decision_shape",
        ),
        Index("ix_ip_block_plans_server_status", "server_id", "status"),
        Index(
            "uq_ip_block_plans_active_incident_ip",
            "incident_id",
            "ip_address",
            unique=True,
            postgresql_where=text("status = 'proposed'"),
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    server_id: Mapped[UUID] = mapped_column(ForeignKey("servers.id", ondelete="RESTRICT"))
    ip_address: Mapped[str] = mapped_column(INET)
    status: Mapped[str] = mapped_column(String(16))
    command_argv: Mapped[list[Any]] = mapped_column(JSONB)
    proposed_by_operator_id: Mapped[UUID] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT")
    )
    proposed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    proposal_request_id: Mapped[str] = mapped_column(String(64))
    decided_by_operator_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"),
        nullable=True,
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IpBlockAllowlistEntry(Base):
    """One CIDR range that may never be proposed for blocking while active."""

    __tablename__ = "ip_block_allowlist_entries"
    __table_args__ = (
        Index(
            "uq_ip_block_allowlist_entries_active_cidr",
            "cidr",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    cidr: Mapped[str] = mapped_column(CIDR)
    label: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
