"""Add dry-run IP block plans and the block-target allowlist.

Revision ID: 20260802_0012
Revises: 20260802_0011
Create Date: 2026-08-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260802_0012"
down_revision: str | None = "20260802_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ip_block_plans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("server_id", sa.Uuid(), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("command_argv", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("proposed_by_operator_id", sa.Uuid(), nullable=False),
        sa.Column(
            "proposed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("proposal_request_id", sa.String(length=64), nullable=False),
        sa.Column("decided_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(family(ip_address) = 4 AND masklen(ip_address) = 32) OR "
            "(family(ip_address) = 6 AND masklen(ip_address) = 128)",
            name=op.f("ck_ip_block_plans_ip_address_is_single_host"),
        ),
        sa.CheckConstraint(
            "status IN ('proposed', 'approved', 'rejected')",
            name=op.f("ck_ip_block_plans_status_allowed"),
        ),
        sa.CheckConstraint(
            "expires_at > proposed_at",
            name=op.f("ck_ip_block_plans_expiry_after_proposal"),
        ),
        sa.CheckConstraint(
            "(status = 'proposed' AND decided_by_operator_id IS NULL "
            "AND decided_at IS NULL) OR "
            "(status IN ('approved', 'rejected') AND decided_by_operator_id IS NOT NULL "
            "AND decided_at IS NOT NULL)",
            name=op.f("ck_ip_block_plans_decision_shape"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_ip_block_plans_incident_id_incidents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("fk_ip_block_plans_server_id_servers"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["proposed_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_ip_block_plans_proposed_by_operator_id_operators"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["decided_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_ip_block_plans_decided_by_operator_id_operators"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ip_block_plans")),
    )
    op.create_index(
        "ix_ip_block_plans_server_status",
        "ip_block_plans",
        ["server_id", "status"],
        unique=False,
    )
    op.create_index(
        "uq_ip_block_plans_active_incident_ip",
        "ip_block_plans",
        ["incident_id", "ip_address"],
        unique=True,
        postgresql_where=sa.text("status = 'proposed'"),
    )

    op.create_table(
        "ip_block_allowlist_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cidr", postgresql.CIDR(), nullable=False),
        sa.Column("label", sa.String(length=100), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ip_block_allowlist_entries")),
    )
    op.create_index(
        "uq_ip_block_allowlist_entries_active_cidr",
        "ip_block_allowlist_entries",
        ["cidr"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_ip_block_allowlist_entries_active_cidr",
        table_name="ip_block_allowlist_entries",
    )
    op.drop_table("ip_block_allowlist_entries")
    op.drop_index("uq_ip_block_plans_active_incident_ip", table_name="ip_block_plans")
    op.drop_index("ix_ip_block_plans_server_status", table_name="ip_block_plans")
    op.drop_table("ip_block_plans")
