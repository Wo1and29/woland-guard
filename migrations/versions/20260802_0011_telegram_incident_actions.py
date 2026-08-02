"""Add pending Telegram incident actions awaiting a terminal-status reason.

Revision ID: 20260802_0011
Revises: 20260802_0010
Create Date: 2026-08-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0011"
down_revision: str | None = "20260802_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "telegram_pending_actions",
        # autoincrement=False: without it, SQLAlchemy Core treats a single-column
        # integer primary key as SERIAL by default and silently creates a sequence
        # this table never uses -- every insert supplies telegram_user_id explicitly.
        sa.Column("telegram_user_id", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("target_status", sa.String(length=32), nullable=False),
        sa.Column("expected_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "telegram_user_id > 0",
            name=op.f("ck_telegram_pending_actions_telegram_user_id_positive"),
        ),
        sa.CheckConstraint(
            "target_status IN ('resolved', 'false_positive')",
            name=op.f("ck_telegram_pending_actions_target_status_allowed"),
        ),
        sa.CheckConstraint(
            "expected_version > 0",
            name=op.f("ck_telegram_pending_actions_expected_version_positive"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name=op.f("ck_telegram_pending_actions_expiry_after_creation"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_telegram_pending_actions_incident_id_incidents"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "telegram_user_id",
            name=op.f("pk_telegram_pending_actions"),
        ),
    )


def downgrade() -> None:
    op.drop_table("telegram_pending_actions")
