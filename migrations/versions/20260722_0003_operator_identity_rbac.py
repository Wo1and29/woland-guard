"""Add local operator identities and independently rotatable API keys.

Revision ID: 20260722_0003
Revises: 20260721_0002
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260722_0003"
down_revision: str | None = "20260721_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create identities first, then their replaceable authentication methods."""

    op.create_table(
        "operators",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('viewer', 'analyst', 'admin')",
            name="ck_operators_role_allowed",
        ),
        sa.CheckConstraint(
            "username ~ '^[a-z][a-z0-9_.-]{2,63}$'",
            name="ck_operators_username_format",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_operators"),
        sa.UniqueConstraint("username", name="uq_operators_username"),
    )
    op.create_table(
        "operator_api_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("public_id", sa.String(length=32), nullable=False),
        sa.Column("secret_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("label", sa.String(length=100), nullable=True),
        sa.Column("rotated_from_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="ck_operator_api_keys_expiry_after_creation",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="ck_operator_api_keys_revocation_not_before_creation",
        ),
        sa.CheckConstraint(
            "octet_length(secret_hash) = 32",
            name="ck_operator_api_keys_secret_hash_length",
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name="fk_operator_api_keys_operator_id_operators",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["rotated_from_id"],
            ["operator_api_keys.id"],
            name="fk_operator_api_keys_rotated_from_id_operator_api_keys",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_operator_api_keys"),
        sa.UniqueConstraint(
            "public_id",
            name="uq_operator_api_keys_public_id",
        ),
        sa.UniqueConstraint(
            "rotated_from_id",
            name="uq_operator_api_keys_rotated_from_id",
        ),
    )
    op.create_index(
        "ix_operator_api_keys_operator_id",
        "operator_api_keys",
        ["operator_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove only stage 6A identities and authentication methods."""

    op.drop_index("ix_operator_api_keys_operator_id", table_name="operator_api_keys")
    op.drop_table("operator_api_keys")
    op.drop_table("operators")
