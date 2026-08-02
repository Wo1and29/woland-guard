"""Add Telegram operator links, poller offset and the telegram auth method.

Revision ID: 20260802_0010
Revises: 20260728_0009
Create Date: 2026-08-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0010"
down_revision: str | None = "20260728_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_HISTORY_AUTH_METHOD_ALLOWED = (
    "(auth_method_type IS NULL AND auth_method_id IS NULL) OR "
    "(auth_method_type IN ({values}) AND auth_method_id IS NOT NULL)"
)
_AUDIT_AUTH_METHOD_ALLOWED = (
    "(actor_type = 'local_cli' AND auth_method_type IS NULL AND auth_method_id IS NULL) OR "
    "(actor_type = 'operator' AND auth_method_type IN ({values}) "
    "AND auth_method_id IS NOT NULL)"
)
_COMMENT_AUTH_METHOD_ALLOWED = "auth_method_type IN ({values})"

_WITHOUT_TELEGRAM = "'operator_api_key', 'web_session'"
_WITH_TELEGRAM = "'operator_api_key', 'web_session', 'telegram'"

# Migration 20260728_0009 passed an already-qualified constraint name to
# sa.CheckConstraint(name=...) inside create_table, so the metadata naming convention
# prefixed it a second time and PostgreSQL truncated the result to 63 bytes with a hash.
# The ORM model declares the short name, so the database and the model disagree today.
# Alembic autogenerate does not compare CHECK constraints, which is why the drift was
# never reported. This migration renames the constraint to the value the model expects
# and restores the historical name on downgrade.
_LEGACY_COMMENT_CONSTRAINT = "ck_incident_comments_ck_incident_comments_auth_method_t_8ac5"


def upgrade() -> None:
    """Widen the auth-method allowlists and add the inbound Telegram tables."""

    op.execute("LOCK TABLE incident_history IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE audit_log_entries IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE incident_comments IN SHARE ROW EXCLUSIVE MODE")
    op.create_table(
        "operator_telegram_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("telegram_user_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "telegram_user_id > 0",
            name=op.f("ck_operator_telegram_links_telegram_user_id_positive"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_operator_telegram_links_revocation_not_before_creation"),
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name=op.f("fk_operator_telegram_links_operator_id_operators"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_operator_telegram_links")),
    )
    op.create_index(
        op.f("ix_operator_telegram_links_operator_id"),
        "operator_telegram_links",
        ["operator_id"],
        unique=False,
    )
    op.create_index(
        "uq_operator_telegram_links_active_telegram_user",
        "operator_telegram_links",
        ["telegram_user_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_index(
        "uq_operator_telegram_links_active_operator",
        "operator_telegram_links",
        ["operator_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_table(
        "telegram_bot_offsets",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("next_update_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("id = 1", name=op.f("ck_telegram_bot_offsets_single_row")),
        sa.CheckConstraint(
            "next_update_id >= 0",
            name=op.f("ck_telegram_bot_offsets_next_update_id_not_negative"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_telegram_bot_offsets")),
    )
    _replace_auth_method_constraints(_WITH_TELEGRAM)


def downgrade() -> None:
    """Remove 9A only when no Telegram-sourced provenance would be lost."""

    op.execute("LOCK TABLE operator_telegram_links IN ACCESS EXCLUSIVE MODE")
    op.execute("LOCK TABLE incident_history IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE audit_log_entries IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE incident_comments IN SHARE ROW EXCLUSIVE MODE")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM operator_telegram_links LIMIT 1) THEN
                RAISE EXCEPTION 'cannot downgrade populated telegram operator links safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM incident_history
                WHERE auth_method_type = 'telegram'
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade telegram incident history safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM incident_comments
                WHERE auth_method_type = 'telegram'
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade telegram incident comments safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM audit_log_entries
                WHERE auth_method_type = 'telegram'
                   OR action IN (
                       'operator_telegram_link.created',
                       'operator_telegram_link.revoked'
                   )
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade telegram audit history safely'
                    USING ERRCODE = '55000';
            END IF;
        END
        $$
        """
    )
    _replace_auth_method_constraints(_WITHOUT_TELEGRAM, restoring=True)
    op.drop_table("telegram_bot_offsets")
    op.drop_index(
        "uq_operator_telegram_links_active_operator",
        table_name="operator_telegram_links",
    )
    op.drop_index(
        "uq_operator_telegram_links_active_telegram_user",
        table_name="operator_telegram_links",
    )
    op.drop_index(
        op.f("ix_operator_telegram_links_operator_id"),
        table_name="operator_telegram_links",
    )
    op.drop_table("operator_telegram_links")


def _replace_auth_method_constraints(values: str, *, restoring: bool = False) -> None:
    """Rewrite the three auth-method allowlists to exactly one closed value set."""

    canonical_comment = op.f("ck_incident_comments_auth_method_type_allowed")
    legacy_comment = op.f(_LEGACY_COMMENT_CONSTRAINT)
    comment_names = (
        (canonical_comment, legacy_comment) if restoring else (legacy_comment, canonical_comment)
    )
    for table, template, names in (
        (
            "incident_history",
            _HISTORY_AUTH_METHOD_ALLOWED,
            (op.f("ck_incident_history_auth_method_type_allowed"),) * 2,
        ),
        (
            "audit_log_entries",
            _AUDIT_AUTH_METHOD_ALLOWED,
            (op.f("ck_audit_log_entries_auth_method_type_allowed"),) * 2,
        ),
        ("incident_comments", _COMMENT_AUTH_METHOD_ALLOWED, comment_names),
    ):
        existing_name, new_name = names
        op.drop_constraint(existing_name, table, type_="check")
        op.create_check_constraint(new_name, table, template.format(values=values))
