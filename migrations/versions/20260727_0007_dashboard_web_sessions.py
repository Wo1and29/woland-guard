"""Add provider-neutral operator web sessions and auth-method invariants.

Revision ID: 20260727_0007
Revises: 20260727_0006
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260727_0007"
down_revision: str | None = "20260727_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add sessions only after validating every existing auth-method snapshot."""

    op.execute("LOCK TABLE incident_history IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE audit_log_entries IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE operator_api_keys IN SHARE ROW EXCLUSIVE MODE")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM incident_history
                WHERE auth_method_type IS NOT NULL
                  AND auth_method_type NOT IN ('operator_api_key', 'web_session')
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot migrate unknown incident auth method safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM audit_log_entries
                WHERE auth_method_type IS NOT NULL
                  AND auth_method_type NOT IN ('operator_api_key', 'web_session')
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot migrate unknown audit auth method safely'
                    USING ERRCODE = '55000';
            END IF;
        END
        $$
        """
    )
    op.create_unique_constraint(
        "uq_operator_api_keys_id_operator_id",
        "operator_api_keys",
        ["id", "operator_id"],
    )
    op.create_table(
        "operator_web_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("authenticated_by_api_key_id", sa.Uuid(), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("csrf_token_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "octet_length(token_digest) = 32",
            name="token_digest_length",
        ),
        sa.CheckConstraint(
            "octet_length(csrf_token_digest) = 32",
            name="csrf_token_digest_length",
        ),
        sa.CheckConstraint(
            "created_at <= last_seen_at",
            name="last_seen_not_before_creation",
        ),
        sa.CheckConstraint(
            "last_seen_at < idle_expires_at",
            name="idle_expiry_after_last_seen",
        ),
        sa.CheckConstraint(
            "idle_expires_at <= absolute_expires_at",
            name="idle_not_after_absolute_expiry",
        ),
        sa.CheckConstraint(
            "absolute_expires_at > created_at",
            name="absolute_expiry_after_creation",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name="updated_not_before_creation",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="revocation_not_before_creation",
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name="fk_operator_web_sessions_operator_id_operators",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authenticated_by_api_key_id", "operator_id"],
            ["operator_api_keys.id", "operator_api_keys.operator_id"],
            name="fk_operator_web_sessions_key_operator",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_operator_web_sessions"),
        sa.UniqueConstraint(
            "token_digest",
            name="uq_operator_web_sessions_token_digest",
        ),
        sa.UniqueConstraint(
            "csrf_token_digest",
            name="uq_operator_web_sessions_csrf_token_digest",
        ),
    )
    op.create_index(
        "ix_operator_web_sessions_key_revoked",
        "operator_web_sessions",
        ["authenticated_by_api_key_id", "revoked_at"],
        unique=False,
    )
    op.create_index(
        "ix_operator_web_sessions_operator_active",
        "operator_web_sessions",
        ["operator_id", "absolute_expires_at"],
        unique=False,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_index(
        "ix_operator_web_sessions_expiry",
        "operator_web_sessions",
        ["absolute_expires_at", "idle_expires_at"],
        unique=False,
    )
    op.create_check_constraint(
        op.f("ck_incident_history_auth_method_type_allowed"),
        "incident_history",
        "(auth_method_type IS NULL AND auth_method_id IS NULL) OR "
        "(auth_method_type IN ('operator_api_key', 'web_session') "
        "AND auth_method_id IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_audit_log_entries_auth_method_type_allowed"),
        "audit_log_entries",
        "(actor_type = 'local_cli' AND auth_method_type IS NULL AND auth_method_id IS NULL) OR "
        "(actor_type = 'operator' AND auth_method_type IN "
        "('operator_api_key', 'web_session') "
        "AND auth_method_id IS NOT NULL)",
    )


def downgrade() -> None:
    """Remove 7A only when no web-session identity history would be lost."""

    op.execute("LOCK TABLE operator_web_sessions IN ACCESS EXCLUSIVE MODE")
    op.execute("LOCK TABLE incident_history IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE audit_log_entries IN SHARE ROW EXCLUSIVE MODE")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM operator_web_sessions LIMIT 1) THEN
                RAISE EXCEPTION 'cannot downgrade populated operator web sessions safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM incident_history
                WHERE auth_method_type = 'web_session'
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade web-session incident history safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM audit_log_entries
                WHERE auth_method_type = 'web_session'
                   OR action IN (
                       'operator_web_session.started',
                       'operator_web_session.ended'
                   )
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade web-session audit history safely'
                    USING ERRCODE = '55000';
            END IF;
        END
        $$
        """
    )
    op.drop_constraint(
        op.f("ck_audit_log_entries_auth_method_type_allowed"),
        "audit_log_entries",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_incident_history_auth_method_type_allowed"),
        "incident_history",
        type_="check",
    )
    op.drop_index(
        "ix_operator_web_sessions_expiry",
        table_name="operator_web_sessions",
    )
    op.drop_index(
        "ix_operator_web_sessions_operator_active",
        table_name="operator_web_sessions",
    )
    op.drop_index(
        "ix_operator_web_sessions_key_revoked",
        table_name="operator_web_sessions",
    )
    op.drop_table("operator_web_sessions")
    op.drop_constraint(
        "uq_operator_api_keys_id_operator_id",
        "operator_api_keys",
        type_="unique",
    )
