"""Add append-only incident comments for Dashboard actions.

Revision ID: 20260728_0009
Revises: 20260728_0008
Create Date: 2026-07-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260728_0009"
down_revision: str | None = "20260728_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create comments and protect them with the existing append-only function."""

    op.create_table(
        "incident_comments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("actor_username_snapshot", sa.String(length=64), nullable=False),
        sa.Column("auth_method_type", sa.String(length=32), nullable=False),
        sa.Column("auth_method_id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("body", sa.String(length=1_000), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "auth_method_type IN ('operator_api_key', 'web_session')",
            name="ck_incident_comments_auth_method_type_allowed",
        ),
        sa.CheckConstraint(
            "char_length(body) BETWEEN 1 AND 1000",
            name="ck_incident_comments_body_length",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name="fk_incident_comments_incident_id_incidents",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name="fk_incident_comments_operator_id_operators",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incident_comments"),
    )
    op.create_index(
        "ix_incident_comments_incident_created_id",
        "incident_comments",
        ["incident_id", "created_at", "id"],
        unique=False,
    )
    op.execute(
        """
        CREATE TRIGGER trg_incident_comments_immutable_rows
        BEFORE UPDATE OR DELETE ON incident_comments
        FOR EACH ROW
        EXECUTE FUNCTION woland_guard_reject_immutable_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_incident_comments_immutable_truncate
        BEFORE TRUNCATE ON incident_comments
        FOR EACH STATEMENT
        EXECUTE FUNCTION woland_guard_reject_immutable_mutation()
        """
    )


def downgrade() -> None:
    """Remove 7C only when no comment provenance or outcome would be lost."""

    op.execute("LOCK TABLE incident_comments IN ACCESS EXCLUSIVE MODE")
    op.execute("LOCK TABLE audit_log_entries IN SHARE ROW EXCLUSIVE MODE")
    op.execute("LOCK TABLE operator_idempotency_records IN SHARE ROW EXCLUSIVE MODE")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM incident_comments LIMIT 1) THEN
                RAISE EXCEPTION 'cannot downgrade populated incident comments safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM audit_log_entries
                WHERE action = 'incident.comment_added'
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade incident comment audit safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM operator_idempotency_records
                WHERE operation = 'incident.comment.create.v1'
                LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade incident comment outcomes safely'
                    USING ERRCODE = '55000';
            END IF;
        END
        $$
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_incident_comments_immutable_truncate ON incident_comments"
    )
    op.execute("DROP TRIGGER IF EXISTS trg_incident_comments_immutable_rows ON incident_comments")
    op.drop_index(
        "ix_incident_comments_incident_created_id",
        table_name="incident_comments",
    )
    op.drop_table("incident_comments")
