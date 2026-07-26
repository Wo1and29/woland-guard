"""Add incident workflow history, audit, and durable idempotency.

Revision ID: 20260722_0004
Revises: 20260722_0003
Create Date: 2026-07-22

Downgrade intentionally destroys incident history, audit entries, idempotency
results, and workflow versions. Back up operational data before downgrading.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260722_0004"
down_revision: str | None = "20260722_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TABLES = (
    "incident_history",
    "audit_log_entries",
    "operator_idempotency_records",
)


def upgrade() -> None:
    """Create complete workflow persistence and one baseline per existing incident."""

    op.execute("LOCK TABLE incidents IN SHARE ROW EXCLUSIVE MODE")
    op.add_column(
        "incidents",
        sa.Column("lock_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
    )
    op.create_check_constraint(
        "ck_incidents_lock_version_positive",
        "incidents",
        "lock_version > 0",
    )
    op.create_index(
        "ix_incidents_created_at_id",
        "incidents",
        ["created_at", "id"],
        unique=False,
    )

    op.create_table(
        "incident_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("entry_type", sa.String(length=32), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=True),
        sa.Column("to_status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=1_000), nullable=True),
        sa.Column("changed_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column("actor_username_snapshot", sa.String(length=64), nullable=True),
        sa.Column("auth_method_type", sa.String(length=32), nullable=True),
        sa.Column("auth_method_id", sa.Uuid(), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "entry_type IN ('baseline', 'status_transition')",
            name="ck_incident_history_entry_type_allowed",
        ),
        sa.CheckConstraint(
            "(entry_type = 'baseline' AND version = 1 AND from_status IS NULL "
            "AND reason IS NULL AND changed_by_operator_id IS NULL "
            "AND actor_username_snapshot IS NULL AND auth_method_type IS NULL "
            "AND auth_method_id IS NULL) OR "
            "(entry_type = 'status_transition' AND version > 1 AND from_status IS NOT NULL "
            "AND changed_by_operator_id IS NOT NULL AND actor_username_snapshot IS NOT NULL "
            "AND auth_method_type IS NOT NULL AND auth_method_id IS NOT NULL)",
            name="ck_incident_history_entry_shape",
        ),
        sa.CheckConstraint(
            "from_status IS NULL OR "
            "from_status IN ('new', 'investigating', 'resolved', 'false_positive')",
            name="ck_incident_history_from_status_allowed",
        ),
        sa.CheckConstraint(
            "reason IS NULL OR (char_length(reason) BETWEEN 1 AND 1000)",
            name="ck_incident_history_reason_length",
        ),
        sa.CheckConstraint(
            "entry_type = 'baseline' OR "
            "to_status NOT IN ('resolved', 'false_positive') OR reason IS NOT NULL",
            name="ck_incident_history_terminal_transition_requires_reason",
        ),
        sa.CheckConstraint(
            "to_status IN ('new', 'investigating', 'resolved', 'false_positive')",
            name="ck_incident_history_to_status_allowed",
        ),
        sa.CheckConstraint("version > 0", name="ck_incident_history_version_positive"),
        sa.ForeignKeyConstraint(
            ["changed_by_operator_id"],
            ["operators.id"],
            name="fk_incident_history_changed_by_operator_id_operators",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name="fk_incident_history_incident_id_incidents",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incident_history"),
        sa.UniqueConstraint(
            "incident_id",
            "version",
            name="uq_incident_history_incident_version",
        ),
    )
    op.create_index(
        "ix_incident_history_incident_version",
        "incident_history",
        ["incident_id", "version"],
        unique=False,
    )

    op.create_table(
        "audit_log_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=True),
        sa.Column("actor_username_snapshot", sa.String(length=64), nullable=True),
        sa.Column("auth_method_type", sa.String(length=32), nullable=True),
        sa.Column("auth_method_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("incident_history_id", sa.Uuid(), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action ~ '^[a-z][a-z0-9_.]{2,63}$'",
            name="ck_audit_log_entries_action_format",
        ),
        sa.CheckConstraint(
            "(actor_type = 'local_cli' AND operator_id IS NULL "
            "AND actor_username_snapshot IS NULL AND auth_method_type IS NULL "
            "AND auth_method_id IS NULL) OR "
            "(actor_type = 'operator' AND operator_id IS NOT NULL "
            "AND actor_username_snapshot IS NOT NULL AND auth_method_type IS NOT NULL "
            "AND auth_method_id IS NOT NULL)",
            name="ck_audit_log_entries_actor_shape",
        ),
        sa.CheckConstraint(
            "actor_type IN ('operator', 'local_cli')",
            name="ck_audit_log_entries_actor_type_allowed",
        ),
        sa.CheckConstraint(
            "target_type ~ '^[a-z][a-z0-9_]{2,31}$'",
            name="ck_audit_log_entries_target_type_format",
        ),
        sa.ForeignKeyConstraint(
            ["incident_history_id"],
            ["incident_history.id"],
            name="fk_audit_log_entries_incident_history_id_incident_history",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name="fk_audit_log_entries_operator_id_operators",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log_entries"),
        sa.UniqueConstraint(
            "incident_history_id",
            name="uq_audit_log_entries_incident_history_id",
        ),
    )
    op.create_index(
        "ix_audit_log_entries_created_id",
        "audit_log_entries",
        ["created_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_audit_log_entries_operator_created",
        "audit_log_entries",
        ["operator_id", "created_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_audit_log_entries_target_created",
        "audit_log_entries",
        ["target_type", "target_id", "created_at", "id"],
        unique=False,
    )

    op.create_table(
        "operator_idempotency_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("canonical_request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_status", sa.SmallInteger(), nullable=False),
        sa.Column(
            "response_body",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'",
            name="ck_operator_idempotency_records_key_format",
        ),
        sa.CheckConstraint(
            "canonical_request_hash ~ '^[0-9a-f]{64}$'",
            name="ck_operator_idempotency_records_request_hash_format",
        ),
        sa.CheckConstraint(
            "response_status IN (200, 404, 409)",
            name="ck_operator_idempotency_records_response_status_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name="fk_operator_idempotency_records_operator_id_operators",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_operator_idempotency_records"),
        sa.UniqueConstraint(
            "operator_id",
            "idempotency_key",
            name="uq_operator_idempotency_records_operator_key",
        ),
    )
    op.create_index(
        "ix_operator_idempotency_records_created_id",
        "operator_idempotency_records",
        ["created_at", "id"],
        unique=False,
    )

    _backfill_baseline_history()
    _create_immutable_triggers()


def downgrade() -> None:
    """Destroy 6B workflow history, audit, idempotency, and version counters."""

    for table_name in reversed(_IMMUTABLE_TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table_name}_immutable_truncate ON {table_name}")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table_name}_immutable_rows ON {table_name}")

    op.drop_index(
        "ix_operator_idempotency_records_created_id",
        table_name="operator_idempotency_records",
    )
    op.drop_table("operator_idempotency_records")

    op.drop_index("ix_audit_log_entries_target_created", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_operator_created", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_created_id", table_name="audit_log_entries")
    op.drop_table("audit_log_entries")

    op.drop_index("ix_incident_history_incident_version", table_name="incident_history")
    op.drop_table("incident_history")
    op.execute("DROP FUNCTION IF EXISTS woland_guard_reject_immutable_mutation()")

    op.drop_index("ix_incidents_created_at_id", table_name="incidents")
    op.drop_constraint("ck_incidents_lock_version_positive", "incidents", type_="check")
    op.drop_column("incidents", "lock_version")


def _backfill_baseline_history() -> None:
    op.execute(
        """
        INSERT INTO incident_history (
            id,
            incident_id,
            version,
            entry_type,
            from_status,
            to_status,
            reason,
            changed_by_operator_id,
            actor_username_snapshot,
            auth_method_type,
            auth_method_id,
            request_id,
            created_at
        )
        SELECT
            (
                substr(md5(id::text || chr(58) || 'baseline'), 1, 8) || '-' ||
                substr(md5(id::text || chr(58) || 'baseline'), 9, 4) || '-' ||
                substr(md5(id::text || chr(58) || 'baseline'), 13, 4) || '-' ||
                substr(md5(id::text || chr(58) || 'baseline'), 17, 4) || '-' ||
                substr(md5(id::text || chr(58) || 'baseline'), 21, 12)
            )::uuid,
            id,
            1,
            'baseline',
            NULL,
            status,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            created_at
        FROM incidents
        """
    )
    op.execute(
        """
        DO $$
        DECLARE
            incident_count bigint;
            baseline_count bigint;
        BEGIN
            SELECT count(*) INTO incident_count FROM incidents;
            SELECT count(*) INTO baseline_count
              FROM incident_history
             WHERE entry_type = 'baseline';
            IF incident_count <> baseline_count THEN
                RAISE EXCEPTION 'incident baseline backfill count mismatch';
            END IF;
        END
        $$
        """
    )


def _create_immutable_triggers() -> None:
    op.execute(
        """
        CREATE FUNCTION woland_guard_reject_immutable_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'immutable Woland Guard table cannot be modified'
                USING ERRCODE = '55000';
            RETURN NULL;
        END
        $$
        """
    )
    for table_name in _IMMUTABLE_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{table_name}_immutable_rows
            BEFORE UPDATE OR DELETE ON {table_name}
            FOR EACH ROW
            EXECUTE FUNCTION woland_guard_reject_immutable_mutation()
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER trg_{table_name}_immutable_truncate
            BEFORE TRUNCATE ON {table_name}
            FOR EACH STATEMENT
            EXECUTE FUNCTION woland_guard_reject_immutable_mutation()
            """
        )
