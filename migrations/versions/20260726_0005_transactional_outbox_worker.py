"""Add provider-neutral destinations and a lease-based transactional outbox.

Revision ID: 20260726_0005
Revises: 20260722_0004
Create Date: 2026-07-26

Upgrade cannot infer a destination for legacy outbox rows and therefore refuses
to run while the legacy table is non-empty. Downgrade likewise refuses to erase
destination, claim, lease, and failure semantics from populated 6C rows.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260726_0005"
down_revision: str | None = "20260722_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Replace the unused legacy envelope with destination-aware worker state."""

    op.execute("LOCK TABLE outbox_messages IN ACCESS EXCLUSIVE MODE")
    _reject_populated_outbox()

    op.create_table(
        "notification_destinations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("adapter_kind", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "minimum_severity",
            sa.String(length=16),
            server_default=sa.text("'low'"),
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
            "adapter_kind IN ('telegram')",
            name="ck_notification_destinations_adapter_kind_allowed",
        ),
        sa.CheckConstraint(
            "minimum_severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_notification_destinations_minimum_severity_allowed",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_notification_destinations"),
    )
    op.create_index(
        "ix_notification_destinations_enabled_severity",
        "notification_destinations",
        ["enabled", "minimum_severity"],
        unique=False,
    )

    op.drop_index("ix_outbox_messages_status_available_at", table_name="outbox_messages")
    _drop_legacy_outbox_constraints()

    op.alter_column(
        "outbox_messages",
        "topic",
        new_column_name="notification_type",
        existing_type=sa.String(length=100),
        type_=sa.String(length=64),
    )
    op.alter_column(
        "outbox_messages",
        "aggregate_id",
        new_column_name="incident_id",
        existing_type=sa.Uuid(),
    )
    op.alter_column(
        "outbox_messages",
        "available_at",
        new_column_name="next_attempt_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
    )
    op.alter_column(
        "outbox_messages",
        "locked_at",
        new_column_name="claimed_at",
        existing_type=sa.DateTime(timezone=True),
    )
    op.alter_column(
        "outbox_messages",
        "idempotency_key",
        existing_type=sa.String(length=255),
        type_=sa.String(length=160),
    )
    op.alter_column(
        "outbox_messages",
        "last_error",
        existing_type=sa.String(length=2_000),
        type_=sa.String(length=512),
    )
    op.drop_column("outbox_messages", "aggregate_type")
    op.drop_column("outbox_messages", "locked_by")
    op.add_column(
        "outbox_messages",
        sa.Column("destination_id", sa.Uuid(), nullable=True),
    )
    op.add_column(
        "outbox_messages",
        sa.Column(
            "payload_schema_version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
    )
    op.add_column("outbox_messages", sa.Column("claim_token", sa.Uuid(), nullable=True))
    op.add_column(
        "outbox_messages",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_messages",
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_messages",
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
    )
    op.alter_column("outbox_messages", "destination_id", nullable=False)

    op.create_foreign_key(
        op.f("fk_outbox_messages_incident_id_incidents"),
        "outbox_messages",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        op.f("fk_outbox_messages_destination_id_notification_destinations"),
        "outbox_messages",
        "notification_destinations",
        ["destination_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    _create_outbox_constraints()
    _create_outbox_indexes()
    _create_outbox_update_guard()


def downgrade() -> None:
    """Restore the legacy empty envelope without silently losing 6C semantics."""

    op.execute("LOCK TABLE outbox_messages IN ACCESS EXCLUSIVE MODE")
    _reject_populated_outbox()
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_messages_guard_update ON outbox_messages")
    op.execute("DROP FUNCTION IF EXISTS woland_guard_guard_outbox_update()")

    op.drop_index("ix_outbox_messages_destination_status", table_name="outbox_messages")
    op.drop_index("ix_outbox_messages_processing_lease", table_name="outbox_messages")
    op.drop_index("ix_outbox_messages_pending_next_attempt", table_name="outbox_messages")
    _drop_6c_outbox_check_constraints()
    op.drop_constraint(
        op.f("uq_outbox_messages_notification_incident_destination"),
        "outbox_messages",
        type_="unique",
    )
    op.drop_constraint(
        op.f("fk_outbox_messages_destination_id_notification_destinations"),
        "outbox_messages",
        type_="foreignkey",
    )
    op.drop_constraint(
        op.f("fk_outbox_messages_incident_id_incidents"),
        "outbox_messages",
        type_="foreignkey",
    )

    op.drop_column("outbox_messages", "last_error_code")
    op.drop_column("outbox_messages", "failed_at")
    op.drop_column("outbox_messages", "lease_expires_at")
    op.drop_column("outbox_messages", "claim_token")
    op.drop_column("outbox_messages", "payload_schema_version")
    op.drop_column("outbox_messages", "destination_id")
    op.add_column("outbox_messages", sa.Column("locked_by", sa.String(length=100), nullable=True))
    op.add_column(
        "outbox_messages",
        sa.Column(
            "aggregate_type",
            sa.String(length=100),
            server_default=sa.text("'notification'"),
            nullable=False,
        ),
    )
    op.alter_column("outbox_messages", "aggregate_type", server_default=None)
    op.alter_column(
        "outbox_messages",
        "last_error",
        existing_type=sa.String(length=512),
        type_=sa.String(length=2_000),
    )
    op.alter_column(
        "outbox_messages",
        "idempotency_key",
        existing_type=sa.String(length=160),
        type_=sa.String(length=255),
    )
    op.alter_column(
        "outbox_messages",
        "claimed_at",
        new_column_name="locked_at",
        existing_type=sa.DateTime(timezone=True),
    )
    op.alter_column(
        "outbox_messages",
        "next_attempt_at",
        new_column_name="available_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )
    op.alter_column(
        "outbox_messages",
        "incident_id",
        new_column_name="aggregate_id",
        existing_type=sa.Uuid(),
    )
    op.alter_column(
        "outbox_messages",
        "notification_type",
        new_column_name="topic",
        existing_type=sa.String(length=64),
        type_=sa.String(length=100),
    )

    op.create_check_constraint(
        "ck_outbox_messages_attempt_count_nonnegative",
        "outbox_messages",
        "attempt_count >= 0",
    )
    op.create_check_constraint(
        "ck_outbox_messages_max_attempts_positive",
        "outbox_messages",
        "max_attempts > 0",
    )
    op.create_check_constraint(
        "ck_outbox_messages_status_allowed",
        "outbox_messages",
        "status IN ('pending', 'processing', 'delivered', 'failed')",
    )
    op.create_index(
        "ix_outbox_messages_status_available_at",
        "outbox_messages",
        ["status", "available_at"],
        unique=False,
    )
    op.drop_index(
        "ix_notification_destinations_enabled_severity",
        table_name="notification_destinations",
    )
    op.drop_table("notification_destinations")


def _reject_populated_outbox() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM outbox_messages LIMIT 1) THEN
                RAISE EXCEPTION 'cannot migrate populated outbox safely'
                    USING ERRCODE = '55000';
            END IF;
        END
        $$
        """
    )


def _drop_legacy_outbox_constraints() -> None:
    op.execute(
        """
        ALTER TABLE outbox_messages
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_attempt_count_nonnegative,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_max_attempts_positive,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_status_allowed,
            DROP CONSTRAINT IF EXISTS
                ck_outbox_messages_ck_outbox_messages_attempt_count_nonnegative,
            DROP CONSTRAINT IF EXISTS
                ck_outbox_messages_ck_outbox_messages_max_attempts_positive,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_status_allowed
        """
    )


def _drop_6c_outbox_check_constraints() -> None:
    op.execute(
        """
        ALTER TABLE outbox_messages
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_idempotency_key_format,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_state_shape,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_last_error_code_allowed,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_lease_after_claim,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_max_attempts_range,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_attempt_count_range,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_status_allowed,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_payload_is_object,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_payload_schema_version_allowed,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_notification_type_allowed,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_idempotency_key_format,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_state_shape,
            DROP CONSTRAINT IF EXISTS
                ck_outbox_messages_ck_outbox_messages_last_error_code_allowed,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_lease_after_claim,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_max_attempts_range,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_attempt_count_range,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_status_allowed,
            DROP CONSTRAINT IF EXISTS ck_outbox_messages_ck_outbox_messages_payload_is_object,
            DROP CONSTRAINT IF EXISTS
                ck_outbox_messages_ck_outbox_messages_payload_schema_version_allowed,
            DROP CONSTRAINT IF EXISTS
                ck_outbox_messages_ck_outbox_messages_notification_type_allowed
        """
    )


def _create_outbox_constraints() -> None:
    constraints = (
        ("ck_outbox_messages_notification_type_allowed", "notification_type = 'incident.created'"),
        ("ck_outbox_messages_payload_schema_version_allowed", "payload_schema_version = 1"),
        ("ck_outbox_messages_payload_is_object", "jsonb_typeof(payload) = 'object'"),
        (
            "ck_outbox_messages_status_allowed",
            "status IN ('pending', 'processing', 'delivered', 'failed')",
        ),
        (
            "ck_outbox_messages_attempt_count_range",
            "attempt_count >= 0 AND attempt_count <= max_attempts",
        ),
        ("ck_outbox_messages_max_attempts_range", "max_attempts BETWEEN 1 AND 20"),
        (
            "ck_outbox_messages_lease_after_claim",
            "claim_token IS NULL OR lease_expires_at > claimed_at",
        ),
        (
            "ck_outbox_messages_last_error_code_allowed",
            "last_error_code IS NULL OR last_error_code IN ("
            "'adapter_unexpected_error', 'attempts_exhausted', 'destination_disabled', "
            "'destination_unconfigured', 'lease_expired', 'payload_invalid', "
            "'permanent_delivery_error', 'retryable_delivery_error')",
        ),
        (
            "ck_outbox_messages_state_shape",
            "(status = 'pending' AND claim_token IS NULL AND claimed_at IS NULL "
            "AND lease_expires_at IS NULL AND next_attempt_at IS NOT NULL "
            "AND delivered_at IS NULL AND failed_at IS NULL) OR "
            "(status = 'processing' AND claim_token IS NOT NULL AND claimed_at IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND next_attempt_at IS NULL "
            "AND delivered_at IS NULL AND failed_at IS NULL) OR "
            "(status = 'delivered' AND claim_token IS NULL AND claimed_at IS NULL "
            "AND lease_expires_at IS NULL AND next_attempt_at IS NULL "
            "AND delivered_at IS NOT NULL AND failed_at IS NULL "
            "AND last_error_code IS NULL AND last_error IS NULL) OR "
            "(status = 'failed' AND claim_token IS NULL AND claimed_at IS NULL "
            "AND lease_expires_at IS NULL AND next_attempt_at IS NULL "
            "AND delivered_at IS NULL AND failed_at IS NOT NULL "
            "AND last_error_code IS NOT NULL AND last_error IS NOT NULL)",
        ),
        (
            "ck_outbox_messages_idempotency_key_format",
            "idempotency_key ~ '^incident[.]created:"
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:"
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'",
        ),
    )
    for name, condition in constraints:
        op.create_check_constraint(op.f(name), "outbox_messages", condition)
    op.create_unique_constraint(
        op.f("uq_outbox_messages_notification_incident_destination"),
        "outbox_messages",
        ["notification_type", "incident_id", "destination_id"],
    )


def _create_outbox_indexes() -> None:
    op.create_index(
        "ix_outbox_messages_pending_next_attempt",
        "outbox_messages",
        ["next_attempt_at", "created_at", "id"],
        unique=False,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_outbox_messages_processing_lease",
        "outbox_messages",
        ["lease_expires_at", "id"],
        unique=False,
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.create_index(
        "ix_outbox_messages_destination_status",
        "outbox_messages",
        ["destination_id", "status"],
        unique=False,
    )


def _create_outbox_update_guard() -> None:
    op.execute(
        """
        CREATE FUNCTION woland_guard_guard_outbox_update()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF OLD.notification_type IS DISTINCT FROM NEW.notification_type
               OR OLD.incident_id IS DISTINCT FROM NEW.incident_id
               OR OLD.destination_id IS DISTINCT FROM NEW.destination_id
               OR OLD.payload_schema_version IS DISTINCT FROM NEW.payload_schema_version
               OR OLD.payload IS DISTINCT FROM NEW.payload
               OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
               OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                RAISE EXCEPTION 'outbox envelope is immutable' USING ERRCODE = '55000';
            END IF;

            IF OLD.status IS DISTINCT FROM NEW.status
               AND NOT (
                   (OLD.status = 'pending' AND NEW.status = 'processing')
                   OR (
                       OLD.status = 'processing'
                       AND NEW.status IN ('pending', 'delivered', 'failed')
                   )
                   OR (OLD.status = 'failed' AND NEW.status = 'pending')
               ) THEN
                RAISE EXCEPTION 'outbox state transition is not allowed' USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_outbox_messages_guard_update
        BEFORE UPDATE ON outbox_messages
        FOR EACH ROW
        EXECUTE FUNCTION woland_guard_guard_outbox_update()
        """
    )
