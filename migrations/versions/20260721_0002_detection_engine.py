"""Add versioned detection rules, incidents, and evidence.

Revision ID: 20260721_0002
Revises: 20260721_0001
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260721_0002"
down_revision: str | None = "20260721_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create append-only rules, active incidents, and evidence links."""

    op.create_index(
        "ix_events_server_id_event_type_occurred_at",
        "events",
        ["server_id", "event_type", "occurred_at"],
        unique=False,
    )
    op.create_table(
        "detection_rule_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_key", sa.String(length=100), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("checksum", sa.CHAR(length=64), nullable=False),
        sa.Column("definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "is_active = false OR activated_at IS NOT NULL",
            name="ck_detection_rule_versions_active_requires_activated_at",
        ),
        sa.CheckConstraint(
            "char_length(checksum) = 64",
            name="ck_detection_rule_versions_checksum_length",
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_detection_rule_versions_severity_allowed",
        ),
        sa.CheckConstraint(
            "version > 0",
            name="ck_detection_rule_versions_version_positive",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_detection_rule_versions"),
        sa.UniqueConstraint(
            "rule_key",
            "checksum",
            name="uq_detection_rule_versions_key_checksum",
        ),
        sa.UniqueConstraint(
            "rule_key",
            "version",
            name="uq_detection_rule_versions_key_version",
        ),
    )
    op.create_index(
        "uq_detection_rule_versions_active_rule_key",
        "detection_rule_versions",
        ["rule_key"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("server_id", sa.Uuid(), nullable=False),
        sa.Column("rule_version_id", sa.Uuid(), nullable=False),
        sa.Column("rule_key", sa.String(length=100), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'new'"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("explanation", sa.String(length=4_000), nullable=False),
        sa.Column("recommendation", sa.String(length=4_000), nullable=False),
        sa.Column("correlation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("correlation_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("rule_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
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
            "char_length(correlation_hash) = 64",
            name="ck_incidents_correlation_hash_length",
        ),
        sa.CheckConstraint("event_count > 0", name="ck_incidents_event_count_positive"),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_incidents_severity_allowed",
        ),
        sa.CheckConstraint(
            "status IN ('new', 'investigating', 'resolved', 'false_positive')",
            name="ck_incidents_status_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["rule_version_id"],
            ["detection_rule_versions.id"],
            name="fk_incidents_rule_version_id_detection_rule_versions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name="fk_incidents_server_id_servers",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incidents"),
    )
    op.create_index(
        "ix_incidents_rule_key_correlation_hash",
        "incidents",
        ["rule_key", "correlation_hash"],
        unique=False,
    )
    op.create_index(
        "ix_incidents_server_status_last_seen",
        "incidents",
        ["server_id", "status", "last_seen_at"],
        unique=False,
    )
    op.create_index(
        "uq_incidents_active_server_rule_version_correlation",
        "incidents",
        ["server_id", "rule_version_id", "correlation_hash"],
        unique=True,
        postgresql_where=sa.text("status IN ('new', 'investigating')"),
    )
    op.create_table(
        "incident_events",
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column(
            "linked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.id"],
            name="fk_incident_events_event_id_events",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name="fk_incident_events_incident_id_incidents",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("incident_id", "event_id", name="pk_incident_events"),
    )
    op.create_index(
        "ix_incident_events_event_id",
        "incident_events",
        ["event_id"],
        unique=False,
    )


def downgrade() -> None:
    """Return to the complete stage 1–4 schema."""

    op.drop_index("ix_incident_events_event_id", table_name="incident_events")
    op.drop_table("incident_events")
    op.drop_index(
        "uq_incidents_active_server_rule_version_correlation",
        table_name="incidents",
    )
    op.drop_index("ix_incidents_server_status_last_seen", table_name="incidents")
    op.drop_index("ix_incidents_rule_key_correlation_hash", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(
        "uq_detection_rule_versions_active_rule_key",
        table_name="detection_rule_versions",
    )
    op.drop_table("detection_rule_versions")
    op.drop_index("ix_events_server_id_event_type_occurred_at", table_name="events")
