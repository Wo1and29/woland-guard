"""Add indexes demonstrated by representative Dashboard query plans.

Revision ID: 20260728_0008
Revises: 20260727_0007
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260728_0008"
down_revision: str | None = "20260727_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add only the ordering indexes justified by EXPLAIN evidence."""

    op.create_index(
        "ix_servers_lower_name_id",
        "servers",
        [sa.text("lower(name)"), "id"],
        unique=False,
    )
    op.execute(
        "CREATE INDEX ix_servers_lower_name_pattern ON servers (lower(name) text_pattern_ops)"
    )
    op.execute(
        "CREATE INDEX ix_servers_lower_hostname_pattern "
        "ON servers (lower(hostname) text_pattern_ops)"
    )
    op.create_index(
        "ix_incident_events_incident_linked_event",
        "incident_events",
        ["incident_id", "linked_at", "event_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the optional Dashboard performance indexes without deleting data."""

    op.drop_index(
        "ix_incident_events_incident_linked_event",
        table_name="incident_events",
    )
    op.drop_index("ix_servers_lower_hostname_pattern", table_name="servers")
    op.drop_index("ix_servers_lower_name_pattern", table_name="servers")
    op.drop_index("ix_servers_lower_name_id", table_name="servers")
