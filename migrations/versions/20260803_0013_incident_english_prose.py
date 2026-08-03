"""Add optional English incident prose alongside the frozen Russian columns.

Revision ID: 20260803_0013
Revises: 20260802_0012
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260803_0013"
down_revision: str | None = "20260802_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRANSLATED_COLUMNS = (
    ("title_en", 255),
    ("explanation_en", 4_000),
    ("recommendation_en", 4_000),
)


def upgrade() -> None:
    """Add nullable English prose without inventing text for historical rows.

    The columns stay nullable on purpose: incidents detected before the rules
    carried English prose have no translation, and the Dashboard falls back to
    the Russian column for them rather than backfilling invented content.
    """

    op.execute("LOCK TABLE incidents IN SHARE ROW EXCLUSIVE MODE")
    for name, length in _TRANSLATED_COLUMNS:
        op.add_column("incidents", sa.Column(name, sa.String(length=length), nullable=True))


def downgrade() -> None:
    op.execute("LOCK TABLE incidents IN SHARE ROW EXCLUSIVE MODE")
    for name, _ in reversed(_TRANSLATED_COLUMNS):
        op.drop_column("incidents", name)
