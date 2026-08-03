"""Add the per-operator Telegram reply language preference.

Revision ID: 20260803_0014
Revises: 20260803_0013
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260803_0014"
down_revision: str | None = "20260803_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add an opt-in reply language, nullable so nothing is assumed for existing links.

    A null preference is not "Russian": it means the operator has not run /lang,
    and the bot falls back to the language tag the Telegram client reports.
    """

    op.execute("LOCK TABLE operator_telegram_links IN SHARE ROW EXCLUSIVE MODE")
    op.add_column(
        "operator_telegram_links",
        sa.Column("language", sa.String(length=2), nullable=True),
    )
    op.create_check_constraint(
        "ck_operator_telegram_links_language_allowed",
        "operator_telegram_links",
        "language IS NULL OR language IN ('ru', 'en')",
    )


def downgrade() -> None:
    op.execute("LOCK TABLE operator_telegram_links IN SHARE ROW EXCLUSIVE MODE")
    op.drop_constraint(
        "ck_operator_telegram_links_language_allowed",
        "operator_telegram_links",
        type_="check",
    )
    op.drop_column("operator_telegram_links", "language")
