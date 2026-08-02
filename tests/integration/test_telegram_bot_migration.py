"""Schema guarantees added by the 9A inbound Telegram migration."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from woland_guard_control_plane.database import get_engine

pytestmark = pytest.mark.integration

_AUTH_METHOD_CONSTRAINTS = (
    ("incident_history", "ck_incident_history_auth_method_type_allowed"),
    ("audit_log_entries", "ck_audit_log_entries_auth_method_type_allowed"),
    ("incident_comments", "ck_incident_comments_auth_method_type_allowed"),
)


@pytest.mark.parametrize("table", ["operator_telegram_links", "telegram_bot_offsets"])
def test_migration_creates_the_inbound_tables(table: str) -> None:
    with get_engine().connect() as connection:
        exists = connection.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = :table"
            ),
            {"table": table},
        ).scalar_one_or_none()
    assert exists == 1


@pytest.mark.parametrize(("table", "constraint"), _AUTH_METHOD_CONSTRAINTS)
def test_auth_method_allowlists_include_telegram(table: str, constraint: str) -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint AS con "
                "JOIN pg_class AS c ON c.oid = con.conrelid "
                "WHERE c.relname = :table AND con.conname = :constraint"
            ),
            {"table": table, "constraint": constraint},
        ).scalar_one()
    assert "'telegram'" in definition
    assert "'operator_api_key'" in definition
    assert "'web_session'" in definition


def test_telegram_user_id_column_is_wider_than_thirty_two_bits() -> None:
    with get_engine().connect() as connection:
        data_type = connection.execute(
            text(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name = 'operator_telegram_links' "
                "AND column_name = 'telegram_user_id'"
            )
        ).scalar_one()
    assert data_type == "bigint"


@pytest.mark.parametrize(
    "index_name",
    [
        "uq_operator_telegram_links_active_telegram_user",
        "uq_operator_telegram_links_active_operator",
    ],
)
def test_active_links_are_unique_only_while_not_revoked(index_name: str) -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = :name"),
            {"name": index_name},
        ).scalar_one()
    assert "UNIQUE" in definition
    assert "revoked_at IS NULL" in definition


def test_offset_table_admits_exactly_one_row() -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint AS con "
                "JOIN pg_class AS c ON c.oid = con.conrelid "
                "WHERE c.relname = 'telegram_bot_offsets' "
                "AND con.conname = 'ck_telegram_bot_offsets_single_row'"
            )
        ).scalar_one()
    assert "id = 1" in definition
