"""Schema guarantees added by the 9C dry-run IP block migration."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from woland_guard_control_plane.database import get_engine

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("table", ["ip_block_plans", "ip_block_allowlist_entries"])
def test_migration_creates_the_ip_block_tables(table: str) -> None:
    with get_engine().connect() as connection:
        exists = connection.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = :table"
            ),
            {"table": table},
        ).scalar_one_or_none()
    assert exists == 1


def test_no_stray_sequence_was_created_for_either_table() -> None:
    with get_engine().connect() as connection:
        sequences = connection.execute(
            text("SELECT sequencename FROM pg_sequences WHERE sequencename LIKE 'ip_block%'")
        ).all()
    assert sequences == []


def test_ip_address_must_be_a_single_host() -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint AS con "
                "JOIN pg_class AS c ON c.oid = con.conrelid "
                "WHERE c.relname = 'ip_block_plans' "
                "AND con.conname = 'ck_ip_block_plans_ip_address_is_single_host'"
            )
        ).scalar_one()
    assert "family(ip_address)" in definition
    assert "masklen(ip_address)" in definition


def test_decision_shape_constraint_ties_status_to_decision_fields() -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint AS con "
                "JOIN pg_class AS c ON c.oid = con.conrelid "
                "WHERE c.relname = 'ip_block_plans' "
                "AND con.conname = 'ck_ip_block_plans_decision_shape'"
            )
        ).scalar_one()
    assert "decided_by_operator_id" in definition
    assert "decided_at" in definition


@pytest.mark.parametrize(
    ("table", "index_name"),
    [
        ("ip_block_plans", "uq_ip_block_plans_active_incident_ip"),
        ("ip_block_allowlist_entries", "uq_ip_block_allowlist_entries_active_cidr"),
    ],
)
def test_active_uniqueness_indexes_are_partial(table: str, index_name: str) -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text("SELECT indexdef FROM pg_indexes WHERE tablename = :table AND indexname = :name"),
            {"table": table, "name": index_name},
        ).scalar_one()
    assert "UNIQUE" in definition


def test_active_incident_ip_index_is_scoped_to_proposed_status() -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'uq_ip_block_plans_active_incident_ip'"
            )
        ).scalar_one()
    assert "status" in definition and "'proposed'" in definition


def test_active_allowlist_index_is_scoped_to_unrevoked_entries() -> None:
    with get_engine().connect() as connection:
        definition = connection.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'uq_ip_block_allowlist_entries_active_cidr'"
            )
        ).scalar_one()
    assert "revoked_at IS NULL" in definition
