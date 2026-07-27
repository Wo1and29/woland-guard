"""PostgreSQL regression tests for guarded stage 6C migration boundaries."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from tests.integration.test_outbox_worker import _seed_outbox
from woland_guard_control_plane.database import get_engine

pytestmark = pytest.mark.integration


def test_migration_installs_strict_canonical_idempotency_constraint() -> None:
    with get_engine().connect() as connection:
        definition = connection.scalar(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'outbox_messages'::regclass "
                "AND conname = 'ck_outbox_messages_idempotency_key_format'"
            )
        )

    assert definition is not None
    assert "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" in definition
    assert "[0-9a-f-]{36}" not in definition


def test_upgrade_and_downgrade_refuse_incompatible_populated_outbox() -> None:
    config = Config("alembic.ini")

    command.downgrade(config, "20260722_0004")
    try:
        with get_engine().begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO outbox_messages "
                    "(id, topic, aggregate_type, aggregate_id, payload, idempotency_key) "
                    "VALUES (:id, 'legacy.notification', 'incident', :aggregate_id, "
                    "'{}'::jsonb, :idempotency_key)"
                ),
                {
                    "id": uuid4(),
                    "aggregate_id": uuid4(),
                    "idempotency_key": f"legacy-{uuid4()}",
                },
            )
        with pytest.raises(DBAPIError, match="cannot migrate populated outbox safely"):
            command.upgrade(config, "head")
    finally:
        with get_engine().begin() as connection:
            connection.execute(text("DELETE FROM outbox_messages"))
        command.upgrade(config, "head")

    _seed_outbox(now=datetime.now(UTC))
    try:
        with get_engine().begin() as connection:
            connection.execute(text("UPDATE notification_destinations SET enabled = false"))
            connection.execute(text("DELETE FROM telegram_destination_configs"))
        command.downgrade(config, "20260726_0005")
        with pytest.raises(DBAPIError, match="cannot migrate populated outbox safely"):
            command.downgrade(config, "20260722_0004")
    finally:
        with get_engine().begin() as connection:
            connection.execute(text("DELETE FROM outbox_messages"))
        command.downgrade(config, "20260722_0004")
        command.upgrade(config, "head")
