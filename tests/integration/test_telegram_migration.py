"""Guarded Alembic boundaries for outbound Telegram configuration."""

from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from woland_guard_control_plane.database import get_engine

pytestmark = pytest.mark.integration

REVISION_0005 = "20260726_0005"


def test_migration_installs_provider_table_triggers_and_error_allowlist() -> None:
    expected_triggers = {
        "trg_notification_destination_telegram_guard",
        "trg_telegram_config_delete_guard",
        "trg_telegram_config_guard",
    }
    with get_engine().connect() as connection:
        triggers = set(
            connection.execute(
                text(
                    "SELECT tgname FROM pg_trigger "
                    "WHERE NOT tgisinternal AND tgname LIKE 'trg_%telegram%'"
                )
            ).scalars()
        )
        definition = connection.scalar(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'outbox_messages'::regclass "
                "AND conname = 'ck_outbox_messages_last_error_code_allowed'"
            )
        )
        primary_key = connection.scalar(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'telegram_destination_configs'::regclass "
                "AND contype = 'p'"
            )
        )

    assert expected_triggers <= triggers
    assert definition is not None
    for code in (
        "telegram_protocol_error",
        "telegram_runtime_copy_invalid",
        "telegram_runtime_copy_unavailable",
        "telegram_staging_file_invalid",
        "telegram_staging_file_missing",
    ):
        assert code in definition
    assert primary_key == "PRIMARY KEY (destination_id)"


def test_upgrade_refuses_existing_enabled_telegram_destination() -> None:
    config = Config("alembic.ini")
    command.downgrade(config, REVISION_0005)
    try:
        with get_engine().begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO notification_destinations "
                    "(id, adapter_kind, enabled, minimum_severity) "
                    "VALUES (:id, 'telegram', true, 'low')"
                ),
                {"id": uuid4()},
            )
        with pytest.raises(DBAPIError, match="cannot migrate enabled Telegram destination"):
            command.upgrade(config, "head")
    finally:
        with get_engine().begin() as connection:
            connection.execute(text("DELETE FROM notification_destinations"))
        command.upgrade(config, "head")


def test_downgrade_refuses_populated_provider_configuration() -> None:
    config = Config("alembic.ini")
    destination_id = uuid4()
    with get_engine().begin() as connection:
        connection.execute(
            text(
                "INSERT INTO notification_destinations "
                "(id, adapter_kind, enabled, minimum_severity) "
                "VALUES (:id, 'telegram', false, 'low')"
            ),
            {"id": destination_id},
        )
        connection.execute(
            text(
                "INSERT INTO telegram_destination_configs "
                "(destination_id, chat_id, token_file_name) "
                "VALUES (:id, 123456, 'migration.token')"
            ),
            {"id": destination_id},
        )
    try:
        with pytest.raises(DBAPIError, match="cannot downgrade populated Telegram"):
            command.downgrade(config, REVISION_0005)
    finally:
        with get_engine().begin() as connection:
            connection.execute(text("DELETE FROM telegram_destination_configs"))
            connection.execute(text("DELETE FROM notification_destinations"))
        command.downgrade(config, REVISION_0005)
        command.upgrade(config, "head")
