"""Add outbound Telegram provider configuration and safety invariants.

Revision ID: 20260727_0006
Revises: 20260726_0005
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260727_0006"
down_revision: str | None = "20260726_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TELEGRAM_ERROR_CODES = (
    "telegram_protocol_error",
    "telegram_runtime_copy_invalid",
    "telegram_runtime_copy_unavailable",
    "telegram_staging_file_invalid",
    "telegram_staging_file_missing",
)


def upgrade() -> None:
    """Create the provider table without silently enabling incomplete routes."""

    op.execute("LOCK TABLE notification_destinations IN ACCESS EXCLUSIVE MODE")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM notification_destinations
                WHERE adapter_kind = 'telegram' AND enabled
            ) THEN
                RAISE EXCEPTION 'cannot migrate enabled Telegram destination without config'
                    USING ERRCODE = '55000';
            END IF;
        END
        $$
        """
    )
    op.create_table(
        "telegram_destination_configs",
        sa.Column("destination_id", sa.Uuid(), nullable=False),
        sa.Column("chat_id", sa.BigInteger(), nullable=False),
        sa.Column("token_file_name", sa.String(length=128), nullable=False),
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
            "chat_id <> 0 AND chat_id BETWEEN -4503599627370495 AND 4503599627370495",
            name="chat_id_safe_range",
        ),
        sa.CheckConstraint(
            "token_file_name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'",
            name="token_file_name_safe",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name="timestamps_ordered",
        ),
        sa.ForeignKeyConstraint(
            ["destination_id"],
            ["notification_destinations.id"],
            name="fk_telegram_destination_configs_destination_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "destination_id",
            name="pk_telegram_destination_configs",
        ),
        sa.UniqueConstraint(
            "chat_id",
            "token_file_name",
            name="uq_telegram_destination_configs_chat_token_file",
        ),
    )
    _replace_outbox_error_constraint(include_telegram=True)
    _create_provider_guards()


def downgrade() -> None:
    """Remove 6D only when no provider data or 6D lifecycle code would be lost."""

    op.execute("LOCK TABLE telegram_destination_configs IN ACCESS EXCLUSIVE MODE")
    op.execute("LOCK TABLE outbox_messages IN ACCESS EXCLUSIVE MODE")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM telegram_destination_configs LIMIT 1) THEN
                RAISE EXCEPTION 'cannot downgrade populated Telegram configuration safely'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM outbox_messages WHERE last_error_code IN (
                    'telegram_protocol_error',
                    'telegram_runtime_copy_invalid',
                    'telegram_runtime_copy_unavailable',
                    'telegram_staging_file_invalid',
                    'telegram_staging_file_missing'
                ) LIMIT 1
            ) THEN
                RAISE EXCEPTION 'cannot downgrade Telegram outbox error state safely'
                    USING ERRCODE = '55000';
            END IF;
        END
        $$
        """
    )
    op.execute("DROP TRIGGER IF EXISTS trg_telegram_config_guard ON telegram_destination_configs")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_telegram_config_delete_guard ON telegram_destination_configs"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_notification_destination_telegram_guard "
        "ON notification_destinations"
    )
    op.execute("DROP FUNCTION IF EXISTS woland_guard_validate_telegram_config()")
    op.execute("DROP FUNCTION IF EXISTS woland_guard_guard_telegram_config_delete()")
    op.execute("DROP FUNCTION IF EXISTS woland_guard_guard_destination_telegram_state()")
    _replace_outbox_error_constraint(include_telegram=False)
    op.drop_table("telegram_destination_configs")


def _replace_outbox_error_constraint(*, include_telegram: bool) -> None:
    op.drop_constraint(
        op.f("ck_outbox_messages_last_error_code_allowed"),
        "outbox_messages",
        type_="check",
    )
    codes = [
        "adapter_unexpected_error",
        "attempts_exhausted",
        "destination_disabled",
        "destination_unconfigured",
        "lease_expired",
        "payload_invalid",
        "permanent_delivery_error",
        "retryable_delivery_error",
    ]
    if include_telegram:
        codes.extend(_TELEGRAM_ERROR_CODES)
    allowed = ", ".join(f"'{code}'" for code in codes)
    op.create_check_constraint(
        op.f("ck_outbox_messages_last_error_code_allowed"),
        "outbox_messages",
        f"last_error_code IS NULL OR last_error_code IN ({allowed})",
    )


def _create_provider_guards() -> None:
    op.execute(
        """
        CREATE FUNCTION woland_guard_validate_telegram_config()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            PERFORM 1 FROM notification_destinations
            WHERE id = NEW.destination_id AND adapter_kind = 'telegram'
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Telegram config requires a Telegram destination'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_telegram_config_guard
        BEFORE INSERT OR UPDATE ON telegram_destination_configs
        FOR EACH ROW EXECUTE FUNCTION woland_guard_validate_telegram_config()
        """
    )
    op.execute(
        """
        CREATE FUNCTION woland_guard_guard_destination_telegram_state()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'UPDATE'
               AND OLD.adapter_kind IS DISTINCT FROM NEW.adapter_kind
               AND EXISTS (
                   SELECT 1 FROM telegram_destination_configs
                   WHERE destination_id = OLD.id
               ) THEN
                RAISE EXCEPTION 'destination adapter kind is protected by provider config'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.adapter_kind = 'telegram' AND NEW.enabled
               AND NOT EXISTS (
                   SELECT 1 FROM telegram_destination_configs
                   WHERE destination_id = NEW.id
               ) THEN
                RAISE EXCEPTION 'enabled Telegram destination requires provider config'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_notification_destination_telegram_guard
        BEFORE INSERT OR UPDATE ON notification_destinations
        FOR EACH ROW EXECUTE FUNCTION woland_guard_guard_destination_telegram_state()
        """
    )
    op.execute(
        """
        CREATE FUNCTION woland_guard_guard_telegram_config_delete()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM notification_destinations
                WHERE id = OLD.destination_id AND enabled
                FOR UPDATE
            ) THEN
                RAISE EXCEPTION 'enabled Telegram destination config cannot be deleted'
                    USING ERRCODE = '55000';
            END IF;
            RETURN OLD;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_telegram_config_delete_guard
        BEFORE DELETE ON telegram_destination_configs
        FOR EACH ROW EXECUTE FUNCTION woland_guard_guard_telegram_config_delete()
        """
    )
