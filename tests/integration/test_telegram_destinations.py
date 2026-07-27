"""PostgreSQL regressions for provider configuration and local destination lifecycle."""

import getpass
import sys
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError

from woland_guard_control_plane import cli
from woland_guard_control_plane.application.notification_destinations import (
    DestinationSummary,
    NotificationDestinationManagementError,
    create_telegram_destination,
    get_notification_destination,
    list_notification_destinations,
    set_notification_destination_enabled,
    update_telegram_destination,
)
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    NotificationDestination,
    NotificationSeverity,
    TelegramDestinationConfig,
)

pytestmark = pytest.mark.integration


def _ready(_name: str) -> bool:
    return True


def _not_ready(_name: str) -> bool:
    return False


def _create(*, ready: bool = True) -> tuple[DestinationSummary, str]:
    token_file_name = f"{uuid4().hex}.token"
    with get_session_factory().begin() as session:
        summary = create_telegram_destination(
            session,
            chat_id=(uuid4().int % (2**52 - 1)) + 1,
            token_file_name=token_file_name,
            minimum_severity=NotificationSeverity.HIGH,
            staging_readiness=_ready if ready else _not_ready,
        )
    return summary, token_file_name


def test_local_lifecycle_is_disabled_first_redacted_and_audited() -> None:
    created, token_file_name = _create()
    assert created.enabled is False
    assert created.configured is True
    assert created.staging_file_ready is True

    with get_session_factory().begin() as session:
        enabled = set_notification_destination_enabled(
            session,
            destination_id=created.destination_id,
            enabled=True,
            staging_readiness=_ready,
        )
        updated = update_telegram_destination(
            session,
            destination_id=created.destination_id,
            minimum_severity=NotificationSeverity.CRITICAL,
            staging_readiness=_ready,
        )
        disabled = set_notification_destination_enabled(
            session,
            destination_id=created.destination_id,
            enabled=False,
            staging_readiness=_ready,
        )

    assert enabled.enabled is True
    assert updated.minimum_severity == NotificationSeverity.CRITICAL.value
    assert disabled.enabled is False
    assert not hasattr(disabled, "chat_id")
    assert not hasattr(disabled, "token_file_name")

    with get_session_factory()() as session:
        listed = list_notification_destinations(session, staging_readiness=_ready)
        shown = get_notification_destination(
            session,
            destination_id=created.destination_id,
            staging_readiness=_ready,
        )
        audit_entries = session.scalars(
            select(AuditLogEntry).order_by(AuditLogEntry.created_at, AuditLogEntry.id)
        ).all()
        provider_config = session.get(TelegramDestinationConfig, created.destination_id)

    assert listed == [shown]
    assert provider_config is not None
    assert [entry.action for entry in audit_entries] == [
        "notification_destination.created",
        "notification_destination.enabled",
        "notification_destination.updated",
        "notification_destination.disabled",
    ]
    serialized = " ".join(str(entry.details) for entry in audit_entries)
    assert str(provider_config.chat_id) not in serialized
    assert token_file_name not in serialized
    assert set(audit_entries[0].details) == {"adapter_kind", "minimum_severity"}


def test_enable_requires_staging_readiness_and_rolls_back_without_audit() -> None:
    created, _token_file_name = _create(ready=False)

    with pytest.raises(NotificationDestinationManagementError):
        with get_session_factory().begin() as session:
            set_notification_destination_enabled(
                session,
                destination_id=created.destination_id,
                enabled=True,
                staging_readiness=_not_ready,
            )

    with get_session_factory()() as session:
        destination = session.get(NotificationDestination, created.destination_id)
        assert destination is not None
        assert destination.enabled is False
        assert session.scalar(select(func.count()).select_from(AuditLogEntry)) == 1


def test_postgresql_rejects_enabled_telegram_without_provider_config() -> None:
    with pytest.raises(DBAPIError, match="requires provider config"):
        with get_engine().begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO notification_destinations "
                    "(id, adapter_kind, enabled, minimum_severity) "
                    "VALUES (:id, 'telegram', true, 'low')"
                ),
                {"id": uuid4()},
            )


def test_postgresql_rejects_nontelegram_parent_for_provider_config() -> None:
    with pytest.raises(DBAPIError, match="CheckViolation"):
        with get_engine().begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO notification_destinations "
                    "(id, adapter_kind, enabled, minimum_severity) "
                    "VALUES (:id, 'synthetic', false, 'low')"
                ),
                {"id": uuid4()},
            )


def test_postgresql_rejects_adapter_kind_change_when_config_exists() -> None:
    created, _token_file_name = _create()

    with pytest.raises(DBAPIError, match="adapter kind is protected"):
        with get_session_factory().begin() as session:
            session.execute(
                update(NotificationDestination)
                .where(NotificationDestination.id == created.destination_id)
                .values(adapter_kind="synthetic", updated_at=datetime.now(UTC))
            )


def test_postgresql_rejects_provider_config_delete_while_enabled() -> None:
    created, _token_file_name = _create()
    with get_session_factory().begin() as session:
        set_notification_destination_enabled(
            session,
            destination_id=created.destination_id,
            enabled=True,
            staging_readiness=_ready,
        )

    with pytest.raises(DBAPIError, match="config cannot be deleted"):
        with get_engine().begin() as connection:
            connection.execute(
                text(
                    "DELETE FROM telegram_destination_configs "
                    "WHERE destination_id = :destination_id"
                ),
                {"destination_id": created.destination_id},
            )


@pytest.mark.parametrize(
    ("chat_id", "token_file_name", "constraint"),
    [
        (0, "safe.token", "chat_id_safe_range"),
        (2**52, "safe.token", "chat_id_safe_range"),
        (123, "../unsafe", "token_file_name_safe"),
    ],
)
def test_postgresql_rejects_invalid_provider_configuration(
    chat_id: int,
    token_file_name: str,
    constraint: str,
) -> None:
    destination_id = uuid4()
    with pytest.raises(DBAPIError, match="CheckViolation"):
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
                    "VALUES (:destination_id, :chat_id, :token_file_name)"
                ),
                {
                    "destination_id": destination_id,
                    "chat_id": chat_id,
                    "token_file_name": token_file_name,
                },
            )
    assert constraint in {"chat_id_safe_range", "token_file_name_safe"}


def test_provider_configuration_is_one_to_one() -> None:
    created, token_file_name = _create()
    with get_session_factory()() as session:
        config = session.get(TelegramDestinationConfig, created.destination_id)
        assert config is not None
        assert config.token_file_name == token_file_name
        assert session.scalar(select(func.count()).select_from(TelegramDestinationConfig)) == 1


def test_admin_cli_reports_only_staging_readiness_without_provider_values(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary_chat_id = "4001002003"
    canary_file_name = "cli-canary-file.token"

    class ReadySynchronizer:
        @staticmethod
        def staging_file_ready(_name: str) -> bool:
            return True

    monkeypatch.setattr(cli, "TelegramTokenSynchronizer", ReadySynchronizer)
    monkeypatch.setattr(getpass, "getpass", lambda _prompt: canary_chat_id)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "woland-guard-admin",
            "create-telegram-destination",
            "--token-file-name",
            canary_file_name,
            "--minimum-severity",
            "medium",
        ],
    )

    cli.main()

    output = capsys.readouterr()
    combined = output.out + output.err
    assert "configured=true" in combined
    assert "staging_file_ready=true" in combined
    assert canary_chat_id not in combined
    assert canary_file_name not in combined
    assert "token_file_healthy" not in combined
