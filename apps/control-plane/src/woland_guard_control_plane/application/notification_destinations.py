"""Local-only management of provider-neutral Telegram destinations."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import record_local_cli_action
from woland_guard_control_plane.infrastructure.database.models import (
    NotificationAdapterKind,
    NotificationDestination,
    NotificationSeverity,
    TelegramDestinationConfig,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    validate_token_file_name,
)

StagingReadiness = Callable[[str], bool]


class NotificationDestinationManagementError(RuntimeError):
    """Safe application error without provider configuration values."""


@dataclass(frozen=True, slots=True)
class DestinationSummary:
    destination_id: UUID
    adapter_kind: str
    enabled: bool
    minimum_severity: str
    configured: bool
    staging_file_ready: bool
    created_at: datetime
    updated_at: datetime


def create_telegram_destination(
    session: Session,
    *,
    chat_id: int,
    token_file_name: str,
    minimum_severity: NotificationSeverity,
    staging_readiness: StagingReadiness,
    now: datetime | None = None,
) -> DestinationSummary:
    """Create a disabled destination and its provider row in one transaction."""

    _validate_chat_id(chat_id)
    name = validate_token_file_name(token_file_name)
    timestamp = now or datetime.now(UTC)
    destination = NotificationDestination(
        adapter_kind=NotificationAdapterKind.TELEGRAM.value,
        enabled=False,
        minimum_severity=minimum_severity.value,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(destination)
    session.flush()
    config = TelegramDestinationConfig(
        destination_id=destination.id,
        chat_id=chat_id,
        token_file_name=name,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(config)
    record_local_cli_action(
        session,
        action="notification_destination.created",
        target_type="notification_destination",
        target_id=destination.id,
        details={
            "adapter_kind": destination.adapter_kind,
            "minimum_severity": destination.minimum_severity,
        },
    )
    session.flush()
    return _summary(destination, config, staging_readiness)


def list_notification_destinations(
    session: Session,
    *,
    staging_readiness: StagingReadiness,
) -> list[DestinationSummary]:
    rows = session.execute(
        select(NotificationDestination, TelegramDestinationConfig)
        .outerjoin(
            TelegramDestinationConfig,
            TelegramDestinationConfig.destination_id == NotificationDestination.id,
        )
        .order_by(NotificationDestination.created_at, NotificationDestination.id)
    ).all()
    return [_summary(destination, config, staging_readiness) for destination, config in rows]


def get_notification_destination(
    session: Session,
    *,
    destination_id: UUID,
    staging_readiness: StagingReadiness,
) -> DestinationSummary:
    destination, config = _load_pair(session, destination_id=destination_id, lock=False)
    return _summary(destination, config, staging_readiness)


def set_notification_destination_enabled(
    session: Session,
    *,
    destination_id: UUID,
    enabled: bool,
    staging_readiness: StagingReadiness,
    now: datetime | None = None,
) -> DestinationSummary:
    destination, config = _load_pair(session, destination_id=destination_id, lock=True)
    if enabled and (config is None or not staging_readiness(config.token_file_name)):
        raise NotificationDestinationManagementError(
            "Telegram destination staging file is not ready."
        )
    if destination.enabled != enabled:
        destination.enabled = enabled
        destination.updated_at = now or datetime.now(UTC)
        record_local_cli_action(
            session,
            action=(
                "notification_destination.enabled"
                if enabled
                else "notification_destination.disabled"
            ),
            target_type="notification_destination",
            target_id=destination.id,
            details={
                "adapter_kind": destination.adapter_kind,
                "minimum_severity": destination.minimum_severity,
            },
        )
        session.flush()
    return _summary(destination, config, staging_readiness)


def update_telegram_destination(
    session: Session,
    *,
    destination_id: UUID,
    staging_readiness: StagingReadiness,
    chat_id: int | None = None,
    token_file_name: str | None = None,
    minimum_severity: NotificationSeverity | None = None,
    now: datetime | None = None,
) -> DestinationSummary:
    """Update safe routing metadata without ever accepting token content."""

    if chat_id is None and token_file_name is None and minimum_severity is None:
        raise NotificationDestinationManagementError("No destination update was requested.")
    destination, config = _load_pair(session, destination_id=destination_id, lock=True)
    if config is None or destination.adapter_kind != NotificationAdapterKind.TELEGRAM.value:
        raise NotificationDestinationManagementError("Telegram destination is not configured.")
    proposed_chat_id = config.chat_id if chat_id is None else chat_id
    proposed_name = (
        config.token_file_name
        if token_file_name is None
        else validate_token_file_name(token_file_name)
    )
    _validate_chat_id(proposed_chat_id)
    proposed_severity = (
        destination.minimum_severity if minimum_severity is None else minimum_severity.value
    )
    if destination.enabled and not staging_readiness(proposed_name):
        raise NotificationDestinationManagementError(
            "Telegram destination staging file is not ready."
        )
    from_severity = destination.minimum_severity
    chat_changed = config.chat_id != proposed_chat_id
    file_changed = config.token_file_name != proposed_name
    config.chat_id = proposed_chat_id
    config.token_file_name = proposed_name
    destination.minimum_severity = proposed_severity
    timestamp = now or datetime.now(UTC)
    config.updated_at = timestamp
    destination.updated_at = timestamp
    record_local_cli_action(
        session,
        action="notification_destination.updated",
        target_type="notification_destination",
        target_id=destination.id,
        details={
            "adapter_kind": destination.adapter_kind,
            "from_minimum_severity": from_severity,
            "to_minimum_severity": proposed_severity,
            "chat_id_changed": chat_changed,
            "token_file_changed": file_changed,
        },
    )
    session.flush()
    return _summary(destination, config, staging_readiness)


def _load_pair(
    session: Session,
    *,
    destination_id: UUID,
    lock: bool,
) -> tuple[NotificationDestination, TelegramDestinationConfig | None]:
    if lock:
        destination = session.scalar(
            select(NotificationDestination)
            .where(NotificationDestination.id == destination_id)
            .with_for_update()
        )
        if destination is None:
            raise NotificationDestinationManagementError("Notification destination was not found.")
        config = session.scalar(
            select(TelegramDestinationConfig)
            .where(TelegramDestinationConfig.destination_id == destination_id)
            .with_for_update()
        )
        return destination, config
    statement = (
        select(NotificationDestination, TelegramDestinationConfig)
        .outerjoin(
            TelegramDestinationConfig,
            TelegramDestinationConfig.destination_id == NotificationDestination.id,
        )
        .where(NotificationDestination.id == destination_id)
    )
    row = session.execute(statement).one_or_none()
    if row is None:
        raise NotificationDestinationManagementError("Notification destination was not found.")
    return row._tuple()


def _summary(
    destination: NotificationDestination,
    config: TelegramDestinationConfig | None,
    staging_readiness: StagingReadiness,
) -> DestinationSummary:
    return DestinationSummary(
        destination_id=destination.id,
        adapter_kind=destination.adapter_kind,
        enabled=destination.enabled,
        minimum_severity=destination.minimum_severity,
        configured=config is not None,
        staging_file_ready=(False if config is None else staging_readiness(config.token_file_name)),
        created_at=destination.created_at,
        updated_at=destination.updated_at,
    )


def _validate_chat_id(value: object) -> None:
    if type(value) is not int or value == 0 or not -(2**52 - 1) <= value <= 2**52 - 1:
        raise NotificationDestinationManagementError("Telegram chat identifier is invalid.")
