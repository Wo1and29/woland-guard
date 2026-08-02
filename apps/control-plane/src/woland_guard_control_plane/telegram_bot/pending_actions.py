"""Durable single-slot storage for a Telegram terminal-status reason prompt."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from woland_guard_control_plane.infrastructure.database.models import (
    IncidentStatus,
    TelegramPendingAction,
)

_TERMINAL_STATUSES = frozenset({IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE})


@dataclass(frozen=True, slots=True)
class PendingIncidentAction:
    """A durable, not-yet-expired reason prompt for one Telegram account."""

    incident_id: UUID
    target_status: IncidentStatus
    expected_version: int


@dataclass(frozen=True, slots=True)
class PendingActionLookup:
    """The live action, if any, and whether an expired row was just deleted."""

    action: PendingIncidentAction | None
    was_expired: bool


def store_pending_action(
    session: Session,
    *,
    telegram_user_id: int,
    incident_id: UUID,
    target_status: IncidentStatus,
    expected_version: int,
    ttl_seconds: int,
    now: datetime,
) -> None:
    """Replace any earlier pending action for this account with a new one."""

    if target_status not in _TERMINAL_STATUSES:
        raise ValueError("pending actions only exist for terminal-status transitions")
    if ttl_seconds < 1:
        raise ValueError("pending action TTL must be positive")
    expires_at = now + timedelta(seconds=ttl_seconds)
    statement = (
        insert(TelegramPendingAction)
        .values(
            telegram_user_id=telegram_user_id,
            incident_id=incident_id,
            target_status=target_status.value,
            expected_version=expected_version,
            created_at=now,
            expires_at=expires_at,
        )
        .on_conflict_do_update(
            index_elements=[TelegramPendingAction.telegram_user_id],
            set_={
                "incident_id": incident_id,
                "target_status": target_status.value,
                "expected_version": expected_version,
                "created_at": now,
                "expires_at": expires_at,
            },
        )
    )
    session.execute(statement)


def load_pending_action(
    session: Session,
    *,
    telegram_user_id: int,
    now: datetime,
) -> PendingActionLookup:
    """Return the live pending action, lazily deleting it if it has expired.

    Distinguishing "never had one" from "had one, now expired" lets the caller
    tell the user their reason arrived too late instead of silently ignoring it.
    """

    stored = session.scalars(
        select(TelegramPendingAction).where(
            TelegramPendingAction.telegram_user_id == telegram_user_id
        )
    ).one_or_none()
    if stored is None:
        return PendingActionLookup(action=None, was_expired=False)
    if _as_utc(stored.expires_at) <= now:
        delete_pending_action(session, telegram_user_id=telegram_user_id)
        return PendingActionLookup(action=None, was_expired=True)
    return PendingActionLookup(
        action=PendingIncidentAction(
            incident_id=stored.incident_id,
            target_status=IncidentStatus(stored.target_status),
            expected_version=stored.expected_version,
        ),
        was_expired=False,
    )


def delete_pending_action(session: Session, *, telegram_user_id: int) -> None:
    session.execute(
        delete(TelegramPendingAction).where(
            TelegramPendingAction.telegram_user_id == telegram_user_id
        )
    )


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
