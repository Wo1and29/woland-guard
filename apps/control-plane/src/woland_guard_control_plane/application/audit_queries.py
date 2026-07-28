"""Transport-neutral keyset queries for append-only audit metadata."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from woland_guard_control_plane.application.dashboard_pagination import (
    DashboardCursorContext,
    DashboardListType,
    DashboardPage,
    decode_dashboard_cursor,
    encode_dashboard_cursor,
)
from woland_guard_control_plane.infrastructure.database.models import AuditLogEntry


class AuditDashboardSort(StrEnum):
    CREATED_ASC = "created_asc"
    CREATED_DESC = "created_desc"


@dataclass(frozen=True, slots=True)
class AuditDashboardFilters:
    actor_type: str | None = None
    action: str | None = None
    target_type: str | None = None
    target_id: UUID | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None

    def cursor_filters(self) -> dict[str, str | None]:
        return {
            "action": self.action,
            "actor_type": self.actor_type,
            "created_from": _utc_text(self.created_from),
            "created_to": _utc_text(self.created_to),
            "target_id": None if self.target_id is None else str(self.target_id),
            "target_type": self.target_type,
        }


@dataclass(frozen=True, slots=True)
class AuditDashboardEntry:
    id: UUID
    actor_type: str
    operator_id: UUID | None
    actor_username: str | None
    auth_method_type: str | None
    action: str
    target_type: str
    target_id: UUID
    request_id: str | None
    details: object
    created_at: datetime


def list_dashboard_audit_entries(
    session: Session,
    *,
    filters: AuditDashboardFilters,
    sort: AuditDashboardSort,
    page_size: int,
    cursor: str | None,
) -> DashboardPage[AuditDashboardEntry]:
    """Return audit metadata and stored details for a second strict presentation check."""

    statement = select(
        AuditLogEntry.id,
        AuditLogEntry.actor_type,
        AuditLogEntry.operator_id,
        AuditLogEntry.actor_username_snapshot.label("actor_username"),
        AuditLogEntry.auth_method_type,
        AuditLogEntry.action,
        AuditLogEntry.target_type,
        AuditLogEntry.target_id,
        AuditLogEntry.request_id,
        AuditLogEntry.details,
        AuditLogEntry.created_at,
    )
    conditions: list[ColumnElement[bool]] = []
    for column, value in (
        (AuditLogEntry.actor_type, filters.actor_type),
        (AuditLogEntry.action, filters.action),
        (AuditLogEntry.target_type, filters.target_type),
        (AuditLogEntry.target_id, filters.target_id),
    ):
        if value is not None:
            conditions.append(column == value)
    if filters.created_from is not None:
        conditions.append(AuditLogEntry.created_at >= filters.created_from)
    if filters.created_to is not None:
        conditions.append(AuditLogEntry.created_at < filters.created_to)
    context = DashboardCursorContext(
        list_type=DashboardListType.AUDIT,
        filters=filters.cursor_filters(),
        search=None,
        sort=sort.value,
        page_size=page_size,
    )
    context.validate()
    if cursor is not None:
        cursor_created_at, cursor_id = decode_dashboard_cursor(cursor, expected=context)
        cursor_created_at = cast(datetime, cursor_created_at)
        cursor_id = cast(UUID, cursor_id)
        if sort is AuditDashboardSort.CREATED_ASC:
            conditions.append(
                or_(
                    AuditLogEntry.created_at > cursor_created_at,
                    and_(
                        AuditLogEntry.created_at == cursor_created_at,
                        AuditLogEntry.id > cursor_id,
                    ),
                )
            )
        else:
            conditions.append(
                or_(
                    AuditLogEntry.created_at < cursor_created_at,
                    and_(
                        AuditLogEntry.created_at == cursor_created_at,
                        AuditLogEntry.id < cursor_id,
                    ),
                )
            )
    if conditions:
        statement = statement.where(*conditions)
    ordering = (
        (AuditLogEntry.created_at.asc(), AuditLogEntry.id.asc())
        if sort is AuditDashboardSort.CREATED_ASC
        else (AuditLogEntry.created_at.desc(), AuditLogEntry.id.desc())
    )
    rows = session.execute(statement.order_by(*ordering).limit(page_size + 1)).mappings().all()
    page_rows = rows[:page_size]
    items = tuple(
        AuditDashboardEntry(
            id=row["id"],
            actor_type=row["actor_type"],
            operator_id=row["operator_id"],
            actor_username=row["actor_username"],
            auth_method_type=row["auth_method_type"],
            action=row["action"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            request_id=row["request_id"],
            details=row["details"],
            created_at=row["created_at"],
        )
        for row in page_rows
    )
    next_cursor = None
    if len(rows) > page_size and page_rows:
        last = page_rows[-1]
        next_cursor = encode_dashboard_cursor(
            context,
            keys=(last["created_at"], last["id"]),
        )
    return DashboardPage(items, next_cursor)


def _utc_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("audit dashboard timestamps require timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
