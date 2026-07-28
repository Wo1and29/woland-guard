"""Transport-neutral, bounded server inventory queries for the Dashboard."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, cast
from uuid import UUID

from sqlalchemy import Select, and_, bindparam, case, func, or_, select, true
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from woland_guard_control_plane.application.dashboard_pagination import (
    DashboardCursorContext,
    DashboardListType,
    DashboardPage,
    decode_dashboard_cursor,
    encode_dashboard_cursor,
)
from woland_guard_control_plane.application.dashboard_search import (
    LIKE_ESCAPE_CHARACTER,
    literal_prefix_pattern,
)
from woland_guard_control_plane.infrastructure.database.models import Event, Incident, Server


class ServerStateFilter(StrEnum):
    ALL = "all"
    ACTIVE = "active"
    INACTIVE = "inactive"


class ServerSort(StrEnum):
    NAME_ASC = "name_asc"
    NAME_DESC = "name_desc"


@dataclass(frozen=True, slots=True)
class ServerFilters:
    state: ServerStateFilter = ServerStateFilter.ALL
    server_id: UUID | None = None
    search: str | None = None

    def cursor_filters(self) -> dict[str, str | None]:
        return {
            "id": None if self.server_id is None else str(self.server_id),
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class ServerSummary:
    id: UUID
    name: str
    hostname: str
    description: str | None
    is_active: bool
    last_event_at: datetime | None
    incident_count: int
    active_incident_count: int
    critical_active_incident_count: int
    created_at: datetime
    updated_at: datetime


def list_servers(
    session: Session,
    *,
    filters: ServerFilters,
    sort: ServerSort,
    page_size: int,
    cursor: str | None,
) -> DashboardPage[ServerSummary]:
    """Return one stable keyset page with aggregate data in a single statement."""

    normalized_name = func.lower(Server.name)
    active_incident = Incident.status.in_(("new", "investigating"))
    base_statement: Select[Any] = select(
        Server.id,
        Server.name,
        Server.hostname,
        Server.description,
        Server.is_active,
        Server.created_at,
        Server.updated_at,
        normalized_name.label("normalized_name"),
    )
    conditions: list[ColumnElement[bool]] = []
    if filters.state is ServerStateFilter.ACTIVE:
        conditions.append(Server.is_active.is_(True))
    elif filters.state is ServerStateFilter.INACTIVE:
        conditions.append(Server.is_active.is_(False))
    if filters.server_id is not None:
        conditions.append(Server.id == filters.server_id)
    if filters.search is not None:
        pattern = literal_prefix_pattern(filters.search)
        search_parameter = func.lower(bindparam("server_prefix_pattern", pattern))
        conditions.append(
            or_(
                func.lower(Server.name).like(search_parameter, escape=LIKE_ESCAPE_CHARACTER),
                func.lower(Server.hostname).like(search_parameter, escape=LIKE_ESCAPE_CHARACTER),
            )
        )

    context = DashboardCursorContext(
        list_type=DashboardListType.SERVERS,
        filters=filters.cursor_filters(),
        search=filters.search,
        sort=sort.value,
        page_size=page_size,
    )
    context.validate()
    if cursor is not None:
        cursor_name, cursor_id = decode_dashboard_cursor(cursor, expected=context)
        cursor_name = cast(str, cursor_name)
        cursor_id = cast(UUID, cursor_id)
        if sort is ServerSort.NAME_ASC:
            conditions.append(
                or_(
                    normalized_name > cursor_name,
                    and_(normalized_name == cursor_name, Server.id > cursor_id),
                )
            )
        else:
            conditions.append(
                or_(
                    normalized_name < cursor_name,
                    and_(normalized_name == cursor_name, Server.id < cursor_id),
                )
            )
    if conditions:
        base_statement = base_statement.where(*conditions)
    ordering = (
        (normalized_name.asc(), Server.id.asc())
        if sort is ServerSort.NAME_ASC
        else (normalized_name.desc(), Server.id.desc())
    )
    server_page = base_statement.order_by(*ordering).limit(page_size + 1).subquery()
    last_event = (
        select(func.max(Event.occurred_at))
        .where(Event.server_id == server_page.c.id)
        .scalar_subquery()
    )
    incident_counts = (
        select(
            func.count().label("incident_count"),
            func.sum(case((active_incident, 1), else_=0)).label("active_count"),
            func.sum(
                case((and_(active_incident, Incident.severity == "critical"), 1), else_=0)
            ).label("critical_active_count"),
        )
        .where(Incident.server_id == server_page.c.id)
        .lateral("incident_counts")
    )
    final_ordering = (
        (server_page.c.normalized_name.asc(), server_page.c.id.asc())
        if sort is ServerSort.NAME_ASC
        else (server_page.c.normalized_name.desc(), server_page.c.id.desc())
    )
    statement = (
        select(
            server_page,
            last_event.label("last_event"),
            incident_counts.c.incident_count,
            func.coalesce(incident_counts.c.active_count, 0).label("active_incident_count"),
            func.coalesce(incident_counts.c.critical_active_count, 0).label(
                "critical_active_incident_count"
            ),
        )
        .select_from(server_page.join(incident_counts, true()))
        .order_by(*final_ordering)
    )
    rows = session.execute(statement).mappings().all()
    page_rows = rows[:page_size]
    items = tuple(_server_summary(row) for row in page_rows)
    next_cursor = None
    if len(rows) > page_size and page_rows:
        last = page_rows[-1]
        next_cursor = encode_dashboard_cursor(
            context,
            keys=(last["normalized_name"], last["id"]),
        )
    return DashboardPage(items, next_cursor)


def get_server_detail(session: Session, server_id: UUID) -> ServerSummary | None:
    """Return one server and factual aggregates without loading any API keys."""

    page = list_servers(
        session,
        filters=ServerFilters(server_id=server_id),
        sort=ServerSort.NAME_ASC,
        page_size=25,
        cursor=None,
    )
    return page.items[0] if page.items else None


def _server_summary(row: RowMapping | Mapping[str, Any]) -> ServerSummary:
    return ServerSummary(
        id=row["id"],
        name=row["name"],
        hostname=row["hostname"],
        description=row["description"],
        is_active=row["is_active"],
        last_event_at=row["last_event"],
        incident_count=int(row["incident_count"]),
        active_incident_count=int(row["active_incident_count"]),
        critical_active_incident_count=int(row["critical_active_incident_count"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )
