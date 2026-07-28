"""Read-only keyset queries and safe projections for incidents and audit."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, cast
from uuid import UUID

from sqlalchemy import Select, and_, bindparam, func, or_, select
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
from woland_guard_control_plane.application.pagination import (
    decode_cursor,
    encode_cursor,
    normalized_filter_hash,
)
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    Server,
)


@dataclass(frozen=True, slots=True)
class IncidentFilters:
    statuses: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    server_id: UUID | None = None
    rule_key: str | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None

    def normalized(self) -> IncidentFilters:
        return IncidentFilters(
            statuses=tuple(sorted(set(self.statuses))),
            severities=tuple(sorted(set(self.severities))),
            server_id=self.server_id,
            rule_key=self.rule_key,
            created_from=self.created_from,
            created_to=self.created_to,
        )

    def hash(self) -> str:
        normalized = self.normalized()
        return normalized_filter_hash(
            {
                "created_from": normalized.created_from,
                "created_to": normalized.created_to,
                "rule_key": normalized.rule_key,
                "server_id": normalized.server_id,
                "severities": list(normalized.severities),
                "statuses": list(normalized.statuses),
            }
        )


@dataclass(frozen=True, slots=True)
class AuditFilters:
    operator_id: UUID | None = None
    action: str | None = None
    target_type: str | None = None
    target_id: UUID | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None

    def hash(self) -> str:
        return normalized_filter_hash(
            {
                "action": self.action,
                "created_from": self.created_from,
                "created_to": self.created_to,
                "operator_id": self.operator_id,
                "target_id": self.target_id,
                "target_type": self.target_type,
            }
        )


@dataclass(frozen=True, slots=True)
class QueryPage:
    items: list[dict[str, Any]]
    next_cursor: str | None


class IncidentDashboardSort(StrEnum):
    CREATED_ASC = "created_asc"
    CREATED_DESC = "created_desc"


@dataclass(frozen=True, slots=True)
class IncidentDashboardFilters:
    statuses: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    server_id: UUID | None = None
    rule_key: str | None = None
    incident_id: UUID | None = None
    search: str | None = None

    def normalized(self) -> IncidentDashboardFilters:
        return IncidentDashboardFilters(
            statuses=tuple(sorted(set(self.statuses))),
            severities=tuple(sorted(set(self.severities))),
            server_id=self.server_id,
            rule_key=self.rule_key,
            incident_id=self.incident_id,
            search=self.search,
        )

    def cursor_filters(self) -> dict[str, Any]:
        value = self.normalized()
        return {
            "id": None if value.incident_id is None else str(value.incident_id),
            "rule_key": value.rule_key,
            "server_id": None if value.server_id is None else str(value.server_id),
            "severities": list(value.severities),
            "statuses": list(value.statuses),
        }


@dataclass(frozen=True, slots=True)
class DashboardIncidentSummary:
    id: UUID
    server_id: UUID
    server_name: str
    rule_key: str
    rule_version: int
    severity: str
    status: str
    title: str
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class DashboardIncidentHistory:
    id: UUID
    version: int
    entry_type: str
    from_status: str | None
    to_status: str
    reason: str | None
    operator_username: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class DashboardIncidentDetail:
    summary: DashboardIncidentSummary
    explanation: str
    recommendation: str
    history: tuple[DashboardIncidentHistory, ...]


@dataclass(frozen=True, slots=True)
class DashboardEvidence:
    event_id: UUID
    event_type: str
    source: str
    occurred_at: datetime
    collected_at: datetime
    linked_at: datetime


def list_incidents(
    session: Session,
    *,
    filters: IncidentFilters,
    limit: int,
    cursor: str | None,
) -> QueryPage:
    normalized = filters.normalized()
    filter_hash = normalized.hash()
    statement: Select[tuple[Incident]] = select(Incident)
    conditions: list[Any] = []
    if normalized.statuses:
        conditions.append(Incident.status.in_(normalized.statuses))
    if normalized.severities:
        conditions.append(Incident.severity.in_(normalized.severities))
    if normalized.server_id is not None:
        conditions.append(Incident.server_id == normalized.server_id)
    if normalized.rule_key is not None:
        conditions.append(Incident.rule_key == normalized.rule_key)
    if normalized.created_from is not None:
        conditions.append(Incident.created_at >= normalized.created_from)
    if normalized.created_to is not None:
        conditions.append(Incident.created_at < normalized.created_to)
    if cursor is not None:
        keyset = decode_cursor(cursor, expected_filter_hash=filter_hash)
        conditions.append(
            or_(
                Incident.created_at < keyset.created_at,
                and_(Incident.created_at == keyset.created_at, Incident.id < keyset.row_id),
            )
        )
    if conditions:
        statement = statement.where(*conditions)
    rows = session.scalars(
        statement.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit + 1)
    ).all()
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor(
            created_at=last.created_at,
            row_id=last.id,
            filter_hash=filter_hash,
        )
    return QueryPage([incident_summary(row) for row in page_rows], next_cursor)


def get_incident_detail(session: Session, incident_id: UUID) -> dict[str, Any] | None:
    incident = session.get(Incident, incident_id)
    if incident is None:
        return None
    history = session.scalars(
        select(IncidentHistoryEntry)
        .where(IncidentHistoryEntry.incident_id == incident_id)
        .order_by(IncidentHistoryEntry.version)
    ).all()
    detail = incident_summary(incident)
    detail.update(
        {
            "explanation": incident.explanation,
            "history": [history_summary(entry) for entry in history],
            "recommendation": incident.recommendation,
        }
    )
    return detail


def list_audit_entries(
    session: Session,
    *,
    filters: AuditFilters,
    limit: int,
    cursor: str | None,
) -> QueryPage:
    filter_hash = filters.hash()
    statement: Select[tuple[AuditLogEntry]] = select(AuditLogEntry)
    conditions: list[Any] = []
    for column, value in (
        (AuditLogEntry.operator_id, filters.operator_id),
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
    if cursor is not None:
        keyset = decode_cursor(cursor, expected_filter_hash=filter_hash)
        conditions.append(
            or_(
                AuditLogEntry.created_at < keyset.created_at,
                and_(
                    AuditLogEntry.created_at == keyset.created_at,
                    AuditLogEntry.id < keyset.row_id,
                ),
            )
        )
    if conditions:
        statement = statement.where(*conditions)
    rows = session.scalars(
        statement.order_by(AuditLogEntry.created_at.desc(), AuditLogEntry.id.desc()).limit(
            limit + 1
        )
    ).all()
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor(
            created_at=last.created_at,
            row_id=last.id,
            filter_hash=filter_hash,
        )
    return QueryPage([audit_summary(row) for row in page_rows], next_cursor)


def list_dashboard_incidents(
    session: Session,
    *,
    filters: IncidentDashboardFilters,
    sort: IncidentDashboardSort,
    page_size: int,
    cursor: str | None,
) -> DashboardPage[DashboardIncidentSummary]:
    """Return safe explicit-column incident summaries for HTML presentation."""

    normalized = filters.normalized()
    statement = _dashboard_incident_statement()
    conditions = _dashboard_incident_conditions(normalized)
    context = DashboardCursorContext(
        list_type=DashboardListType.INCIDENTS,
        filters=normalized.cursor_filters(),
        search=normalized.search,
        sort=sort.value,
        page_size=page_size,
    )
    context.validate()
    if cursor is not None:
        cursor_created_at, cursor_id = decode_dashboard_cursor(cursor, expected=context)
        cursor_created_at = cast(datetime, cursor_created_at)
        cursor_id = cast(UUID, cursor_id)
        if sort is IncidentDashboardSort.CREATED_ASC:
            conditions.append(
                or_(
                    Incident.created_at > cursor_created_at,
                    and_(Incident.created_at == cursor_created_at, Incident.id > cursor_id),
                )
            )
        else:
            conditions.append(
                or_(
                    Incident.created_at < cursor_created_at,
                    and_(Incident.created_at == cursor_created_at, Incident.id < cursor_id),
                )
            )
    if conditions:
        statement = statement.where(*conditions)
    ordering = (
        (Incident.created_at.asc(), Incident.id.asc())
        if sort is IncidentDashboardSort.CREATED_ASC
        else (Incident.created_at.desc(), Incident.id.desc())
    )
    rows = session.execute(statement.order_by(*ordering).limit(page_size + 1)).mappings().all()
    page_rows = rows[:page_size]
    items = tuple(_dashboard_incident_summary(row) for row in page_rows)
    next_cursor = None
    if len(rows) > page_size and page_rows:
        last = page_rows[-1]
        next_cursor = encode_dashboard_cursor(
            context,
            keys=(last["created_at"], last["id"]),
        )
    return DashboardPage(items, next_cursor)


def list_recent_dashboard_incidents(
    session: Session,
    *,
    limit: int,
) -> tuple[DashboardIncidentSummary, ...]:
    """Return a small fixed newest-first overview list without a pagination cursor."""

    if type(limit) is not int or not 1 <= limit <= 25:
        raise ValueError("recent incident limit must be between 1 and 25")
    rows = session.execute(
        _dashboard_incident_statement()
        .order_by(Incident.created_at.desc(), Incident.id.desc())
        .limit(limit)
    ).mappings()
    return tuple(_dashboard_incident_summary(row) for row in rows)


def get_dashboard_incident_detail(
    session: Session,
    incident_id: UUID,
) -> DashboardIncidentDetail | None:
    """Return safe incident fields and bounded workflow history, never correlation."""

    row = (
        session.execute(
            _dashboard_incident_statement()
            .add_columns(Incident.explanation, Incident.recommendation)
            .where(Incident.id == incident_id)
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    history_rows = session.execute(
        select(
            IncidentHistoryEntry.id,
            IncidentHistoryEntry.version,
            IncidentHistoryEntry.entry_type,
            IncidentHistoryEntry.from_status,
            IncidentHistoryEntry.to_status,
            IncidentHistoryEntry.reason,
            IncidentHistoryEntry.actor_username_snapshot.label("operator_username"),
            IncidentHistoryEntry.created_at,
        )
        .where(IncidentHistoryEntry.incident_id == incident_id)
        .order_by(IncidentHistoryEntry.version.asc())
    ).mappings()
    history = tuple(
        DashboardIncidentHistory(
            id=item["id"],
            version=item["version"],
            entry_type=item["entry_type"],
            from_status=item["from_status"],
            to_status=item["to_status"],
            reason=item["reason"],
            operator_username=item["operator_username"],
            created_at=item["created_at"],
        )
        for item in history_rows
    )
    return DashboardIncidentDetail(
        summary=_dashboard_incident_summary(row),
        explanation=row["explanation"],
        recommendation=row["recommendation"],
        history=history,
    )


def list_dashboard_evidence(
    session: Session,
    *,
    incident_id: UUID,
    page_size: int,
    cursor: str | None,
) -> DashboardPage[DashboardEvidence]:
    """Select only six allowlisted evidence fields; Event.payload is not selected."""

    context = DashboardCursorContext(
        list_type=DashboardListType.EVIDENCE,
        filters={"incident_id": str(incident_id)},
        search=None,
        sort="linked_asc",
        page_size=page_size,
    )
    context.validate()
    statement = dashboard_evidence_statement(incident_id)
    if cursor is not None:
        cursor_linked_at, cursor_event_id = decode_dashboard_cursor(cursor, expected=context)
        cursor_linked_at = cast(datetime, cursor_linked_at)
        cursor_event_id = cast(UUID, cursor_event_id)
        statement = statement.where(
            or_(
                IncidentEvent.linked_at > cursor_linked_at,
                and_(
                    IncidentEvent.linked_at == cursor_linked_at,
                    IncidentEvent.event_id > cursor_event_id,
                ),
            )
        )
    rows = (
        session.execute(
            statement.order_by(IncidentEvent.linked_at.asc(), IncidentEvent.event_id.asc()).limit(
                page_size + 1
            )
        )
        .mappings()
        .all()
    )
    page_rows = rows[:page_size]
    items = tuple(
        DashboardEvidence(
            event_id=row["event_id"],
            event_type=row["event_type"],
            source=row["source"],
            occurred_at=row["occurred_at"],
            collected_at=row["collected_at"],
            linked_at=row["linked_at"],
        )
        for row in page_rows
    )
    next_cursor = None
    if len(rows) > page_size and page_rows:
        last = page_rows[-1]
        next_cursor = encode_dashboard_cursor(
            context,
            keys=(last["linked_at"], last["event_id"]),
        )
    return DashboardPage(items, next_cursor)


def dashboard_evidence_statement(incident_id: UUID) -> Select[Any]:
    """Expose the explicit allowlisted SELECT for SQL-level security regression tests."""

    statement: Select[Any] = (
        select(
            IncidentEvent.event_id,
            Event.event_type,
            Event.source,
            Event.occurred_at,
            Event.collected_at,
            IncidentEvent.linked_at,
        )
        .join(Event, Event.id == IncidentEvent.event_id)
        .where(IncidentEvent.incident_id == incident_id)
    )
    return statement


def _dashboard_incident_statement() -> Select[Any]:
    statement: Select[Any] = select(
        Incident.id,
        Incident.server_id,
        Server.name.label("server_name"),
        Incident.rule_key,
        Incident.rule_version,
        Incident.severity,
        Incident.status,
        Incident.title,
        Incident.first_seen_at,
        Incident.last_seen_at,
        Incident.event_count,
        Incident.lock_version.label("version"),
        Incident.created_at,
        Incident.updated_at,
    ).join(Server, Server.id == Incident.server_id)
    return statement


def _dashboard_incident_conditions(
    filters: IncidentDashboardFilters,
) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if filters.statuses:
        conditions.append(Incident.status.in_(filters.statuses))
    if filters.severities:
        conditions.append(Incident.severity.in_(filters.severities))
    if filters.server_id is not None:
        conditions.append(Incident.server_id == filters.server_id)
    if filters.rule_key is not None:
        conditions.append(Incident.rule_key == filters.rule_key)
    if filters.incident_id is not None:
        conditions.append(Incident.id == filters.incident_id)
    if filters.search is not None:
        pattern = literal_prefix_pattern(filters.search)
        parameter = func.lower(bindparam("incident_prefix_pattern", pattern))
        conditions.append(
            or_(
                func.lower(Incident.rule_key).like(parameter, escape=LIKE_ESCAPE_CHARACTER),
                func.lower(Incident.title).like(parameter, escape=LIKE_ESCAPE_CHARACTER),
            )
        )
    return conditions


def _dashboard_incident_summary(
    row: RowMapping | Mapping[str, Any],
) -> DashboardIncidentSummary:
    return DashboardIncidentSummary(
        id=row["id"],
        server_id=row["server_id"],
        server_name=row["server_name"],
        rule_key=row["rule_key"],
        rule_version=row["rule_version"],
        severity=row["severity"],
        status=row["status"],
        title=row["title"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        event_count=row["event_count"],
        version=row["version"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def incident_summary(incident: Incident) -> dict[str, Any]:
    return {
        "created_at": incident.created_at,
        "event_count": incident.event_count,
        "first_seen_at": incident.first_seen_at,
        "id": incident.id,
        "last_seen_at": incident.last_seen_at,
        "rule_key": incident.rule_key,
        "rule_version": incident.rule_version,
        "server_id": incident.server_id,
        "severity": incident.severity,
        "status": incident.status,
        "title": incident.title,
        "updated_at": incident.updated_at,
        "version": incident.lock_version,
    }


def history_summary(entry: IncidentHistoryEntry) -> dict[str, Any]:
    return {
        "created_at": entry.created_at,
        "entry_type": entry.entry_type,
        "from_status": entry.from_status,
        "id": entry.id,
        "operator_id": entry.changed_by_operator_id,
        "operator_username": entry.actor_username_snapshot,
        "reason": entry.reason,
        "to_status": entry.to_status,
        "version": entry.version,
    }


def audit_summary(entry: AuditLogEntry) -> dict[str, Any]:
    return {
        "action": entry.action,
        "actor_type": entry.actor_type,
        "actor_username": entry.actor_username_snapshot,
        "created_at": entry.created_at,
        "details": entry.details,
        "id": entry.id,
        "operator_id": entry.operator_id,
        "request_id": entry.request_id,
        "target_id": entry.target_id,
        "target_type": entry.target_type,
    }
