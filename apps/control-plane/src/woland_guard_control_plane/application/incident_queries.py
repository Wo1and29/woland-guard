"""Read-only keyset queries and safe projections for incidents and audit."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.pagination import (
    decode_cursor,
    encode_cursor,
    normalized_filter_hash,
)
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    Incident,
    IncidentHistoryEntry,
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
