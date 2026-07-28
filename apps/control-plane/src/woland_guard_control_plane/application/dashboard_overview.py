"""Factual Dashboard overview metrics without inferred health claims."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.incident_queries import (
    DashboardIncidentSummary,
    list_recent_dashboard_incidents,
)
from woland_guard_control_plane.application.outbox_worker import QueueStatistics, queue_statistics
from woland_guard_control_plane.infrastructure.database.models import Incident, Server


@dataclass(frozen=True, slots=True)
class ServerOverviewCounts:
    total: int
    active: int
    inactive: int


@dataclass(frozen=True, slots=True)
class IncidentOverviewCounts:
    active: int
    critical_active: int


@dataclass(frozen=True, slots=True)
class DashboardOverview:
    servers: ServerOverviewCounts
    incidents: IncidentOverviewCounts
    notifications: QueueStatistics
    recent_incidents: tuple[DashboardIncidentSummary, ...]


def get_dashboard_overview(session: Session, *, now: datetime) -> DashboardOverview:
    """Return exact persisted counts; no server or provider availability is inferred."""

    server_row = session.execute(
        select(
            func.count().label("total"),
            func.sum(case((Server.is_active.is_(True), 1), else_=0)).label("active"),
            func.sum(case((Server.is_active.is_(False), 1), else_=0)).label("inactive"),
        ).select_from(Server)
    ).one()
    active_status = Incident.status.in_(("new", "investigating"))
    incident_row = session.execute(
        select(
            func.sum(case((active_status, 1), else_=0)).label("active"),
            func.sum(
                case(
                    ((active_status & (Incident.severity == "critical")), 1),
                    else_=0,
                )
            ).label("critical_active"),
        ).select_from(Incident)
    ).one()
    return DashboardOverview(
        servers=ServerOverviewCounts(
            total=int(server_row.total or 0),
            active=int(server_row.active or 0),
            inactive=int(server_row.inactive or 0),
        ),
        incidents=IncidentOverviewCounts(
            active=int(incident_row.active or 0),
            critical_active=int(incident_row.critical_active or 0),
        ),
        notifications=queue_statistics(session, now=now),
        recent_incidents=list_recent_dashboard_incidents(session, limit=10),
    )
