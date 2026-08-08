"""Aggregate counts for one reporting week (ADR-0023).

This module answers "what happened", not "show me the events": it returns counts
and groupings only. Nothing here reads event payloads, incident correlation or
addresses, because the report it feeds is the first artifact designed to leave
the perimeter (ADR-0023 §1-§2).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import Select, case, func, select
from sqlalchemy.orm import Session

from woland_guard_control_plane.infrastructure.database.models import (
    Event,
    Incident,
    IncidentHistoryEntry,
    Server,
)

REPORT_DAYS = 7
_ACTIVE_STATUSES = ("new", "investigating")
_SEVERITY_ORDER = ("critical", "high", "medium", "low")
_TERMINAL_STATUSES = ("investigating", "resolved", "false_positive")


class ReportPeriodError(ValueError):
    """A safe error for a period this report cannot describe."""


@dataclass(frozen=True, slots=True)
class ReportPeriod:
    """A half-open UTC window, so two consecutive reports never double-count."""

    start: datetime
    end: datetime

    @property
    def days(self) -> int:
        return (self.end - self.start).days


@dataclass(frozen=True, slots=True)
class WeeklyReport:
    period: ReportPeriod
    generated_at: datetime
    servers_total: int
    servers_active: int
    servers_inactive: int
    opened_by_severity: tuple[tuple[str, int], ...]
    opened_by_rule: tuple[tuple[str, int], ...]
    transitions_to_status: tuple[tuple[str, int], ...]
    open_now_by_severity: tuple[tuple[str, int], ...]
    events_by_source: tuple[tuple[str, int], ...]

    @property
    def opened_total(self) -> int:
        return sum(count for _, count in self.opened_by_severity)

    @property
    def open_now_total(self) -> int:
        return sum(count for _, count in self.open_now_by_severity)

    @property
    def events_total(self) -> int:
        return sum(count for _, count in self.events_by_source)


def week_ending(day: date) -> ReportPeriod:
    """Build the seven-day window that ends at midnight UTC of the given day."""

    end = datetime(day.year, day.month, day.day, tzinfo=UTC)
    return ReportPeriod(start=end - timedelta(days=REPORT_DAYS), end=end)


def build_weekly_report(
    session: Session,
    *,
    period: ReportPeriod,
    now: datetime,
) -> WeeklyReport:
    """Collect every count in one place; no availability or health is inferred."""

    if period.end <= period.start:
        raise ReportPeriodError("report period must end after it starts")

    server_row = session.execute(
        select(
            func.count().label("total"),
            func.sum(case((Server.is_active.is_(True), 1), else_=0)).label("active"),
            func.sum(case((Server.is_active.is_(False), 1), else_=0)).label("inactive"),
        ).select_from(Server)
    ).one()

    # Opened in the period means created_at, not last_seen_at: an old incident
    # that received new evidence has not been opened again (ADR-0023 §7).
    in_period = (Incident.created_at >= period.start) & (Incident.created_at < period.end)
    opened_by_severity = _counts(
        session,
        select(Incident.severity, func.count()).where(in_period).group_by(Incident.severity),
        order=_SEVERITY_ORDER,
    )
    opened_by_rule = _ranked(
        session,
        select(Incident.rule_key, func.count()).where(in_period).group_by(Incident.rule_key),
    )
    transitions = _counts(
        session,
        select(IncidentHistoryEntry.to_status, func.count())
        .where(
            IncidentHistoryEntry.entry_type == "status_transition",
            IncidentHistoryEntry.created_at >= period.start,
            IncidentHistoryEntry.created_at < period.end,
        )
        .group_by(IncidentHistoryEntry.to_status),
        order=_TERMINAL_STATUSES,
    )
    # Deliberately "as of generation", not "as of the end of the period": the
    # schema keeps the current status, not a status timeline, so a retroactive
    # answer would be a guess (ADR-0023 §8).
    open_now = _counts(
        session,
        select(Incident.severity, func.count())
        .where(Incident.status.in_(_ACTIVE_STATUSES))
        .group_by(Incident.severity),
        order=_SEVERITY_ORDER,
    )
    events_by_source = _ranked(
        session,
        select(Event.source, func.count())
        .where(Event.occurred_at >= period.start, Event.occurred_at < period.end)
        .group_by(Event.source),
    )

    return WeeklyReport(
        period=period,
        generated_at=now.astimezone(UTC),
        servers_total=int(server_row.total or 0),
        servers_active=int(server_row.active or 0),
        servers_inactive=int(server_row.inactive or 0),
        opened_by_severity=opened_by_severity,
        opened_by_rule=opened_by_rule,
        transitions_to_status=transitions,
        open_now_by_severity=open_now,
        events_by_source=events_by_source,
    )


def _counts(
    session: Session,
    statement: Select[tuple[str, int]],
    *,
    order: tuple[str, ...],
) -> tuple[tuple[str, int], ...]:
    """Return counts in a fixed order, including the zeroes.

    A severity missing from the report reads as "not measured"; an explicit zero
    reads as "measured, none found", which is the honest statement.
    """

    found = {str(key): int(count) for key, count in session.execute(statement).all()}
    return tuple((name, found.get(name, 0)) for name in order)


def _ranked(
    session: Session,
    statement: Select[tuple[str, int]],
) -> tuple[tuple[str, int], ...]:
    """Return only what actually occurred, most frequent first, then by name."""

    rows = [(str(key), int(count)) for key, count in session.execute(statement).all()]
    return tuple(sorted(rows, key=lambda item: (-item[1], item[0])))
