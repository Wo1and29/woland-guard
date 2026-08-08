"""PostgreSQL integration tests for the weekly report aggregates (ADR-0023)."""

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from tests.integration.conftest import AgentFactory, OperatorFactory
from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.application.detection.sync import sync_rules
from woland_guard_control_plane.application.report_rendering import render_markdown
from woland_guard_control_plane.application.weekly_report import (
    ReportPeriod,
    ReportPeriodError,
    build_weekly_report,
    week_ending,
)
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentHistoryEntry,
    OperatorRole,
)

pytestmark = pytest.mark.integration

RULES_DIR = Path(__file__).parents[2] / "detection-rules"
WEEK_END = date(2026, 8, 7)
PERIOD = week_ending(WEEK_END)
INSIDE = PERIOD.start + timedelta(days=2)
BEFORE = PERIOD.start - timedelta(hours=1)


def _rule_version_id() -> UUID:
    with get_session_factory().begin() as session:
        sync_rules(session, load_rules_directory(RULES_DIR))
    with get_session_factory()() as session:
        return (
            session.scalars(
                select(DetectionRuleVersion.id).where(DetectionRuleVersion.is_active.is_(True))
            ).first()
            or uuid4()
        )


def _add_incident(
    server_id: UUID,
    rule_version_id: UUID,
    *,
    created_at: datetime,
    severity: str = "high",
    status: str = "new",
    rule_key: str = "ssh_bruteforce_by_ip",
) -> UUID:
    incident_id = uuid4()
    with get_session_factory().begin() as session:
        session.add(
            Incident(
                id=incident_id,
                server_id=server_id,
                rule_version_id=rule_version_id,
                rule_key=rule_key,
                rule_version=1,
                severity=severity,
                status=status,
                title="synthetic weekly report incident",
                explanation="synthetic",
                recommendation="synthetic",
                # A real correlation carries an address; the report must not.
                correlation={"source_ip": "192.0.2.10"},
                correlation_hash=uuid4().hex + uuid4().hex,
                rule_snapshot={},
                first_seen_at=created_at,
                last_seen_at=created_at,
                event_count=1,
                created_at=created_at,
            )
        )
    return incident_id


def _add_event(server_id: UUID, *, occurred_at: datetime, source: str = "journald") -> None:
    with get_session_factory().begin() as session:
        session.add(
            Event(
                server_id=server_id,
                agent_event_id=uuid4(),
                schema_version=1,
                source=source,
                event_type="linux.ssh.authentication_failed",
                occurred_at=occurred_at,
                collected_at=occurred_at,
                payload={"summary": "synthetic"},
            )
        )


def test_only_incidents_opened_inside_the_window_are_counted(
    register_agent: AgentFactory,
) -> None:
    """The window is half-open, so a boundary incident belongs to exactly one week."""

    agent = register_agent()
    version_id = _rule_version_id()
    _add_incident(agent.server_id, version_id, created_at=INSIDE)
    _add_incident(agent.server_id, version_id, created_at=BEFORE)
    _add_incident(agent.server_id, version_id, created_at=PERIOD.end)

    with get_session_factory()() as session:
        report = build_weekly_report(session, period=PERIOD, now=datetime.now(UTC))

    assert report.opened_total == 1
    assert dict(report.opened_by_severity)["high"] == 1
    assert report.opened_by_rule == (("ssh_bruteforce_by_ip", 1),)


def test_severities_with_no_incidents_are_reported_as_explicit_zero(
    register_agent: AgentFactory,
) -> None:
    agent = register_agent()
    _add_incident(agent.server_id, _rule_version_id(), created_at=INSIDE, severity="critical")

    with get_session_factory()() as session:
        report = build_weekly_report(session, period=PERIOD, now=datetime.now(UTC))

    assert dict(report.opened_by_severity) == {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def test_status_transitions_are_counted_only_inside_the_window(
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    agent = register_agent()
    # The schema requires a real operator on a status_transition entry: the
    # history is the audit trail, so an anonymous transition cannot exist.
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id = _add_incident(agent.server_id, _rule_version_id(), created_at=INSIDE)

    with get_session_factory().begin() as session:
        for created_at, to_status in ((INSIDE, "investigating"), (BEFORE, "resolved")):
            session.add(
                IncidentHistoryEntry(
                    incident_id=incident_id,
                    version=2 if to_status == "investigating" else 3,
                    entry_type="status_transition",
                    from_status="new",
                    to_status=to_status,
                    reason="synthetic reason",
                    changed_by_operator_id=operator.operator_id,
                    actor_username_snapshot=operator.username,
                    auth_method_type="operator_api_key",
                    auth_method_id=operator.key_id,
                    created_at=created_at,
                )
            )

    with get_session_factory()() as session:
        report = build_weekly_report(session, period=PERIOD, now=datetime.now(UTC))

    assert dict(report.transitions_to_status) == {
        "investigating": 1,
        "resolved": 0,
        "false_positive": 0,
    }


def test_events_are_counted_by_source_within_the_window(
    register_agent: AgentFactory,
) -> None:
    agent = register_agent()
    _add_event(agent.server_id, occurred_at=INSIDE)
    _add_event(agent.server_id, occurred_at=INSIDE, source="nginx_access")
    _add_event(agent.server_id, occurred_at=INSIDE, source="nginx_access")
    _add_event(agent.server_id, occurred_at=BEFORE)

    with get_session_factory()() as session:
        report = build_weekly_report(session, period=PERIOD, now=datetime.now(UTC))

    assert report.events_total == 3
    assert report.events_by_source == (("nginx_access", 2), ("journald", 1))


def test_open_incidents_are_counted_regardless_of_when_they_were_opened(
    register_agent: AgentFactory,
) -> None:
    """They answer "what is in work now", so an older incident still counts."""

    agent = register_agent()
    version_id = _rule_version_id()
    _add_incident(agent.server_id, version_id, created_at=BEFORE, status="investigating")
    _add_incident(agent.server_id, version_id, created_at=INSIDE, status="resolved")

    with get_session_factory()() as session:
        report = build_weekly_report(session, period=PERIOD, now=datetime.now(UTC))

    assert report.open_now_total == 1
    assert report.opened_total == 1


def test_an_empty_week_renders_without_pretending_nothing_happened(
    register_agent: AgentFactory,
) -> None:
    register_agent()

    with get_session_factory()() as session:
        report = build_weekly_report(session, period=PERIOD, now=datetime.now(UTC))
    rendered = render_markdown(report)

    assert report.opened_total == 0
    assert "не сработало ни одно правило" in rendered
    assert "Отсутствие инцидентов не означает отсутствия атак" in rendered


def test_a_reversed_period_is_rejected(register_agent: AgentFactory) -> None:
    register_agent()
    broken = ReportPeriod(start=PERIOD.end, end=PERIOD.start)

    with get_session_factory()() as session:
        with pytest.raises(ReportPeriodError, match="must end after"):
            build_weekly_report(session, period=broken, now=datetime.now(UTC))


def test_the_report_never_contains_an_address_from_incident_correlation(
    register_agent: AgentFactory,
) -> None:
    """Correlation holds a real address; the report is built not to carry it."""

    agent = register_agent()
    _add_incident(agent.server_id, _rule_version_id(), created_at=INSIDE)

    with get_session_factory()() as session:
        report = build_weekly_report(session, period=PERIOD, now=datetime.now(UTC))

    assert "192.0.2.10" not in render_markdown(report)
