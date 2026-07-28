"""PostgreSQL query, pagination, privacy and budget regressions for Dashboard 7B."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit_queries import (
    AuditDashboardFilters,
    AuditDashboardSort,
    list_dashboard_audit_entries,
)
from woland_guard_control_plane.application.dashboard_overview import get_dashboard_overview
from woland_guard_control_plane.application.dashboard_search import normalize_literal_prefix
from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.application.detection.sync import sync_rules
from woland_guard_control_plane.application.incident_queries import (
    IncidentDashboardFilters,
    IncidentDashboardSort,
    get_dashboard_incident_detail,
    list_dashboard_evidence,
    list_dashboard_incidents,
)
from woland_guard_control_plane.application.rule_queries import (
    RuleFilters,
    RuleSort,
    StoredRuleDefinitionError,
    list_active_rules,
)
from woland_guard_control_plane.application.server_queries import (
    ServerFilters,
    ServerSort,
    get_server_detail,
    list_servers,
)
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    Server,
)

pytestmark = pytest.mark.integration
RULES_DIR = Path(__file__).parents[2] / "detection-rules"


def test_literal_prefix_metacharacters_are_data_not_wildcards() -> None:
    with get_session_factory().begin() as session:
        for name in ("%literal", "_literal", "!literal", "ordinary"):
            session.add(Server(name=name, hostname=f"{uuid4().hex}.invalid"))

    for value in ("%", "_", "!"):
        with get_session_factory()() as session:
            page = list_servers(
                session,
                filters=ServerFilters(search=normalize_literal_prefix(value)),
                sort=ServerSort.NAME_ASC,
                page_size=25,
                cursor=None,
            )
        assert [item.name for item in page.items] == [f"{value}literal"]


def test_server_keyset_uses_uuid_tie_breaker_and_documents_concurrent_insert() -> None:
    with get_session_factory().begin() as session:
        for index in range(24):
            session.add(Server(name=f"prefix-{index:02d}", hostname=f"{uuid4().hex}.invalid"))
        session.add(Server(name="same", hostname=f"{uuid4().hex}.invalid"))
        session.add(Server(name="SAME", hostname=f"{uuid4().hex}.invalid"))

    with get_session_factory()() as session:
        first = list_servers(
            session,
            filters=ServerFilters(),
            sort=ServerSort.NAME_ASC,
            page_size=25,
            cursor=None,
        )
    assert first.next_cursor is not None
    with get_session_factory().begin() as session:
        session.add(Server(name="aaa-inserted-after-page-one", hostname=f"{uuid4().hex}.invalid"))
    with get_session_factory()() as session:
        second = list_servers(
            session,
            filters=ServerFilters(),
            sort=ServerSort.NAME_ASC,
            page_size=25,
            cursor=first.next_cursor,
        )
    first_ids = {item.id for item in first.items}
    second_ids = {item.id for item in second.items}
    assert not first_ids & second_ids
    assert len(first_ids | second_ids) == 26
    assert all(item.name != "aaa-inserted-after-page-one" for item in second.items)


def test_evidence_projection_never_materializes_payload_canaries() -> None:
    incident_id, canary = _create_incident_with_evidence()
    with get_session_factory()() as session:
        detail = get_dashboard_incident_detail(session, incident_id)
        evidence = list_dashboard_evidence(
            session,
            incident_id=incident_id,
            page_size=25,
            cursor=None,
        )
    assert detail is not None
    assert len(evidence.items) == 1
    assert canary not in repr(detail)
    assert canary not in repr(evidence)
    assert not hasattr(evidence.items[0], "payload")


def test_corrupt_active_rule_fails_closed_with_safe_identifier() -> None:
    row_id = uuid4()
    with get_session_factory().begin() as session:
        session.add(
            DetectionRuleVersion(
                id=row_id,
                rule_key="corrupt_rule",
                version=1,
                schema_version=1,
                enabled=True,
                severity="high",
                checksum="a" * 64,
                definition={"unsafe": "canary-rule-definition"},
                is_active=True,
                activated_at=datetime.now(UTC),
            )
        )
    with get_session_factory()() as session:
        with pytest.raises(StoredRuleDefinitionError) as captured:
            list_active_rules(
                session,
                filters=RuleFilters(),
                sort=RuleSort.RULE_KEY_ASC,
                page_size=25,
                cursor=None,
            )
    assert captured.value.rule_version_id == row_id
    assert "canary" not in str(captured.value)


def test_application_query_statement_budgets_are_independent_of_session_touch() -> None:
    _create_incident_with_evidence()
    counts: list[str] = []

    def record_statement(
        _connection: Connection,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        counts.append(statement)

    engine: Engine = get_engine()
    sqlalchemy_event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with get_session_factory()() as session:
            counts.clear()
            get_dashboard_overview(session, now=datetime.now(UTC))
            assert len(counts) == 7

            counts.clear()
            servers = list_servers(
                session,
                filters=ServerFilters(),
                sort=ServerSort.NAME_ASC,
                page_size=25,
                cursor=None,
            )
            assert len(counts) == 1

            counts.clear()
            get_server_detail(session, servers.items[0].id)
            assert len(counts) == 1

            counts.clear()
            incidents = list_dashboard_incidents(
                session,
                filters=IncidentDashboardFilters(),
                sort=IncidentDashboardSort.CREATED_DESC,
                page_size=25,
                cursor=None,
            )
            assert len(counts) == 1

            counts.clear()
            get_dashboard_incident_detail(session, incidents.items[0].id)
            list_dashboard_evidence(
                session,
                incident_id=incidents.items[0].id,
                page_size=25,
                cursor=None,
            )
            assert len(counts) == 3

            counts.clear()
            list_active_rules(
                session,
                filters=RuleFilters(),
                sort=RuleSort.RULE_KEY_ASC,
                page_size=25,
                cursor=None,
            )
            assert len(counts) == 2

            counts.clear()
            list_dashboard_audit_entries(
                session,
                filters=AuditDashboardFilters(),
                sort=AuditDashboardSort.CREATED_DESC,
                page_size=25,
                cursor=None,
            )
            assert len(counts) == 1
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", record_statement)


def test_representative_query_plans_are_bounded_after_page_selection() -> None:
    incident_id = _create_representative_query_fixtures()
    engine = get_engine()

    with get_session_factory()() as session:
        database_collation = session.scalar(
            text("SELECT datcollate FROM pg_database WHERE datname = current_database()")
        )
        server_plan = _capture_explain(
            engine,
            session,
            lambda: list_servers(
                session,
                filters=ServerFilters(),
                sort=ServerSort.NAME_ASC,
                page_size=25,
                cursor=None,
            ),
        )
        server_prefix_plan = _capture_explain(
            engine,
            session,
            lambda: list_servers(
                session,
                filters=ServerFilters(search=normalize_literal_prefix("representative-099")),
                sort=ServerSort.NAME_ASC,
                page_size=25,
                cursor=None,
            ),
        )
        evidence_plan = _capture_explain(
            engine,
            session,
            lambda: list_dashboard_evidence(
                session,
                incident_id=incident_id,
                page_size=25,
                cursor=None,
            ),
        )

    server_nodes = _plan_nodes(server_plan)
    server_prefix_nodes = _plan_nodes(server_prefix_plan)
    evidence_nodes = _plan_nodes(evidence_plan)
    assert isinstance(database_collation, str) and database_collation
    print("7B_DATABASE_COLLATION", database_collation)
    print("7B_SERVER_PLAN", _plan_summary(server_nodes))
    print("7B_SERVER_PREFIX_PLAN", _plan_summary(server_prefix_nodes))
    print("7B_EVIDENCE_PLAN", _plan_summary(evidence_nodes))
    assert not any(
        node.get("Node Type") == "Seq Scan" and node.get("Relation Name") in {"events", "incidents"}
        for node in server_nodes
    )
    assert not any(
        node.get("Node Type") == "Seq Scan" and node.get("Relation Name") == "servers"
        for node in server_prefix_nodes
    )
    assert not any(
        node.get("Node Type") == "Sort" and _sort_key_contains(node, "linked_at")
        for node in evidence_nodes
    )


def _capture_explain(
    engine: Engine,
    session: Session,
    execute_query: Callable[[], object],
) -> dict[str, object]:
    captured: list[tuple[str, Any]] = []

    def capture(
        _connection: Connection,
        _cursor: object,
        statement: str,
        parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        captured.append((statement, parameters))

    sqlalchemy_event.listen(engine, "before_cursor_execute", capture)
    try:
        execute_query()
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", capture)
    assert len(captured) == 1
    statement, parameters = captured[0]
    connection = session.connection()
    raw_plan = connection.exec_driver_sql(
        f"EXPLAIN (FORMAT JSON, ANALYZE false) {statement}",
        parameters,
    ).scalar_one()
    assert isinstance(raw_plan, list) and len(raw_plan) == 1
    root = raw_plan[0]
    assert isinstance(root, dict) and isinstance(root.get("Plan"), dict)
    return cast(dict[str, object], root["Plan"])


def _plan_nodes(plan: dict[str, object]) -> list[dict[str, object]]:
    result = [plan]
    children = plan.get("Plans", [])
    assert isinstance(children, list)
    for child in children:
        assert isinstance(child, dict)
        result.extend(_plan_nodes(cast(dict[str, object], child)))
    return result


def _sort_key_contains(node: dict[str, object], value: str) -> bool:
    sort_keys = node.get("Sort Key", [])
    return isinstance(sort_keys, list) and any(value in str(key) for key in sort_keys)


def _plan_summary(nodes: list[dict[str, object]]) -> list[tuple[object, object, object]]:
    return [
        (node.get("Node Type"), node.get("Relation Name"), node.get("Index Name")) for node in nodes
    ]


def _create_representative_query_fixtures() -> UUID:
    now = datetime.now(UTC)
    server_ids = [UUID(int=index + 1) for index in range(1_000)]
    with get_session_factory().begin() as session:
        session.execute(
            insert(Server),
            [
                {
                    "id": server_id,
                    "name": f"representative-{index:04d}",
                    "hostname": f"representative-{index:04d}.invalid",
                    "description": None,
                    "is_active": index % 3 != 0,
                    "created_at": now,
                    "updated_at": now,
                }
                for index, server_id in enumerate(server_ids)
            ],
        )
        rule = load_rules_directory(RULES_DIR)[0]
        sync_rules(session, (rule,), activated_at=now)
        stored_rule = session.scalar(
            select(DetectionRuleVersion).where(DetectionRuleVersion.rule_key == rule.rule_key)
        )
        assert stored_rule is not None
        incident_ids = [UUID(int=100_000 + index) for index in range(2_000)]
        session.execute(
            insert(Incident),
            [
                {
                    "id": incident_id,
                    "server_id": server_ids[index // 2],
                    "rule_version_id": stored_rule.id,
                    "rule_key": rule.rule_key,
                    "rule_version": rule.version,
                    "severity": rule.severity.value,
                    "status": "resolved",
                    "title": f"Representative incident {index:04d}",
                    "explanation": "Synthetic representative fixture",
                    "recommendation": "Synthetic representative fixture",
                    "correlation": {},
                    "correlation_hash": f"{index:064x}",
                    "rule_snapshot": rule.model_dump(mode="json"),
                    "first_seen_at": now,
                    "last_seen_at": now,
                    "event_count": 1,
                    "lock_version": 1,
                    "created_at": now - timedelta(seconds=index),
                    "updated_at": now,
                }
                for index, incident_id in enumerate(incident_ids)
            ],
        )
        event_ids = [UUID(int=200_000 + index) for index in range(3_500)]
        session.execute(
            insert(Event),
            [
                {
                    "id": event_id,
                    "server_id": server_ids[0] if index < 2_500 else server_ids[index - 2_500],
                    "agent_event_id": UUID(int=300_000 + index),
                    "schema_version": 1,
                    "source": "journald",
                    "event_type": "linux.ssh.authentication_failed",
                    "occurred_at": now - timedelta(seconds=index),
                    "collected_at": now - timedelta(seconds=index),
                    "persisted_at": now,
                    "payload": {},
                }
                for index, event_id in enumerate(event_ids)
            ],
        )
        session.execute(
            insert(IncidentEvent),
            [
                {
                    "incident_id": incident_ids[0],
                    "event_id": event_id,
                    "linked_at": now - timedelta(milliseconds=index),
                }
                for index, event_id in enumerate(event_ids[:2_500])
            ],
        )
    with get_session_factory().begin() as session:
        session.execute(text("ANALYZE servers, events, incidents, incident_events"))
    return incident_ids[0]


def _create_incident_with_evidence() -> tuple[UUID, str]:
    rule = load_rules_directory(RULES_DIR)[0]
    now = datetime.now(UTC)
    canary = "canary-payload-actor-ip-correlation"
    with get_session_factory().begin() as session:
        sync_rules(session, (rule,), activated_at=now)
        stored_rule = session.scalar(
            select(DetectionRuleVersion).where(DetectionRuleVersion.rule_key == rule.rule_key)
        )
        assert stored_rule is not None
        server = Server(name=f"query-{uuid4().hex}", hostname=f"{uuid4().hex}.invalid")
        session.add(server)
        session.flush()
        event = Event(
            server_id=server.id,
            agent_event_id=uuid4(),
            schema_version=1,
            source="journald",
            event_type="linux.ssh.authentication_failed",
            occurred_at=now - timedelta(seconds=2),
            collected_at=now - timedelta(seconds=1),
            payload={
                "actor": canary,
                "source_ip": canary,
                "summary": canary,
                "attributes": {"secret": canary},
            },
        )
        incident = Incident(
            server_id=server.id,
            rule_version_id=stored_rule.id,
            rule_key=rule.rule_key,
            rule_version=rule.version,
            severity=rule.severity.value,
            status="new",
            title=rule.title,
            explanation=rule.explanation,
            recommendation=rule.recommendation,
            correlation={"unsafe": canary},
            correlation_hash="b" * 64,
            rule_snapshot=rule.model_dump(mode="json"),
            first_seen_at=event.occurred_at,
            last_seen_at=event.occurred_at,
            event_count=1,
        )
        session.add_all((event, incident))
        session.flush()
        session.add_all(
            (
                IncidentHistoryEntry(
                    incident_id=incident.id,
                    version=1,
                    entry_type="baseline",
                    from_status=None,
                    to_status="new",
                    reason=None,
                    changed_by_operator_id=None,
                    actor_username_snapshot=None,
                    auth_method_type=None,
                    auth_method_id=None,
                ),
                IncidentEvent(incident_id=incident.id, event_id=event.id, linked_at=now),
            )
        )
        return incident.id, canary
