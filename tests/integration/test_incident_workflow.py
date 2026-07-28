"""PostgreSQL integration and concurrency tests for stage 6B."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event
from typing import Any
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session

from tests.integration.conftest import AgentFactory, OperatorFactory, RegisteredAgent
from woland_guard_control_plane.application import incident_workflow
from woland_guard_control_plane.application.detection import engine as detection_engine
from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.application.detection.sync import sync_rules
from woland_guard_control_plane.application.incident_workflow import (
    canonical_transition_hash,
    normalize_transition,
    transition_incident,
)
from woland_guard_control_plane.application.operator_authentication import authenticate_operator
from woland_guard_control_plane.application.operator_keys import generate_operator_api_key
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    Incident,
    IncidentHistoryEntry,
    IncidentStatus,
    OperatorIdempotencyRecord,
    OperatorRole,
)

pytestmark = pytest.mark.integration

RULES_DIR = Path(__file__).parents[2] / "detection-rules"
INGESTION_PATH = "/api/v1/events"


def _sync_root_rule() -> None:
    rule = next(
        item
        for item in load_rules_directory(RULES_DIR)
        if item.rule_key == "ssh_root_login_success"
    )
    with get_session_factory().begin() as session:
        sync_rules(session, (rule,))


def _agent_headers(agent: RegisteredAgent, request_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {agent.token}", "X-Request-ID": request_id}


def _operator_headers(token: str, request_id: str, key: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}", "X-Request-ID": request_id}
    if key is not None:
        headers["Idempotency-Key"] = key
    return headers


def _event(occurred_at: datetime, *, event_id: UUID | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": str(event_id or uuid4()),
        "occurred_at": occurred_at.isoformat(),
        "collected_at": occurred_at.isoformat(),
        "source": "journald",
        "event_type": "linux.ssh.login_succeeded",
        "actor": "root",
        "source_ip": "192.0.2.10",
        "summary": "synthetic root login",
        "attributes": {},
    }


def _batch(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "batch_id": str(uuid4()),
        "sent_at": datetime.now(UTC).isoformat(),
        "events": [event],
    }


def _create_incident(
    client: TestClient,
    register_agent: AgentFactory,
    *,
    occurred_at: datetime | None = None,
) -> tuple[Incident, RegisteredAgent]:
    agent = register_agent()
    response = client.post(
        INGESTION_PATH,
        json=_batch(_event(occurred_at or datetime.now(UTC) - timedelta(seconds=1))),
        headers=_agent_headers(agent, f"create-incident-{uuid4().hex}"),
    )
    assert response.status_code == 200
    with get_session_factory()() as session:
        incident = session.scalar(select(Incident).where(Incident.server_id == agent.server_id))
        assert incident is not None
        session.expunge(incident)
    return incident, agent


def _transition(
    client: TestClient,
    *,
    incident_id: UUID,
    token: str,
    key: str,
    status_value: str,
    expected_version: int,
    reason: str | None = None,
) -> Any:
    return client.post(
        f"/api/v1/incidents/{incident_id}/transitions",
        json={"status": status_value, "expected_version": expected_version, "reason": reason},
        headers=_operator_headers(
            token,
            f"transition-{key}-{uuid4().hex}",
            key,
        ),
    )


def test_ingestion_creates_one_baseline_and_evidence_does_not_increment_version(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    _sync_root_rule()
    incident, agent = _create_incident(client, register_agent)

    second = client.post(
        INGESTION_PATH,
        json=_batch(_event(datetime.now(UTC) - timedelta(milliseconds=100))),
        headers=_agent_headers(agent, "second-evidence"),
    )

    assert second.status_code == 200
    with get_session_factory()() as session:
        stored = session.get(Incident, incident.id)
        assert stored is not None
        assert stored.event_count == 2
        assert stored.lock_version == 1
        history = session.scalars(
            select(IncidentHistoryEntry).where(IncidentHistoryEntry.incident_id == incident.id)
        ).all()
        assert [(entry.entry_type, entry.version, entry.to_status) for entry in history] == [
            ("baseline", 1, "new")
        ]


@pytest.mark.parametrize(
    ("start_investigating", "target_status"),
    [
        (False, "investigating"),
        (False, "resolved"),
        (False, "false_positive"),
        (True, "resolved"),
        (True, "false_positive"),
    ],
)
def test_every_allowed_transition_commits_history_audit_and_idempotency(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
    start_investigating: bool,
    target_status: str,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    expected_version = 1
    if start_investigating:
        first = _transition(
            client,
            incident_id=incident.id,
            token=operator.token,
            key="allowed-first",
            status_value="investigating",
            expected_version=1,
        )
        assert first.status_code == 200
        expected_version = 2

    response = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="allowed-target",
        status_value=target_status,
        expected_version=expected_version,
        reason="synthetic review" if target_status != "investigating" else None,
    )

    assert response.status_code == 200
    assert response.json()["incident"]["status"] == target_status
    assert response.json()["incident"]["version"] == expected_version + 1
    with get_session_factory()() as session:
        stored = session.get(Incident, incident.id)
        assert stored is not None
        assert stored.status == target_status
        assert stored.lock_version == expected_version + 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(IncidentHistoryEntry)
                .where(IncidentHistoryEntry.incident_id == incident.id)
            )
            == expected_version + 1
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "incident.status_changed")
            )
            == expected_version
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(OperatorIdempotencyRecord)
                .where(OperatorIdempotencyRecord.resource_id == incident.id)
            )
            == expected_version
        )


def test_success_replay_precedes_stale_check_and_returns_original_snapshot(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    first = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="replay-original",
        status_value="investigating",
        expected_version=1,
    )
    terminal = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="replay-terminal",
        status_value="resolved",
        expected_version=2,
        reason="synthetic terminal decision",
    )
    replay = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="replay-original",
        status_value="investigating",
        expected_version=1,
    )

    assert first.status_code == terminal.status_code == replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json()["incident"] == first.json()["incident"]
    assert replay.json()["incident"]["status"] == "investigating"
    assert replay.json()["request_id"] != first.json()["request_id"]
    with get_session_factory()() as session:
        stored = session.get(Incident, incident.id)
        assert stored is not None
        assert (stored.status, stored.lock_version) == ("resolved", 3)


def test_same_key_with_other_incident_conflicts_without_reading_that_incident(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    first = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="same-key-other-resource",
        status_value="investigating",
        expected_version=1,
    )
    unknown_incident_id = uuid4()
    conflict = _transition(
        client,
        incident_id=unknown_incident_id,
        token=operator.token,
        key="same-key-other-resource",
        status_value="resolved",
        expected_version=999,
        reason="different request",
    )

    assert first.status_code == 200
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "Idempotency-Key was already used for another request"
    assert unknown_incident_id.hex not in conflict.text


@pytest.mark.parametrize("result_kind", ["not_found", "stale_version"])
def test_saved_404_and_409_are_committed_and_replayed(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
    result_kind: str,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id = uuid4() if result_kind == "not_found" else incident.id
    expected_version = 1 if result_kind == "not_found" else 99
    key = f"saved-{result_kind}"

    first = _transition(
        client,
        incident_id=incident_id,
        token=operator.token,
        key=key,
        status_value="resolved",
        expected_version=expected_version,
        reason="synthetic deterministic result",
    )
    replay = _transition(
        client,
        incident_id=incident_id,
        token=operator.token,
        key=key,
        status_value="resolved",
        expected_version=expected_version,
        reason="synthetic deterministic result",
    )

    assert first.status_code == (404 if result_kind == "not_found" else 409)
    assert replay.status_code == first.status_code
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json()["detail"] == first.json()["detail"]
    with get_session_factory()() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(OperatorIdempotencyRecord)
                .where(OperatorIdempotencyRecord.idempotency_key == key)
            )
            == 1
        )


def test_identical_parallel_requests_mutate_once(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    transition = normalize_transition(
        target_status=IncidentStatus.RESOLVED,
        expected_version=1,
        reason="parallel synthetic decision",
    )
    request_hash = canonical_transition_hash(incident.id, transition)
    start = Barrier(2)

    def execute() -> Any:
        with get_session_factory()() as session, session.begin():
            actor = authenticate_operator(session, operator.token, now=datetime.now(UTC))
            start.wait(timeout=10)
            return transition_incident(
                session,
                actor=actor.principal,
                incident_id=incident.id,
                transition=transition,
                idempotency_key="parallel-identical",
                canonical_request_hash=request_hash,
                request_id=uuid4().hex,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [
            future.result(timeout=20) for future in [executor.submit(execute) for _ in range(2)]
        ]

    assert [outcome.http_status for outcome in outcomes] == [200, 200]
    assert sorted(outcome.replayed for outcome in outcomes) == [False, True]
    assert outcomes[0].response_body == outcomes[1].response_body
    with get_session_factory()() as session:
        assert _workflow_counts(session, incident.id) == (2, 1, 1)


def test_parallel_different_keys_with_same_version_have_one_stale_result(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    start = Barrier(2)
    transitions = [
        normalize_transition(
            target_status=IncidentStatus.RESOLVED,
            expected_version=1,
            reason="parallel resolved",
        ),
        normalize_transition(
            target_status=IncidentStatus.FALSE_POSITIVE,
            expected_version=1,
            reason="parallel false positive",
        ),
    ]

    def execute(index: int) -> Any:
        transition = transitions[index]
        with get_session_factory()() as session, session.begin():
            actor = authenticate_operator(session, operator.token, now=datetime.now(UTC))
            start.wait(timeout=10)
            return transition_incident(
                session,
                actor=actor.principal,
                incident_id=incident.id,
                transition=transition,
                idempotency_key=f"parallel-version-{index}",
                canonical_request_hash=canonical_transition_hash(incident.id, transition),
                request_id=uuid4().hex,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [
            future.result(timeout=20) for future in [executor.submit(execute, i) for i in range(2)]
        ]

    assert sorted(outcome.http_status for outcome in outcomes) == [200, 409]
    assert {outcome.conflict_type for outcome in outcomes} == {None, "stale_version"}
    with get_session_factory()() as session:
        assert _workflow_counts(session, incident.id) == (2, 1, 2)


def test_parallel_different_requests_with_same_idempotency_key_mutate_once(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    start = Barrier(2)
    transitions = (
        normalize_transition(
            target_status=IncidentStatus.RESOLVED,
            expected_version=1,
            reason="parallel resolved",
        ),
        normalize_transition(
            target_status=IncidentStatus.FALSE_POSITIVE,
            expected_version=1,
            reason="parallel false positive",
        ),
    )

    def execute(index: int) -> Any:
        transition = transitions[index]
        with get_session_factory()() as session, session.begin():
            actor = authenticate_operator(session, operator.token, now=datetime.now(UTC))
            start.wait(timeout=10)
            return transition_incident(
                session,
                actor=actor.principal,
                incident_id=incident.id,
                transition=transition,
                idempotency_key="parallel-different",
                canonical_request_hash=canonical_transition_hash(incident.id, transition),
                request_id=uuid4().hex,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [
            future.result(timeout=20) for future in [executor.submit(execute, i) for i in range(2)]
        ]

    assert sorted(outcome.http_status for outcome in outcomes) == [200, 409]
    assert {outcome.conflict_type for outcome in outcomes} == {
        None,
        "idempotency_key_reused",
    }
    with get_session_factory()() as session:
        assert _workflow_counts(session, incident.id) == (2, 1, 1)


def test_forbidden_terminal_transition_is_saved_without_history_or_audit(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    terminal = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="terminal-first",
        status_value="resolved",
        expected_version=1,
        reason="terminal synthetic decision",
    )
    forbidden = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="terminal-forbidden",
        status_value="investigating",
        expected_version=2,
    )

    assert terminal.status_code == 200
    assert forbidden.status_code == 409
    assert forbidden.json()["conflict_type"] == "transition_not_allowed"
    with get_session_factory()() as session:
        assert _workflow_counts(session, incident.id) == (2, 1, 2)


@pytest.mark.parametrize(
    "reason",
    ["unsafe\x00reason", "unsafe\nreason", "unsafe\treason", "unsafe\u200breason"],
)
def test_invalid_terminal_reason_is_rejected_before_workflow_persistence(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
    reason: str,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)

    response = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key=f"invalid-reason-{ord(reason[6])}",
        status_value="resolved",
        expected_version=1,
        reason=reason,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "invalid transition request"
    assert reason not in response.text
    assert "Idempotency-Replayed" not in response.headers
    with get_session_factory()() as session:
        stored = session.get(Incident, incident.id)
        assert stored is not None
        assert (stored.status, stored.lock_version) == ("new", 1)
        assert _workflow_counts(session, incident.id) == (1, 0, 0)


def test_database_error_rolls_back_incident_history_audit_and_idempotency(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)

    def fail_audit(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise OperationalError("synthetic audit failure", {}, RuntimeError("synthetic"))

    monkeypatch.setattr(incident_workflow, "record_operator_action", fail_audit)
    response = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="rollback-all",
        status_value="resolved",
        expected_version=1,
        reason="synthetic rollback decision",
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "incident transition unavailable"
    assert "synthetic" not in response.text
    with get_session_factory()() as session:
        stored = session.get(Incident, incident.id)
        assert stored is not None
        assert (stored.status, stored.lock_version) == ("new", 1)
        assert _workflow_counts(session, incident.id) == (1, 0, 0)


def test_ingestion_race_after_terminal_transition_creates_new_incident(
    api_app: Any,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sync_root_rule()
    with TestClient(api_app) as initial_client:
        first_incident, agent = _create_incident(initial_client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    detection_ready = Event()
    continue_detection = Event()
    original_persist = detection_engine._persist_match

    def synchronized_persist(*args: Any, **kwargs: Any) -> Any:
        detection_ready.set()
        assert continue_detection.wait(timeout=10)
        return original_persist(*args, **kwargs)

    monkeypatch.setattr(detection_engine, "_persist_match", synchronized_persist)
    with (
        TestClient(api_app) as ingestion_client,
        TestClient(api_app) as transition_client,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        ingestion_future = executor.submit(
            ingestion_client.post,
            INGESTION_PATH,
            json=_batch(_event(datetime.now(UTC) - timedelta(milliseconds=100))),
            headers=_agent_headers(agent, "terminal-race-ingestion"),
        )
        assert detection_ready.wait(timeout=10)
        transition_response = _transition(
            transition_client,
            incident_id=first_incident.id,
            token=operator.token,
            key="terminal-race-transition",
            status_value="resolved",
            expected_version=1,
            reason="terminal before active incident lookup",
        )
        continue_detection.set()
        ingestion_response = ingestion_future.result(timeout=20)

    assert transition_response.status_code == 200
    assert ingestion_response.status_code == 200
    with get_session_factory()() as session:
        incidents = session.scalars(
            select(Incident)
            .where(Incident.server_id == agent.server_id)
            .order_by(Incident.created_at)
        ).all()
        assert len(incidents) == 2
        assert (incidents[0].status, incidents[0].event_count, incidents[0].lock_version) == (
            "resolved",
            1,
            2,
        )
        assert (incidents[1].status, incidents[1].event_count, incidents[1].lock_version) == (
            "new",
            1,
            1,
        )


def test_immutable_tables_reject_update_delete_and_truncate_and_cleanup_reenables_triggers(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    response = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="immutable-fixture",
        status_value="resolved",
        expected_version=1,
        reason="immutable synthetic result",
    )
    assert response.status_code == 200

    destructive_statements = {
        "incident_history": (
            "UPDATE incident_history SET created_at = created_at",
            "DELETE FROM incident_history",
            "TRUNCATE TABLE incident_history",
        ),
        "audit_log_entries": (
            "UPDATE audit_log_entries SET created_at = created_at",
            "DELETE FROM audit_log_entries",
            "TRUNCATE TABLE audit_log_entries",
        ),
        "operator_idempotency_records": (
            "UPDATE operator_idempotency_records SET created_at = created_at",
            "DELETE FROM operator_idempotency_records",
            "TRUNCATE TABLE operator_idempotency_records",
        ),
    }
    for table_name, statements in destructive_statements.items():
        for statement in statements:
            with pytest.raises(DBAPIError), get_engine().begin() as connection:
                connection.execute(text(statement))
        with get_engine().connect() as connection:
            enabled = connection.execute(
                text(
                    "SELECT count(*) FROM pg_trigger "
                    "WHERE tgrelid = CAST(:table_name AS regclass) "
                    "AND NOT tgisinternal AND tgenabled = 'O'"
                ),
                {"table_name": table_name},
            ).scalar_one()
        assert enabled == 2


def test_incident_cursor_filters_and_responses_never_expose_event_payload(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incidents = [_create_incident(client, register_agent)[0] for _ in range(3)]
    viewer = register_operator(role=OperatorRole.VIEWER)
    headers = _operator_headers(viewer.token, "incident-pagination")

    first = client.get(
        "/api/v1/incidents?status=new&status=new&limit=2",
        headers=headers,
    )
    assert first.status_code == 200
    cursor = first.json()["next_cursor"]
    second = client.get(
        "/api/v1/incidents",
        params={"status": "new", "limit": 2, "cursor": cursor},
        headers=headers,
    )
    assert second.status_code == 200
    ids = [item["id"] for item in first.json()["items"] + second.json()["items"]]
    assert len(ids) == len(set(ids)) == len(incidents)

    mismatch = client.get(
        "/api/v1/incidents",
        params={"status": "new", "severity": "critical", "cursor": cursor},
        headers=headers,
    )
    assert mismatch.status_code == 400
    assert cursor not in mismatch.text

    oversized_cursor = "a" * 1_025
    oversized = client.get(
        "/api/v1/incidents",
        params={"cursor": oversized_cursor},
        headers=headers,
    )
    assert oversized.status_code == 400
    assert oversized_cursor not in oversized.text

    detail = client.get(f"/api/v1/incidents/{incidents[0].id}", headers=headers)
    assert detail.status_code == 200
    serialized = detail.text.lower()
    for forbidden in ("payload", "attributes", "correlation", "secret_hash", "source_ip"):
        assert forbidden not in serialized


def test_rbac_denials_do_not_create_audit_entries(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    viewer = register_operator(role=OperatorRole.VIEWER)
    analyst = register_operator(role=OperatorRole.ANALYST)
    admin = register_operator(role=OperatorRole.ADMIN)
    initial_incident_audit = _incident_audit_count()

    viewer_list = client.get(
        "/api/v1/incidents",
        headers=_operator_headers(viewer.token, "viewer-list"),
    )
    viewer_transition = _transition(
        client,
        incident_id=incident.id,
        token=viewer.token,
        key="viewer-denied",
        status_value="investigating",
        expected_version=1,
    )
    analyst_audit = client.get(
        "/api/v1/audit-log",
        headers=_operator_headers(analyst.token, "analyst-audit"),
    )
    admin_audit = client.get(
        "/api/v1/audit-log",
        headers=_operator_headers(admin.token, "admin-audit"),
    )
    unknown_token = generate_operator_api_key().token
    unknown_credentials = client.get(
        "/api/v1/incidents",
        headers=_operator_headers(unknown_token, "unknown-credentials"),
    )

    assert viewer_list.status_code == 200
    assert viewer_transition.status_code == analyst_audit.status_code == 403
    assert unknown_credentials.status_code == 401
    assert admin_audit.status_code == 200
    assert _incident_audit_count() == initial_incident_audit


def test_audit_cursor_is_filter_bound_and_response_is_allowlisted(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    analyst = register_operator(role=OperatorRole.ANALYST)
    admin = register_operator(role=OperatorRole.ADMIN)
    investigating = _transition(
        client,
        incident_id=incident.id,
        token=analyst.token,
        key="audit-first",
        status_value="investigating",
        expected_version=1,
    )
    resolved = _transition(
        client,
        incident_id=incident.id,
        token=analyst.token,
        key="audit-second",
        status_value="resolved",
        expected_version=2,
        reason="synthetic audit result",
    )
    assert investigating.status_code == resolved.status_code == 200
    headers = _operator_headers(admin.token, "audit-pagination")
    params: dict[str, str | int] = {
        "action": "incident.status_changed",
        "target_id": str(incident.id),
        "limit": 1,
    }

    first = client.get("/api/v1/audit-log", params=params, headers=headers)
    assert first.status_code == 200
    cursor = first.json()["next_cursor"]
    assert cursor is not None
    second = client.get(
        "/api/v1/audit-log",
        params={**params, "cursor": cursor},
        headers=headers,
    )
    assert second.status_code == 200
    items = first.json()["items"] + second.json()["items"]
    assert len({item["id"] for item in items}) == 2
    assert all(item["action"] == "incident.status_changed" for item in items)
    assert all(
        set(item["details"])
        == {"from_status", "from_version", "history_id", "to_status", "to_version"}
        for item in items
    )
    assert {item["details"]["from_status"] for item in items} == {"new", "investigating"}
    assert {item["details"]["to_status"] for item in items} == {
        "investigating",
        "resolved",
    }
    assert {item["details"]["from_version"] for item in items} == {1, 2}
    assert {item["details"]["to_version"] for item in items} == {2, 3}
    assert all(
        str(UUID(item["details"]["history_id"])) == item["details"]["history_id"] for item in items
    )
    serialized = str(items).lower()
    for forbidden in (
        analyst.token.lower(),
        admin.token.lower(),
        "secret_hash",
        "payload",
        "correlation",
        "source_ip",
    ):
        assert forbidden not in serialized

    mismatch = client.get(
        "/api/v1/audit-log",
        params={**params, "target_id": str(uuid4()), "cursor": cursor},
        headers=headers,
    )
    assert mismatch.status_code == 400
    assert cursor not in mismatch.text


def test_migration_cycle_backfills_exactly_one_baseline_for_existing_incident(
    client: TestClient,
    register_agent: AgentFactory,
    register_operator: OperatorFactory,
) -> None:
    _sync_root_rule()
    incident, _agent = _create_incident(client, register_agent)
    operator = register_operator(role=OperatorRole.ANALYST)
    terminal = _transition(
        client,
        incident_id=incident.id,
        token=operator.token,
        key="migration-terminal",
        status_value="resolved",
        expected_version=1,
        reason="synthetic state before migration cycle",
    )
    assert terminal.status_code == 200
    config = Config("alembic.ini")

    command.downgrade(config, "20260722_0003")
    try:
        with get_engine().connect() as connection:
            preserved_status = connection.execute(
                text("SELECT status FROM incidents WHERE id = :incident_id"),
                {"incident_id": incident.id},
            ).scalar_one()
            lock_version_column = connection.execute(
                text(
                    "SELECT count(*) FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = 'incidents' "
                    "AND column_name = 'lock_version'"
                )
            ).scalar_one()
        assert preserved_status == "resolved"
        assert lock_version_column == 0

        command.upgrade(config, "head")
        with get_session_factory()() as session:
            stored = session.get(Incident, incident.id)
            assert stored is not None
            assert (stored.status, stored.lock_version) == ("resolved", 1)
            baselines = session.scalars(
                select(IncidentHistoryEntry).where(IncidentHistoryEntry.incident_id == incident.id)
            ).all()
            assert len(baselines) == 1
            assert (
                baselines[0].entry_type,
                baselines[0].version,
                baselines[0].from_status,
                baselines[0].to_status,
                baselines[0].reason,
            ) == ("baseline", 1, None, "resolved", None)
    finally:
        command.upgrade(config, "head")


def _workflow_counts(session: Session, incident_id: UUID) -> tuple[int, int, int]:
    history = session.scalar(
        select(func.count())
        .select_from(IncidentHistoryEntry)
        .where(IncidentHistoryEntry.incident_id == incident_id)
    )
    audit = session.scalar(
        select(func.count())
        .select_from(AuditLogEntry)
        .where(AuditLogEntry.action == "incident.status_changed")
    )
    idempotency = session.scalar(
        select(func.count())
        .select_from(OperatorIdempotencyRecord)
        .where(OperatorIdempotencyRecord.resource_id == incident_id)
    )
    return int(history or 0), int(audit or 0), int(idempotency or 0)


def _incident_audit_count() -> int:
    with get_session_factory()() as session:
        value = session.scalar(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.action == "incident.status_changed")
        )
    return int(value or 0)
