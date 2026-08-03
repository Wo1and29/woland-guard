"""PostgreSQL integration tests for rule sync and transactional detection."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any, NoReturn, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tests.integration.conftest import AgentFactory, RegisteredAgent
from woland_guard_control_plane import cli
from woland_guard_control_plane.api.routes import events as events_route
from woland_guard_control_plane.application.agent_keys import generate_agent_api_key
from woland_guard_control_plane.application.detection import engine as detection_engine
from woland_guard_control_plane.application.detection.engine import DetectionEngineError
from woland_guard_control_plane.application.detection.rules import (
    RuleDefinition,
    RuleValidationError,
    load_rules_directory,
)
from woland_guard_control_plane.application.detection.sync import RuleSyncError, sync_rules
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    NotificationDestination,
    OutboxMessage,
    TelegramDestinationConfig,
)

pytestmark = pytest.mark.integration

INGESTION_PATH = "/api/v1/events"
RULES_DIR = Path(__file__).parents[2] / "detection-rules"


def _default_rule(rule_key: str) -> RuleDefinition:
    return next(rule for rule in load_rules_directory(RULES_DIR) if rule.rule_key == rule_key)


def _sync_rule(rule_key: str) -> None:
    with get_session_factory().begin() as session:
        assert sync_rules(session, (_default_rule(rule_key),)) == 1


def _create_destination(*, minimum_severity: str = "low") -> UUID:
    unique = uuid4()
    with get_session_factory().begin() as session:
        destination = NotificationDestination(
            adapter_kind="telegram",
            enabled=False,
            minimum_severity=minimum_severity,
        )
        session.add(destination)
        session.flush()
        session.add(
            TelegramDestinationConfig(
                destination_id=destination.id,
                chat_id=(unique.int % (2**52 - 1)) + 1,
                token_file_name=f"{unique.hex}.token",
            )
        )
        session.flush()
        destination.enabled = True
        session.flush()
        return destination.id


def _event(
    event_type: str,
    occurred_at: datetime,
    *,
    event_id: str | None = None,
    actor: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": event_id or str(uuid4()),
        "occurred_at": occurred_at.isoformat(),
        "collected_at": occurred_at.isoformat(),
        "source": "journald",
        "event_type": event_type,
        "actor": actor,
        "source_ip": source_ip,
        "summary": "synthetic detection integration event",
        "attributes": attributes or {},
    }


def _batch(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "batch_id": str(uuid4()),
        "sent_at": datetime.now(UTC).isoformat(),
        "events": events,
    }


def _headers(agent: RegisteredAgent, request_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {agent.token}",
        "X-Request-ID": request_id,
    }


def _positive_events(rule_key: str, base: datetime) -> list[dict[str, Any]]:
    if rule_key == "ssh_bruteforce_by_ip":
        return [
            _event("linux.ssh.authentication_failed", base + timedelta(seconds=offset))
            for offset in range(-7, 1)
        ]
    if rule_key == "ssh_password_spray_by_ip":
        return [
            _event(
                "linux.ssh.authentication_failed",
                base + timedelta(seconds=offset),
                actor=f"user-{offset}",
            )
            for offset in range(-4, 1)
        ]
    if rule_key == "ssh_success_after_failures":
        return [
            *[
                _event(
                    "linux.ssh.authentication_failed",
                    base + timedelta(seconds=offset),
                )
                for offset in (-3, -2, -1)
            ],
            _event("linux.ssh.login_succeeded", base),
        ]
    if rule_key == "ssh_login_from_new_ip":
        return [
            _event(
                "linux.ssh.login_succeeded",
                base - timedelta(seconds=1),
                source_ip="192.0.2.1",
            ),
            _event("linux.ssh.login_succeeded", base, source_ip="192.0.2.2"),
        ]
    if rule_key == "ssh_root_login_success":
        return [_event("linux.ssh.login_succeeded", base, actor="root")]
    if rule_key == "sudo_auth_failures":
        return [
            _event(
                "linux.sudo.authentication_failed",
                base + timedelta(seconds=offset),
                source_ip=None,
            )
            for offset in range(-4, 1)
        ]
    if rule_key == "user_account_created":
        return [_event("linux.account.user_created", base, source_ip=None)]
    if rule_key == "privileged_group_membership_changed":
        return [
            _event(
                "linux.account.privileged_group_changed",
                base,
                source_ip=None,
                attributes={"group": "sudo", "action": "added"},
            )
        ]
    raise AssertionError(f"unknown default rule: {rule_key}")


def test_sync_rules_cli_activates_exactly_eight_validated_defaults(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The local CLI appends and atomically activates the complete default set."""

    monkeypatch.setattr(
        "sys.argv",
        ["woland-guard-admin", "sync-rules", "--rules-dir", str(RULES_DIR)],
    )

    cli.main()

    assert capsys.readouterr().out == "Активировано правил: 8\n"
    with get_session_factory()() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(DetectionRuleVersion)
                .where(DetectionRuleVersion.is_active.is_(True))
            )
            == 8
        )


@pytest.mark.parametrize(
    ("rule_key", "expected_evidence"),
    [
        ("ssh_bruteforce_by_ip", 8),
        ("ssh_password_spray_by_ip", 5),
        ("ssh_success_after_failures", 4),
        ("ssh_login_from_new_ip", 2),
        ("ssh_root_login_success", 1),
        ("sudo_auth_failures", 5),
        ("user_account_created", 1),
        ("privileged_group_membership_changed", 1),
    ],
)
def test_each_rule_runs_ingestion_to_incident_on_real_postgresql(
    client: TestClient,
    register_agent: AgentFactory,
    rule_key: str,
    expected_evidence: int,
) -> None:
    """Each journald rule has an end-to-end normalized event → incident proof."""

    _sync_rule(rule_key)
    agent = register_agent()
    events = _positive_events(rule_key, datetime.now(UTC) - timedelta(seconds=1))

    response = client.post(
        INGESTION_PATH,
        json=_batch(events),
        headers=_headers(agent, f"e2e-{rule_key}"),
    )

    assert response.status_code == 200
    assert response.json()["accepted"] == len(events)
    with get_session_factory()() as session:
        incident = session.execute(select(Incident)).scalar_one()
        assert incident.server_id == agent.server_id
        assert incident.rule_key == rule_key
        assert incident.status == "new"
        assert incident.event_count == expected_evidence
        assert incident.rule_snapshot["rule_key"] == rule_key
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == expected_evidence


def test_new_incident_without_destination_creates_no_outbox_row(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    _sync_rule("ssh_root_login_success")
    agent = register_agent()

    response = client.post(
        INGESTION_PATH,
        json=_batch(
            _positive_events("ssh_root_login_success", datetime.now(UTC) - timedelta(seconds=1))
        ),
        headers=_headers(agent, "outbox-no-destination"),
    )

    assert response.status_code == 200
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Incident)) == 1
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0


@pytest.mark.parametrize("destination_count", [1, 2])
def test_new_incident_creates_one_outbox_per_enabled_destination(
    client: TestClient,
    register_agent: AgentFactory,
    destination_count: int,
) -> None:
    _sync_rule("ssh_root_login_success")
    destination_ids = {_create_destination() for _ in range(destination_count)}
    agent = register_agent()

    response = client.post(
        INGESTION_PATH,
        json=_batch(
            _positive_events("ssh_root_login_success", datetime.now(UTC) - timedelta(seconds=1))
        ),
        headers=_headers(agent, f"outbox-destinations-{destination_count}"),
    )

    assert response.status_code == 200
    with get_session_factory()() as session:
        incident = session.execute(select(Incident)).scalar_one()
        messages = session.scalars(
            select(OutboxMessage).order_by(OutboxMessage.destination_id)
        ).all()
        assert len(messages) == destination_count
        assert {message.destination_id for message in messages} == destination_ids
        for message in messages:
            assert message.incident_id == incident.id
            assert message.notification_type == "incident.created"
            assert set(message.payload) == {
                "schema_version",
                "notification_type",
                "incident_id",
                "server_id",
                "rule_key",
                "rule_version",
                "severity",
                "title",
                "title_en",
                "created_at",
            }


def test_destination_minimum_severity_filters_outbox_routing(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    _sync_rule("ssh_root_login_success")
    accepted_destination = _create_destination(minimum_severity="medium")
    _create_destination(minimum_severity="critical")
    agent = register_agent()

    response = client.post(
        INGESTION_PATH,
        json=_batch(
            _positive_events("ssh_root_login_success", datetime.now(UTC) - timedelta(seconds=1))
        ),
        headers=_headers(agent, "outbox-severity-routing"),
    )

    assert response.status_code == 200
    with get_session_factory()() as session:
        message = session.execute(select(OutboxMessage)).scalar_one()
        assert message.destination_id == accepted_destination


def test_duplicate_delivery_does_not_run_detection_or_duplicate_evidence(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """ON CONFLICT rows are existing and never enter the Detection Engine."""

    _sync_rule("ssh_root_login_success")
    agent = register_agent()
    event = _positive_events("ssh_root_login_success", datetime.now(UTC) - timedelta(seconds=1))[0]

    first = client.post(
        INGESTION_PATH,
        json=_batch([event]),
        headers=_headers(agent, "duplicate-first"),
    )
    second = client.post(
        INGESTION_PATH,
        json=_batch([event]),
        headers=_headers(agent, "duplicate-second"),
    )

    assert (first.json()["accepted"], first.json()["existing"]) == (1, 0)
    assert (second.json()["accepted"], second.json()["existing"]) == (0, 1)
    with get_session_factory()() as session:
        incident = session.execute(select(Incident)).scalar_one()
        assert incident.event_count == 1
        assert session.scalar(select(func.count()).select_from(Event)) == 1
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 1


def test_repeated_match_updates_one_active_incident_with_unique_evidence(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """A later match reuses its correlation bucket and extends first/last/evidence."""

    _sync_rule("ssh_root_login_success")
    _create_destination()
    agent = register_agent()
    first_time = datetime.now(UTC) - timedelta(seconds=2)
    second_time = first_time + timedelta(seconds=1)
    first_event = _event("linux.ssh.login_succeeded", first_time, actor="root")
    second_event = _event("linux.ssh.login_succeeded", second_time, actor="root")

    for index, event in enumerate((first_event, second_event)):
        response = client.post(
            INGESTION_PATH,
            json=_batch([event]),
            headers=_headers(agent, f"repeat-match-{index}"),
        )
        assert response.status_code == 200

    with get_session_factory()() as session:
        incident = session.execute(select(Incident)).scalar_one()
        assert incident.first_seen_at == first_time
        assert incident.last_seen_at == second_time
        assert incident.event_count == 2
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 2
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 1


def test_server_and_correlation_boundaries_create_separate_incidents(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """The same rule is isolated by server and explicit source_ip correlation."""

    _sync_rule("ssh_root_login_success")
    first_agent = register_agent()
    second_agent = register_agent()
    base = datetime.now(UTC) - timedelta(seconds=1)
    requests = (
        (
            first_agent,
            _event("linux.ssh.login_succeeded", base, actor="root", source_ip="192.0.2.1"),
        ),
        (
            first_agent,
            _event("linux.ssh.login_succeeded", base, actor="root", source_ip="192.0.2.2"),
        ),
        (
            second_agent,
            _event("linux.ssh.login_succeeded", base, actor="root", source_ip="192.0.2.1"),
        ),
    )

    for index, (agent, event) in enumerate(requests):
        response = client.post(
            INGESTION_PATH,
            json=_batch([event]),
            headers=_headers(agent, f"isolation-{index}"),
        )
        assert response.status_code == 200

    with get_session_factory()() as session:
        incidents = session.scalars(select(Incident)).all()
        assert len(incidents) == 3
        assert len({(item.server_id, item.correlation_hash) for item in incidents}) == 3


def test_incident_snapshot_stays_immutable_after_new_rule_activation(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """Events handled by v2 create a separate incident with the matching snapshot."""

    original = _default_rule("ssh_root_login_success")
    with get_session_factory().begin() as session:
        sync_rules(session, (original,))
    agent = register_agent()
    base = datetime.now(UTC) - timedelta(seconds=2)
    first = client.post(
        INGESTION_PATH,
        json=_batch([_event("linux.ssh.login_succeeded", base, actor="root")]),
        headers=_headers(agent, "snapshot-v1"),
    )
    assert first.status_code == 200

    successor = original.version + 1
    second_version = original.model_copy(
        update={"version": successor, "title": "Synthetic changed successor title"}
    )
    with get_session_factory().begin() as session:
        sync_rules(session, (second_version,))

    second = client.post(
        INGESTION_PATH,
        json=_batch(
            [
                _event(
                    "linux.ssh.login_succeeded",
                    base + timedelta(seconds=1),
                    actor="root",
                )
            ]
        ),
        headers=_headers(agent, "snapshot-v2"),
    )
    assert second.status_code == 200

    with get_session_factory()() as session:
        versions = session.scalars(
            select(DetectionRuleVersion).order_by(DetectionRuleVersion.version)
        ).all()
        incidents = session.scalars(select(Incident).order_by(Incident.rule_version)).all()
        assert [(version.version, version.is_active) for version in versions] == [
            (original.version, False),
            (successor, True),
        ]
        assert versions[0].definition["title"] == original.title
        assert len(incidents) == 2
        first_incident, second_incident = incidents
        assert first_incident.rule_version_id == versions[0].id
        assert first_incident.rule_version == original.version
        assert first_incident.rule_snapshot["version"] == original.version
        assert first_incident.title == original.title
        assert first_incident.event_count == 1
        assert second_incident.rule_version_id == versions[1].id
        assert second_incident.rule_version == successor
        assert second_incident.rule_snapshot["version"] == successor
        assert second_incident.title == second_version.title
        assert second_incident.event_count == 1
        evidence_counts: dict[UUID, int] = dict(
            session.execute(
                select(IncidentEvent.incident_id, func.count())
                .group_by(IncidentEvent.incident_id)
                .order_by(IncidentEvent.incident_id)
            )
            .tuples()
            .all()
        )
        assert evidence_counts == {
            first_incident.id: 1,
            second_incident.id: 1,
        }


def test_malformed_rule_set_does_not_change_active_versions(tmp_path: Path) -> None:
    """Validation fails before a synchronization transaction can alter PostgreSQL."""

    _sync_rule("ssh_root_login_success")
    valid = (RULES_DIR / "ssh_root_login_success.yaml").read_text(encoding="utf-8")
    (tmp_path / "01-valid.yaml").write_text(valid, encoding="utf-8")
    (tmp_path / "02-malformed.yaml").write_text("condition: [broken\n", encoding="utf-8")

    with pytest.raises(RuleValidationError):
        load_rules_directory(tmp_path)

    with get_session_factory()() as session:
        versions = session.scalars(select(DetectionRuleVersion)).all()
        assert len(versions) == 1
        assert versions[0].is_active is True
        assert versions[0].version == _default_rule("ssh_root_login_success").version


def test_published_rule_version_cannot_be_mutated() -> None:
    """The same rule_key/version with different canonical content is rejected atomically."""

    original = _default_rule("ssh_root_login_success")
    with get_session_factory().begin() as session:
        sync_rules(session, (original,))
    changed_same_version = original.model_copy(update={"title": "Forbidden in-place change"})

    with pytest.raises(RuleSyncError, match="immutable rule version conflicts"):
        with get_session_factory().begin() as session:
            sync_rules(session, (changed_same_version,))

    with get_session_factory()() as session:
        stored = session.execute(select(DetectionRuleVersion)).scalar_one()
        assert stored.definition["title"] == original.title
        assert stored.is_active is True


def test_concurrent_matches_create_one_active_incident(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """A server/rule/correlation advisory lock serializes concurrent incident updates."""

    _sync_rule("ssh_root_login_success")
    agent = register_agent()
    barrier = Barrier(2)
    base = datetime.now(UTC) - timedelta(seconds=1)

    def ingest(index: int) -> dict[str, Any]:
        event = _event(
            "linux.ssh.login_succeeded",
            base + timedelta(microseconds=index),
            actor="root",
        )
        barrier.wait(timeout=10)
        response = client.post(
            INGESTION_PATH,
            json=_batch([event]),
            headers=_headers(agent, f"concurrent-detection-{index}"),
        )
        assert response.status_code == 200
        return cast(dict[str, Any], response.json())

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(ingest, range(2)))

    assert sum(int(result["accepted"]) for result in results) == 2
    with get_session_factory()() as session:
        incident = session.execute(select(Incident)).scalar_one()
        assert incident.event_count == 2
        assert session.scalar(select(func.count()).select_from(Incident)) == 1
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 2


def test_threshold_history_is_read_after_correlation_lock_under_concurrency(
    client: TestClient,
    register_agent: AgentFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Six committed failures plus two concurrent failures produce one 8-event incident."""

    _sync_rule("ssh_bruteforce_by_ip")
    agent = register_agent()
    second_key_material = generate_agent_api_key()
    with get_session_factory().begin() as session:
        second_key = AgentApiKey(
            server_id=agent.server_id,
            public_id=second_key_material.public_id,
            secret_hash=second_key_material.secret_hash,
            label="threshold-concurrency-second-key",
        )
        session.add(second_key)
        session.flush()
        second_agent = RegisteredAgent(
            server_id=agent.server_id,
            key_id=second_key.id,
            public_id=second_key.public_id,
            token=second_key_material.token,
        )
    concurrent_agents = (agent, second_agent)
    base = datetime.now(UTC) - timedelta(seconds=3)
    initial_events = [
        _event(
            "linux.ssh.authentication_failed",
            base + timedelta(milliseconds=index),
        )
        for index in range(6)
    ]
    initial_response = client.post(
        INGESTION_PATH,
        json=_batch(initial_events),
        headers=_headers(agent, "threshold-concurrency-initial-six"),
    )
    assert initial_response.status_code == 200
    assert initial_response.json()["accepted"] == 6
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Incident)) == 0

    lock_barrier = Barrier(2)
    concurrent_occurred_at = base + timedelta(seconds=1)
    real_acquire_correlation_lock = detection_engine._acquire_correlation_lock

    def acquire_after_both_transactions_insert(
        session: Session,
        *,
        server_id: UUID,
        rule_version_id: UUID,
        correlation_hash: str,
    ) -> None:
        lock_barrier.wait(timeout=10)
        real_acquire_correlation_lock(
            session,
            server_id=server_id,
            rule_version_id=rule_version_id,
            correlation_hash=correlation_hash,
        )

    monkeypatch.setattr(
        detection_engine,
        "_acquire_correlation_lock",
        acquire_after_both_transactions_insert,
    )

    def ingest(index: int) -> dict[str, Any]:
        event = _event(
            "linux.ssh.authentication_failed",
            concurrent_occurred_at,
        )
        response = client.post(
            INGESTION_PATH,
            json=_batch([event]),
            headers=_headers(concurrent_agents[index], f"threshold-concurrency-{index}"),
        )
        assert response.status_code == 200
        return cast(dict[str, Any], response.json())

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(ingest, range(2)))

    assert sum(int(result["accepted"]) for result in results) == 2
    with get_session_factory()() as session:
        incident = session.execute(select(Incident)).scalar_one()
        evidence_event_ids = session.scalars(
            select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
        ).all()
        assert session.scalar(select(func.count()).select_from(Event)) == 8
        assert incident.event_count == 8
        assert len(evidence_event_ids) == 8
        assert len(set(evidence_event_ids)) == 8


@pytest.mark.parametrize(
    "failure_type",
    [DetectionEngineError, RuntimeError],
    ids=["declared-engine-error", "unexpected-engine-error"],
)
def test_detection_failure_rolls_back_event_incident_and_key_usage(
    client: TestClient,
    register_agent: AgentFactory,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[Exception],
) -> None:
    """A failure after incident flush rolls the complete ingestion transaction back."""

    _sync_rule("ssh_root_login_success")
    _create_destination()
    agent = register_agent()

    def detect_then_fail(session: Session, *, new_events: tuple[Event, ...]) -> NoReturn:
        detection_engine.run_detection(session, new_events=new_events)
        session.flush()
        raise failure_type("synthetic detection failure after flush")

    monkeypatch.setattr(events_route, "run_detection", detect_then_fail)
    response = client.post(
        INGESTION_PATH,
        json=_batch(
            [
                _event(
                    "linux.ssh.login_succeeded",
                    datetime.now(UTC) - timedelta(seconds=1),
                    actor="root",
                )
            ]
        ),
        headers=_headers(agent, "detection-rollback"),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "event ingestion unavailable"
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 0
        assert session.scalar(select(func.count()).select_from(Incident)) == 0
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 0
        assert session.scalar(select(func.count()).select_from(IncidentHistoryEntry)) == 0
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0
        key = session.get(AgentApiKey, agent.key_id)
        assert key is not None
        assert key.last_used_at is None
