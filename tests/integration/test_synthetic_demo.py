"""PostgreSQL and real ASGI ingestion regressions for the 8A demo catalog."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests.integration.conftest import AgentFactory
from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.application.detection.sync import sync_rules
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.demo.client import (
    DemoApiCredential,
    DemoIngestionClient,
    DemoOrigin,
)
from woland_guard_control_plane.demo.contracts import DemoManifestError
from woland_guard_control_plane.demo.scenarios import (
    EXPECTED_RULE_KEYS,
    build_manifest,
    list_scenarios,
)
from woland_guard_control_plane.infrastructure.database.models import (
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

RULES_DIR = Path(__file__).parents[2] / "detection-rules"
ORIGIN = DemoOrigin.parse("http://localhost:8000")
RUN_ID = UUID("55555555-5555-4555-8555-555555555555")


def _prepare_environment() -> None:
    rules = load_rules_directory(RULES_DIR)
    assert len(rules) == 10
    assert {rule.rule_key for rule in rules} == EXPECTED_RULE_KEYS
    unique = uuid4()
    with get_session_factory().begin() as session:
        assert sync_rules(session, rules) == 10
        destination = NotificationDestination(
            adapter_kind="telegram",
            enabled=False,
            minimum_severity="low",
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
    with get_session_factory()() as session:
        active = set(
            session.scalars(
                select(DetectionRuleVersion.rule_key).where(
                    DetectionRuleVersion.is_active.is_(True)
                )
            )
        )
    assert active == EXPECTED_RULE_KEYS


def _demo_client(client: TestClient, token: str, anchor: datetime) -> DemoIngestionClient:
    return DemoIngestionClient(
        origin=ORIGIN,
        credential=DemoApiCredential(token),
        now_function=lambda: anchor,
        sleep_function=lambda _seconds: None,
        _test_client=cast(Any, client),
    )


@pytest.mark.parametrize("definition", list_scenarios(), ids=lambda item: item.scenario_id)
def test_each_manifest_uses_ingestion_and_creates_the_full_exact_expected_set(
    definition: Any,
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    _prepare_environment()
    agent = register_agent()
    anchor = datetime.now(UTC).replace(microsecond=0)
    manifest = build_manifest(definition.scenario_id, run_id=RUN_ID, anchor_utc=anchor)

    summary = _demo_client(client, agent.token, anchor).send(manifest)

    assert summary.accepted == len(manifest.events)
    assert summary.duplicates == 0
    expected = manifest.expected_outcomes
    expected_keys = tuple(item.rule_key for item in expected.incidents)
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == len(manifest.events)
        incidents = tuple(session.scalars(select(Incident).order_by(Incident.rule_key)))
        assert tuple(incident.rule_key for incident in incidents) == expected_keys
        assert len(incidents) == expected.new_incident_count
        expected_by_key = {item.rule_key: item for item in expected.incidents}
        for incident in incidents:
            outcome = expected_by_key[incident.rule_key]
            assert incident.status == outcome.initial_status
            assert incident.severity == outcome.severity.value
            assert incident.title == outcome.title
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == (
            expected.evidence_link_count
        )
        assert session.scalar(select(func.count()).select_from(IncidentHistoryEntry)) == (
            expected.new_incident_count
        )
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == (
            expected.outbox_count_delta
        )


def test_replaying_complete_manifest_does_not_duplicate_any_persistence(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    _prepare_environment()
    agent = register_agent()
    anchor = datetime.now(UTC).replace(microsecond=0)
    manifest = build_manifest(
        "ssh_bruteforce_by_ip.positive.v1",
        run_id=RUN_ID,
        anchor_utc=anchor,
    )
    demo_client = _demo_client(client, agent.token, anchor)

    first = demo_client.send(manifest)
    second = demo_client.send(manifest)

    assert first.accepted == 8
    assert first.duplicates == 0
    assert second.accepted == 0
    assert second.duplicates == 8
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 8
        assert session.scalar(select(func.count()).select_from(Incident)) == 1
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 8
        assert session.scalar(select(func.count()).select_from(IncidentHistoryEntry)) == 1
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 1


def test_transport_uncertainty_retries_same_request_without_duplicate_rows(
    client: TestClient,
    register_agent: AgentFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _prepare_environment()
    agent = register_agent()
    anchor = datetime.now(UTC).replace(microsecond=0)
    manifest = build_manifest(
        "user_account_created.positive.v1",
        run_id=RUN_ID,
        anchor_utc=anchor,
    )
    uncertain = _UncertainClient(client)
    caplog.set_level(logging.INFO)
    demo_client = DemoIngestionClient(
        origin=ORIGIN,
        credential=DemoApiCredential(agent.token),
        now_function=lambda: anchor,
        sleep_function=lambda _seconds: None,
        _test_client=uncertain,
    )

    summary = demo_client.send(manifest)

    assert summary.accepted == 0
    assert summary.duplicates == 1
    assert uncertain.requests[0] == uncertain.requests[1]
    assert "transport-canary" not in caplog.text
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 1
        assert session.scalar(select(func.count()).select_from(Incident)) == 1
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 1
        assert session.scalar(select(func.count()).select_from(IncidentHistoryEntry)) == 1
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 1


@pytest.mark.parametrize("mutation", ["expected_outcome", "event"], ids=str)
def test_catalog_mutation_is_rejected_before_ingestion_and_persistence(
    mutation: str,
    client: TestClient,
    register_agent: AgentFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _prepare_environment()
    agent = register_agent()
    anchor = datetime.now(UTC).replace(microsecond=0)
    manifest = build_manifest(
        "ssh_bruteforce_by_ip.positive.v1",
        run_id=RUN_ID,
        anchor_utc=anchor,
    )
    canary = f"integration-catalog-{mutation}-canary"
    if mutation == "expected_outcome":
        incident = manifest.expected_outcomes.incidents[0].model_copy(update={"title": canary})
        outcomes = manifest.expected_outcomes.model_copy(update={"incidents": (incident,)})
        mutated = manifest.model_copy(update={"expected_outcomes": outcomes})
    else:
        event = manifest.events[0].model_copy(update={"summary": canary})
        mutated = manifest.model_copy(update={"events": (event, *manifest.events[1:])})
    transport = _CountingClient(client)
    demo_client = DemoIngestionClient(
        origin=ORIGIN,
        credential=DemoApiCredential(agent.token),
        now_function=lambda: anchor,
        sleep_function=lambda _seconds: None,
        _test_client=transport,
    )
    caplog.set_level(logging.INFO)

    with pytest.raises(DemoManifestError, match="catalog validation") as captured:
        demo_client.send(mutated)

    assert transport.request_count == 0
    assert canary not in str(captured.value)
    assert canary not in caplog.text
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 0
        assert session.scalar(select(func.count()).select_from(Incident)) == 0
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 0
        assert session.scalar(select(func.count()).select_from(IncidentHistoryEntry)) == 0
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0


def test_all_scenarios_on_one_server_remain_cross_rule_isolated(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    _prepare_environment()
    agent = register_agent()
    anchor = datetime.now(UTC).replace(microsecond=0)
    manifests = tuple(
        build_manifest(definition.scenario_id, run_id=RUN_ID, anchor_utc=anchor)
        for definition in list_scenarios()
    )
    demo_client = _demo_client(client, agent.token, anchor)

    summaries = tuple(demo_client.send(manifest) for manifest in manifests)

    expected_rule_counts = Counter(
        incident.rule_key
        for manifest in manifests
        for incident in manifest.expected_outcomes.incidents
    )
    with get_session_factory()() as session:
        actual_rule_counts = Counter(session.scalars(select(Incident.rule_key)))
        assert actual_rule_counts == expected_rule_counts
        assert session.scalar(select(func.count()).select_from(Event)) == sum(
            len(manifest.events) for manifest in manifests
        )
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == sum(
            manifest.expected_outcomes.evidence_link_count for manifest in manifests
        )
        assert session.scalar(select(func.count()).select_from(IncidentHistoryEntry)) == 16
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 16
    assert sum(summary.accepted for summary in summaries) == sum(
        len(manifest.events) for manifest in manifests
    )


class _UncertainClient:
    """Commit one request, then emulate loss of its HTTP response exactly once."""

    def __init__(self, client: TestClient) -> None:
        self._client = client
        self._uncertain = True
        self.requests: list[bytes] = []

    @contextmanager
    def stream(self, method: str, url: str, **kwargs: Any) -> Iterator[Any]:
        body = cast(bytes, kwargs["content"])
        self.requests.append(body)
        if self._uncertain:
            self._uncertain = False
            response = self._client.request(method, url, **kwargs)
            assert response.status_code == 200
            request = httpx2.Request(method, url)
            raise httpx2.ReadError("transport-canary", request=request)
        with self._client.stream(method, url, **kwargs) as response:
            yield response

    def close(self) -> None:
        return None


class _CountingClient:
    def __init__(self, client: TestClient) -> None:
        self._client = client
        self.request_count = 0

    @contextmanager
    def stream(self, method: str, url: str, **kwargs: Any) -> Iterator[Any]:
        self.request_count += 1
        with self._client.stream(method, url, **kwargs) as response:
            yield response

    def close(self) -> None:
        return None
