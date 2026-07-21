"""PostgreSQL integration tests for the version 1 event ingestion API."""

import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from tests.integration.conftest import AgentFactory, RegisteredAgent
from woland_guard_contracts import NormalizedEventV1
from woland_guard_control_plane import cli
from woland_guard_control_plane.api.routes import events as events_route
from woland_guard_control_plane.application.agent_keys import generate_agent_api_key
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.event_repository import insert_event_batch
from woland_guard_control_plane.infrastructure.database.models import AgentApiKey, Event
from woland_guard_control_plane.main import create_app

pytestmark = pytest.mark.integration

INGESTION_PATH = "/api/v1/events"


def test_successful_authentication_persists_event_and_updates_last_used(
    client: TestClient,
    register_agent: AgentFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A valid key derives server_id, commits the event, and records successful use."""

    agent = register_agent()
    request_id = "integration-success"
    caplog.set_level(logging.INFO)

    response = client.post(
        INGESTION_PATH,
        json=make_batch(),
        headers=auth_headers(agent, request_id=request_id),
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id
    assert response.json()["request_id"] == request_id
    assert response.json()["accepted"] == 1
    assert response.json()["existing"] == 0
    assert f"request_id={request_id}" in caplog.text

    with get_session_factory()() as session:
        stored_event = session.execute(select(Event)).scalar_one()
        stored_key = session.get(AgentApiKey, agent.key_id)
        assert stored_event.server_id == agent.server_id
        assert stored_key is not None
        assert stored_key.last_used_at is not None


def test_wrong_secret_gets_same_safe_response_and_does_not_update_last_used(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """A wrong secret is indistinguishable from an unknown public identifier."""

    agent = register_agent()
    token_prefix, _secret = agent.token.split(".", maxsplit=1)
    fixed_request_id = "invalid-credentials"
    wrong_response = client.post(
        INGESTION_PATH,
        json=make_batch(),
        headers={
            "Authorization": f"Bearer {token_prefix}.wrong-secret",
            "X-Request-ID": fixed_request_id,
        },
    )
    unknown_material = generate_agent_api_key()
    unknown_response = client.post(
        INGESTION_PATH,
        json=make_batch(),
        headers={
            "Authorization": f"Bearer {unknown_material.token}",
            "X-Request-ID": fixed_request_id,
        },
    )

    assert wrong_response.status_code == 401
    assert unknown_response.status_code == 401
    assert wrong_response.json() == unknown_response.json()
    assert wrong_response.json() == {
        "detail": "invalid agent credentials",
        "request_id": fixed_request_id,
    }
    with get_session_factory()() as session:
        stored_key = session.get(AgentApiKey, agent.key_id)
        assert stored_key is not None
        assert stored_key.last_used_at is None


def test_unknown_public_id_is_rejected(client: TestClient) -> None:
    """A structurally valid token without a database key gets a safe 401."""

    material = generate_agent_api_key()

    response = client.post(
        INGESTION_PATH,
        json=make_batch(),
        headers={"Authorization": f"Bearer {material.token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid agent credentials"


def test_revoked_key_is_rejected(client: TestClient, register_agent: AgentFactory) -> None:
    """A revoked key cannot ingest events even with the correct secret."""

    agent = register_agent(revoked_at=datetime.now(UTC))

    response = client.post(INGESTION_PATH, json=make_batch(), headers=auth_headers(agent))

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid agent credentials"


def test_expired_key_is_rejected(client: TestClient, register_agent: AgentFactory) -> None:
    """An expired key cannot ingest events."""

    agent = register_agent(expires_at=datetime.now(UTC) - timedelta(seconds=1))

    response = client.post(INGESTION_PATH, json=make_batch(), headers=auth_headers(agent))

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid agent credentials"


def test_inactive_server_is_rejected(client: TestClient, register_agent: AgentFactory) -> None:
    """A valid key cannot bypass the owning server's inactive state."""

    agent = register_agent(is_active=False)

    response = client.post(INGESTION_PATH, json=make_batch(), headers=auth_headers(agent))

    assert response.status_code == 403
    assert response.json()["detail"] == "server is inactive"


def test_malformed_authorization_header_is_rejected(client: TestClient) -> None:
    """Only one strict Bearer token is accepted."""

    response = client.post(
        INGESTION_PATH,
        json=make_batch(),
        headers={"Authorization": "Basic malformed"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid agent credentials"


def test_wrong_content_type_is_rejected_before_json_parsing(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """The ingestion endpoint accepts only application/json."""

    agent = register_agent()
    headers = auth_headers(agent)
    headers["Content-Type"] = "text/plain"

    response = client.post(INGESTION_PATH, content=json.dumps(make_batch()), headers=headers)

    assert response.status_code == 415
    assert response.json()["detail"] == "Content-Type must be application/json"


def test_body_size_limit_runs_before_json_parsing(
    integration_settings: Settings,
    register_agent: AgentFactory,
) -> None:
    """A declared and actual body above the configured bound receives 413."""

    agent = register_agent()
    small_settings = integration_settings.model_copy(update={"ingest_max_body_bytes": 64})
    with TestClient(create_app(small_settings)) as small_client:
        response = small_client.post(
            INGESTION_PATH,
            content=json.dumps(make_batch()),
            headers={**auth_headers(agent), "Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "request body is too large"


def test_empty_batch_is_rejected(client: TestClient, register_agent: AgentFactory) -> None:
    """EventBatchV1 requires at least one event."""

    agent = register_agent()

    response = client.post(
        INGESTION_PATH,
        json=make_batch(events=[]),
        headers=auth_headers(agent),
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "request validation failed"


def test_batch_over_one_hundred_events_is_rejected(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """The version 1 contract caps a request at 100 events."""

    agent = register_agent()
    events = [make_event() for _ in range(101)]

    response = client.post(
        INGESTION_PATH,
        json=make_batch(events=events),
        headers=auth_headers(agent),
    )

    assert response.status_code == 422


def test_duplicate_event_id_inside_batch_is_rejected(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """Duplicate IDs inside one input contract never reach PostgreSQL."""

    agent = register_agent()
    event = make_event()

    response = client.post(
        INGESTION_PATH,
        json=make_batch(events=[event, event]),
        headers=auth_headers(agent),
    )

    assert response.status_code == 422


@pytest.mark.parametrize("nul_location", ["actor", "summary", "nested_value", "nested_key"])
def test_nul_text_is_rejected_before_postgresql(
    nul_location: str,
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """Contract validation rejects every NUL location without executing a SQL statement."""

    agent = register_agent()
    event_payload = make_event()
    if nul_location == "actor":
        event_payload["actor"] = "synthetic\x00actor"
    elif nul_location == "summary":
        event_payload["summary"] = "synthetic\x00summary"
    elif nul_location == "nested_value":
        event_payload["attributes"] = {"outer": [{"inner": "synthetic\x00value"}]}
    else:
        event_payload["attributes"] = {"outer": {"inner\x00key": "synthetic"}}

    executed_statements: list[str] = []

    def record_statement(*_args: object, **_kwargs: object) -> None:
        executed_statements.append("executed")

    engine = get_engine()
    sqlalchemy_event.listen(engine, "before_cursor_execute", record_statement)
    try:
        response = client.post(
            INGESTION_PATH,
            json=make_batch(events=[event_payload]),
            headers=auth_headers(agent),
        )
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", record_statement)

    assert response.status_code == 422
    assert response.json()["detail"] == "request validation failed"
    assert "synthetic" not in response.text
    assert executed_statements == []
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 0
        stored_key = session.get(AgentApiKey, agent.key_id)
        assert stored_key is not None
        assert stored_key.last_used_at is None


def test_event_retried_in_next_request_is_reported_as_existing(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """ON CONFLICT makes a later delivery idempotent for the same server."""

    agent = register_agent()
    batch = make_batch()

    first = client.post(INGESTION_PATH, json=batch, headers=auth_headers(agent))
    second = client.post(INGESTION_PATH, json=batch, headers=auth_headers(agent))

    assert first.status_code == 200
    assert first.json()["accepted"] == 1
    assert first.json()["existing"] == 0
    assert second.status_code == 200
    assert second.json()["accepted"] == 0
    assert second.json()["existing"] == 1


def test_parallel_delivery_of_same_event_inserts_one_row(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """The PostgreSQL uniqueness constraint resolves concurrent identical deliveries."""

    agent = register_agent()
    event = make_event()
    barrier = Barrier(2)

    def send_request(index: int) -> dict[str, Any]:
        barrier.wait(timeout=10)
        response = client.post(
            INGESTION_PATH,
            json=make_batch(events=[event]),
            headers=auth_headers(agent, request_id=f"parallel-{index}"),
        )
        assert response.status_code == 200
        return cast(dict[str, Any], response.json())

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(send_request, range(2)))

    assert sum(int(result["accepted"]) for result in results) == 1
    assert sum(int(result["existing"]) for result in results) == 1
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 1


def test_unexpected_database_error_rolls_back_whole_batch(
    client: TestClient,
    register_agent: AgentFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure after a partial flush rolls back events and last_used_at together."""

    agent = register_agent()
    batch = make_batch(events=[make_event(), make_event()])

    def partially_insert_then_fail(
        session: Session,
        *,
        server_id: UUID,
        events: tuple[NormalizedEventV1, ...],
        persisted_at: datetime,
    ) -> int:
        insert_event_batch(
            session,
            server_id=server_id,
            events=events[:1],
            persisted_at=persisted_at,
        )
        raise SQLAlchemyError("synthetic integration database error")

    monkeypatch.setattr(events_route, "insert_event_batch", partially_insert_then_fail)

    response = client.post(INGESTION_PATH, json=batch, headers=auth_headers(agent))

    assert response.status_code == 503
    assert response.json()["detail"] == "event ingestion unavailable"
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 0
        stored_key = session.get(AgentApiKey, agent.key_id)
        assert stored_key is not None
        assert stored_key.last_used_at is None


def test_plaintext_secret_is_absent_from_logs_and_responses(
    client: TestClient,
    register_agent: AgentFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Request logging and safe errors never echo the bearer credential."""

    agent = register_agent()
    token_prefix, secret = agent.token.split(".", maxsplit=1)
    presented_token = f"{token_prefix}.{secret}changed"
    caplog.set_level(logging.INFO)

    response = client.post(
        INGESTION_PATH,
        json=make_batch(),
        headers={"Authorization": f"Bearer {presented_token}"},
    )

    combined_output = caplog.text + response.text
    assert response.status_code == 401
    assert presented_token not in combined_output
    assert secret not in combined_output


def test_rate_limit_is_configurable_per_authenticated_key(
    integration_settings: Settings,
    register_agent: AgentFactory,
) -> None:
    """The configured request count is enforced independently for an agent key."""

    agent = register_agent()
    limited_settings = integration_settings.model_copy(
        update={"ingest_rate_limit_requests": 1, "ingest_rate_limit_window_seconds": 60}
    )
    with TestClient(create_app(limited_settings)) as limited_client:
        first = limited_client.post(
            INGESTION_PATH,
            json=make_batch(),
            headers=auth_headers(agent),
        )
        second = limited_client.post(
            INGESTION_PATH,
            json=make_batch(),
            headers=auth_headers(agent),
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) >= 1


def test_clock_skew_rejection_consumes_authenticated_rate_limit(
    integration_settings: Settings,
    register_agent: AgentFactory,
) -> None:
    """A request counts immediately after auth even when clock skew later rejects it."""

    agent = register_agent()
    limited_settings = integration_settings.model_copy(
        update={"ingest_rate_limit_requests": 1, "ingest_rate_limit_window_seconds": 60}
    )
    with TestClient(create_app(limited_settings)) as limited_client:
        invalid_clock = limited_client.post(
            INGESTION_PATH,
            json=make_batch(sent_at=datetime.now(UTC) - timedelta(seconds=301)),
            headers=auth_headers(agent),
        )
        next_valid = limited_client.post(
            INGESTION_PATH,
            json=make_batch(),
            headers=auth_headers(agent),
        )

    assert invalid_clock.status_code == 422
    assert next_valid.status_code == 429
    assert int(next_valid.headers["Retry-After"]) >= 1


def test_sent_at_outside_clock_skew_is_rejected(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """An authenticated batch outside the configured clock skew is not persisted."""

    agent = register_agent()
    stale_sent_at = datetime.now(UTC) - timedelta(seconds=301)

    response = client.post(
        INGESTION_PATH,
        json=make_batch(sent_at=stale_sent_at),
        headers=auth_headers(agent),
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "sent_at is outside allowed clock skew"
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 0


def test_future_event_timestamp_is_rejected_without_updating_last_used(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """A current batch cannot contain an event collected far in the future."""

    agent = register_agent()
    future_timestamp = datetime.now(UTC) + timedelta(days=1)
    future_event = make_event(
        occurred_at=future_timestamp,
        collected_at=future_timestamp,
    )

    response = client.post(
        INGESTION_PATH,
        json=make_batch(events=[future_event], sent_at=datetime.now(UTC)),
        headers=auth_headers(agent),
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "event collected_at is outside allowed clock skew"
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(Event)) == 0
        stored_key = session.get(AgentApiKey, agent.key_id)
        assert stored_key is not None
        assert stored_key.last_used_at is None


def test_old_event_is_accepted_when_batch_sent_at_is_current(
    client: TestClient,
    register_agent: AgentFactory,
) -> None:
    """Offline queue delivery remains valid because events have no lower time bound."""

    agent = register_agent()
    old_timestamp = datetime.now(UTC) - timedelta(days=30)
    old_event = make_event(occurred_at=old_timestamp, collected_at=old_timestamp)

    response = client.post(
        INGESTION_PATH,
        json=make_batch(events=[old_event], sent_at=datetime.now(UTC)),
        headers=auth_headers(agent),
    )

    assert response.status_code == 200
    assert response.json()["accepted"] == 1


def test_local_cli_creates_server_and_reveals_unstored_token_once(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The local CLI prints a new token while PostgreSQL stores only its digest."""

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "woland-guard-admin",
            "create-test-agent",
            "--name",
            "cli-integration-server",
            "--hostname",
            "cli-integration.invalid",
            "--label",
            "cli-integration",
        ],
    )

    cli.main()

    output_lines = capsys.readouterr().out.splitlines()
    token_lines = [line for line in output_lines if line.startswith("token=")]
    assert len(token_lines) == 1
    issued_token = token_lines[0].removeprefix("token=")
    assert issued_token.startswith("wgak_")

    with get_session_factory()() as session:
        stored_key = session.execute(select(AgentApiKey)).scalar_one()
        assert stored_key.public_id in issued_token
        assert "token" not in AgentApiKey.__table__.columns
        assert "secret" not in AgentApiKey.__table__.columns


def make_event(
    *,
    event_id: UUID | None = None,
    occurred_at: datetime | None = None,
    collected_at: datetime | None = None,
) -> dict[str, Any]:
    """Create one synthetic journald event without real infrastructure data."""

    event_occurred_at = occurred_at or datetime.now(UTC)
    event_collected_at = collected_at or event_occurred_at
    return {
        "schema_version": 1,
        "event_id": str(event_id or uuid4()),
        "occurred_at": event_occurred_at.isoformat(),
        "collected_at": event_collected_at.isoformat(),
        "source": "journald",
        "event_type": "ssh.authentication_failed",
        "actor": "synthetic-agent",
        "source_ip": "192.0.2.10",
        "summary": "synthetic integration event",
        "attributes": {"attempt": 1},
    }


def make_batch(
    *,
    events: list[dict[str, Any]] | None = None,
    sent_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a versioned synthetic delivery batch."""

    return {
        "schema_version": 1,
        "batch_id": str(uuid4()),
        "sent_at": (sent_at or datetime.now(UTC)).isoformat(),
        "events": events if events is not None else [make_event()],
    }


def auth_headers(agent: RegisteredAgent, *, request_id: str | None = None) -> dict[str, str]:
    """Build request headers without logging or persisting the bearer token."""

    headers = {"Authorization": f"Bearer {agent.token}"}
    if request_id is not None:
        headers["X-Request-ID"] = request_id
    return headers
