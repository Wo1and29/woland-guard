"""PostgreSQL integration coverage for existing-server agent-key lifecycle."""

import sys
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests.integration.conftest import AgentFactory
from woland_guard_control_plane import cli
from woland_guard_control_plane.application.agent_key_management import (
    AgentKeyManagementError,
    issue_agent_api_key,
    revoke_agent_api_key,
)
from woland_guard_control_plane.application.authentication import authenticate_agent
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    AuditLogEntry,
    Event,
    Server,
)

pytestmark = pytest.mark.integration

_INGESTION_PATH = "/api/v1/events"


def test_cli_issues_overlapping_key_then_safely_revokes_old_key(
    client: TestClient,
    register_agent: AgentFactory,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original = register_agent()
    with get_session_factory()() as session:
        server = session.get(Server, original.server_id)
        assert server is not None
        server_name = server.name

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "woland-guard-admin",
            "issue-agent-key",
            "--server",
            server_name,
            "--label",
            "day-5-rotation",
        ],
    )
    cli.main()
    issued_output = capsys.readouterr()
    issued = _output_map(issued_output.out)
    replacement_key_id = UUID(issued["key_id"])
    replacement_token = issued["token"]
    assert issued["server_id"] == str(original.server_id)
    assert issued["label"] == "day-5-rotation"
    assert datetime.fromisoformat(issued["created_at"]).tzinfo is not None
    assert issued_output.out.count(replacement_token) == 1
    assert "secret_hash" not in issued_output.out

    original_response = client.post(
        _INGESTION_PATH,
        json=_batch(),
        headers=_headers(original.token, "old-before-revoke"),
    )
    replacement_response = client.post(
        _INGESTION_PATH,
        json=_batch(),
        headers=_headers(replacement_token, "new-before-revoke"),
    )
    assert original_response.status_code == 200
    assert replacement_response.status_code == 200

    with get_session_factory()() as session:
        keys = session.scalars(
            select(AgentApiKey)
            .where(AgentApiKey.server_id == original.server_id)
            .order_by(AgentApiKey.created_at, AgentApiKey.id)
        ).all()
        assert len(keys) == 2
        assert {key.id for key in keys} == {original.key_id, replacement_key_id}
        assert all(key.server_id == original.server_id for key in keys)
        replacement = next(key for key in keys if key.id == replacement_key_id)
        assert replacement.label == "day-5-rotation"
        assert replacement.last_used_at is not None
        assert replacement.revoked_at is None
        assert "token" not in AgentApiKey.__table__.columns
        assert "secret" not in AgentApiKey.__table__.columns
        replacement_secret = replacement_token.split(".", maxsplit=1)[1].encode()
        assert replacement.secret_hash != replacement_secret
        event_ids_before_revoke = set(session.scalars(select(Event.id)).all())
        assert len(event_ids_before_revoke) == 2

    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "revoke-agent-key", original.public_id],
    )
    cli.main()
    first_revoke = _output_map(capsys.readouterr().out)
    assert first_revoke["server_id"] == str(original.server_id)
    assert first_revoke["key_id"] == str(original.key_id)
    assert first_revoke["public_id"] == original.public_id
    assert first_revoke["revoked"] == "true"

    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "revoke-agent-key", original.public_id],
    )
    cli.main()
    second_revoke_output = capsys.readouterr().out
    assert _output_map(second_revoke_output)["revoked"] == "already"
    assert "token=" not in second_revoke_output
    assert "secret_hash" not in second_revoke_output

    with get_session_factory()() as session:
        assert set(session.scalars(select(Event.id)).all()) == event_ids_before_revoke

    rejected = client.post(
        _INGESTION_PATH,
        json=_batch(),
        headers=_headers(original.token, "old-after-revoke"),
    )
    accepted = client.post(
        _INGESTION_PATH,
        json=_batch(),
        headers=_headers(replacement_token, "new-after-revoke"),
    )
    assert rejected.status_code == 401
    assert rejected.json()["detail"] == "invalid agent credentials"
    assert accepted.status_code == 200

    with get_session_factory()() as session:
        stored_original = session.get(AgentApiKey, original.key_id)
        stored_replacement = session.get(AgentApiKey, replacement_key_id)
        assert stored_original is not None
        assert stored_replacement is not None
        assert stored_original.revoked_at is not None
        assert stored_replacement.revoked_at is None
        assert stored_replacement.server_id == original.server_id
        audit_entries = session.scalars(
            select(AuditLogEntry).order_by(AuditLogEntry.created_at, AuditLogEntry.id)
        ).all()
        assert [entry.action for entry in audit_entries] == [
            "agent_api_key.issued",
            "agent_api_key.revoked",
        ]
        assert [entry.target_id for entry in audit_entries] == [
            replacement_key_id,
            original.key_id,
        ]
        assert all(
            entry.details == {"server_id": str(original.server_id)} for entry in audit_entries
        )
        serialized_audit = " ".join(str(entry.details) for entry in audit_entries)
        assert original.token not in serialized_audit
        assert replacement_token not in serialized_audit
        assert all(entry.actor_type == "local_cli" for entry in audit_entries)


def test_issue_accepts_existing_server_uuid(register_agent: AgentFactory) -> None:
    original = register_agent()

    with get_session_factory().begin() as session:
        issued = issue_agent_api_key(
            session,
            server_selector=str(original.server_id),
            label="uuid-selector",
        )

    assert issued.server_id == original.server_id
    assert "token=" not in repr(issued)
    assert issued.token not in repr(issued)
    with get_session_factory()() as session:
        authenticated = authenticate_agent(session, issued.token, now=datetime.now(UTC))
        assert authenticated.server_id == original.server_id


def test_unknown_server_or_key_does_not_change_other_servers(
    register_agent: AgentFactory,
) -> None:
    first = register_agent()
    second = register_agent()

    with pytest.raises(AgentKeyManagementError):
        with get_session_factory().begin() as session:
            issue_agent_api_key(session, server_selector="missing-server")
    with pytest.raises(AgentKeyManagementError):
        with get_session_factory().begin() as session:
            revoke_agent_api_key(session, public_id="missing_public_id")

    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(AgentApiKey)) == 2
        assert session.scalar(select(func.count()).select_from(AuditLogEntry)) == 0
        first_auth = authenticate_agent(session, first.token, now=datetime.now(UTC))
        second_auth = authenticate_agent(session, second.token, now=datetime.now(UTC))
        assert first_auth.server_id == first.server_id
        assert second_auth.server_id == second.server_id


def _output_map(output: str) -> dict[str, str]:
    return dict(line.split("=", maxsplit=1) for line in output.splitlines() if "=" in line)


def _headers(token: str, request_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Request-ID": request_id}


def _batch() -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "schema_version": 1,
        "batch_id": str(uuid4()),
        "sent_at": now.isoformat(),
        "events": [
            {
                "schema_version": 1,
                "event_id": str(uuid4()),
                "occurred_at": now.isoformat(),
                "collected_at": now.isoformat(),
                "source": "journald",
                "event_type": "linux.ssh.authentication_failed",
                "actor": "synthetic-agent",
                "source_ip": "192.0.2.10",
                "summary": "Synthetic lifecycle event",
                "attributes": {"authentication_method": "publickey"},
            }
        ],
    }
