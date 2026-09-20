"""Unit tests for safe existing-server agent-key lifecycle operations."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.agent_key_management import (
    AgentKeyManagementError,
    issue_agent_api_key,
    revoke_agent_api_key,
)
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    AuditLogEntry,
    Server,
)


def test_issue_returns_secret_once_and_persists_only_digest_and_safe_audit() -> None:
    session = Mock(spec=Session)
    server = _server()
    session.get.return_value = server
    key_id = uuid4()

    def assign_key_id(instance: object) -> None:
        if isinstance(instance, AgentApiKey):
            instance.id = key_id

    session.add.side_effect = assign_key_id
    now = datetime(2026, 9, 20, 18, 0, tzinfo=UTC)

    issued = issue_agent_api_key(
        session,
        server_selector=str(server.id),
        label=" canary rotation ",
        now=now,
    )

    assert issued.server_id == server.id
    assert issued.key_id == key_id
    assert issued.label == "canary rotation"
    assert issued.created_at == now
    assert issued.token.startswith(f"wgak_{issued.public_id}.")
    assert issued.token not in repr(issued)
    added = [call.args[0] for call in session.add.call_args_list]
    stored_key = next(item for item in added if isinstance(item, AgentApiKey))
    audit = next(item for item in added if isinstance(item, AuditLogEntry))
    assert stored_key.server_id == server.id
    assert stored_key.public_id == issued.public_id
    assert len(stored_key.secret_hash) == 32
    assert stored_key.secret_hash != issued.token.split(".", maxsplit=1)[1].encode()
    assert audit.action == "agent_api_key.issued"
    assert audit.target_type == "agent_api_key"
    assert audit.target_id == key_id
    assert audit.details == {"server_id": str(server.id)}
    assert issued.token not in str(audit.details)


def test_issue_resolves_exact_server_name_and_rejects_inactive_server() -> None:
    active_session = Mock(spec=Session)
    active_server = _server()
    active_session.scalar.return_value = active_server
    active_session.add.side_effect = lambda instance: setattr(instance, "id", uuid4())

    issued = issue_agent_api_key(
        active_session,
        server_selector=active_server.name,
        now=datetime(2026, 9, 20, 18, 0, tzinfo=UTC),
    )

    assert issued.server_id == active_server.id

    inactive_session = Mock(spec=Session)
    inactive_session.scalar.return_value = _server(is_active=False)
    with pytest.raises(AgentKeyManagementError, match="server is inactive"):
        issue_agent_api_key(
            inactive_session,
            server_selector="inactive-server",
            now=datetime(2026, 9, 20, 18, 0, tzinfo=UTC),
        )
    inactive_session.add.assert_not_called()


def test_revoke_is_idempotent_and_keeps_original_timestamp() -> None:
    server_id = uuid4()
    created_at = datetime(2026, 9, 20, 17, 0, tzinfo=UTC)
    first_revoke_at = datetime(2026, 9, 20, 18, 0, tzinfo=UTC)
    key = _key(server_id=server_id, created_at=created_at)
    session = Mock(spec=Session)
    session.scalar.return_value = key

    first = revoke_agent_api_key(session, public_id=key.public_id, now=first_revoke_at)

    assert first.changed
    assert first.server_id == server_id
    assert first.key_id == key.id
    assert first.revoked_at == first_revoke_at
    audit = session.add.call_args.args[0]
    assert isinstance(audit, AuditLogEntry)
    assert audit.action == "agent_api_key.revoked"
    assert audit.details == {"server_id": str(server_id)}

    session.reset_mock()
    session.scalar.return_value = key
    second = revoke_agent_api_key(
        session,
        public_id=key.public_id,
        now=first_revoke_at + timedelta(hours=1),
    )

    assert not second.changed
    assert second.revoked_at == first_revoke_at
    session.add.assert_not_called()
    session.flush.assert_not_called()


@pytest.mark.parametrize("public_id", ["missing_public_id", "", "contains.dot", "x" * 33])
def test_unknown_or_invalid_public_id_does_not_mutate_any_key(public_id: str) -> None:
    session = Mock(spec=Session)
    session.scalar.return_value = None

    with pytest.raises(AgentKeyManagementError, match="agent API key does not exist"):
        revoke_agent_api_key(session, public_id=public_id)

    session.add.assert_not_called()
    session.flush.assert_not_called()


def test_issue_rejects_unknown_server_without_creating_key_or_audit() -> None:
    session = Mock(spec=Session)
    session.get.return_value = None
    session.scalar.return_value = None

    with pytest.raises(AgentKeyManagementError, match="server does not exist"):
        issue_agent_api_key(session, server_selector=str(UUID(int=7)))

    session.add.assert_not_called()
    session.flush.assert_not_called()


def _server(*, is_active: bool = True) -> Server:
    return Server(
        id=uuid4(),
        name="existing-server",
        hostname="existing-server.invalid",
        is_active=is_active,
    )


def _key(*, server_id: UUID, created_at: datetime) -> AgentApiKey:
    return AgentApiKey(
        id=uuid4(),
        server_id=server_id,
        public_id="synthetic_public",
        secret_hash=bytes(32),
        label="old-key",
        created_at=created_at,
    )
