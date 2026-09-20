"""Audited local lifecycle operations for existing-server agent credentials."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.agent_keys import generate_agent_api_key
from woland_guard_control_plane.application.audit import record_local_cli_action
from woland_guard_control_plane.infrastructure.database.models import AgentApiKey, Server

_PUBLIC_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class AgentKeyManagementError(ValueError):
    """A safe validation or lifecycle error for local agent-key management."""


@dataclass(frozen=True, slots=True)
class IssuedAgentApiKey:
    """Public metadata plus plaintext material returned exactly once."""

    server_id: UUID
    key_id: UUID
    public_id: str
    label: str | None
    created_at: datetime
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RevokedAgentApiKey:
    """Safe result of a first or repeated revocation request."""

    server_id: UUID
    key_id: UUID
    public_id: str
    revoked_at: datetime
    changed: bool


def issue_agent_api_key(
    session: Session,
    *,
    server_selector: str,
    label: str | None = None,
    now: datetime | None = None,
) -> IssuedAgentApiKey:
    """Issue an independently revocable key for one existing active server."""

    current_time = _as_utc(now or datetime.now(UTC))
    server = _resolve_server(session, server_selector)
    if not server.is_active:
        raise AgentKeyManagementError("server is inactive")

    material = generate_agent_api_key()
    key = AgentApiKey(
        server_id=server.id,
        public_id=material.public_id,
        secret_hash=material.secret_hash,
        label=_normalize_label(label),
        created_at=current_time,
    )
    session.add(key)
    session.flush()
    record_local_cli_action(
        session,
        action="agent_api_key.issued",
        target_type="agent_api_key",
        target_id=key.id,
        details={"server_id": str(server.id)},
    )
    return IssuedAgentApiKey(
        server_id=server.id,
        key_id=key.id,
        public_id=key.public_id,
        label=key.label,
        created_at=key.created_at,
        token=material.token,
    )


def revoke_agent_api_key(
    session: Session,
    *,
    public_id: str,
    now: datetime | None = None,
) -> RevokedAgentApiKey:
    """Revoke one public key identifier; repeated revocation is a safe no-op."""

    normalized_public_id = public_id.strip()
    if not _PUBLIC_ID_PATTERN.fullmatch(normalized_public_id):
        raise AgentKeyManagementError("agent API key does not exist")

    key = session.scalar(
        select(AgentApiKey).where(AgentApiKey.public_id == normalized_public_id).with_for_update()
    )
    if key is None:
        raise AgentKeyManagementError("agent API key does not exist")
    if key.revoked_at is not None:
        return RevokedAgentApiKey(
            server_id=key.server_id,
            key_id=key.id,
            public_id=key.public_id,
            revoked_at=_as_utc(key.revoked_at),
            changed=False,
        )

    current_time = _as_utc(now or datetime.now(UTC))
    key.revoked_at = max(current_time, _as_utc(key.created_at))
    record_local_cli_action(
        session,
        action="agent_api_key.revoked",
        target_type="agent_api_key",
        target_id=key.id,
        details={"server_id": str(key.server_id)},
    )
    session.flush()
    return RevokedAgentApiKey(
        server_id=key.server_id,
        key_id=key.id,
        public_id=key.public_id,
        revoked_at=key.revoked_at,
        changed=True,
    )


def _resolve_server(session: Session, selector: str) -> Server:
    normalized = selector.strip()
    if not normalized or len(normalized) > 100 or not normalized.isprintable():
        raise AgentKeyManagementError("server does not exist")

    try:
        server_id = UUID(normalized)
    except ValueError:
        server_id = None
    server = session.get(Server, server_id) if server_id is not None else None
    if server is None:
        server = session.scalar(select(Server).where(Server.name == normalized))
    if server is None:
        raise AgentKeyManagementError("server does not exist")
    return server


def _normalize_label(label: str | None) -> str | None:
    if label is None:
        return None
    normalized = label.strip()
    if not normalized or len(normalized) > 100 or not normalized.isprintable():
        raise AgentKeyManagementError("key label must contain 1 to 100 printable characters")
    return normalized


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AgentKeyManagementError("timestamps must include a timezone")
    return value.astimezone(UTC)
