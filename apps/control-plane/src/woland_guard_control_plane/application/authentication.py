"""Database-backed authentication for Linux agents."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.agent_keys import (
    SECRET_HASH_SIZE,
    parse_agent_api_key_public_id,
    verify_agent_api_key,
)
from woland_guard_control_plane.infrastructure.database.models import AgentApiKey, Server

_DUMMY_SECRET_HASH = bytes(SECRET_HASH_SIZE)


class InvalidAgentCredentialsError(Exception):
    """Raised for every invalid, unknown, revoked, or expired agent credential."""


class InactiveServerError(Exception):
    """Raised after valid authentication when the owning server is inactive."""


@dataclass(frozen=True, slots=True)
class AuthenticatedAgent:
    """Trusted server identity derived exclusively from a verified API key."""

    key: AgentApiKey
    server_id: UUID
    public_id: str


def authenticate_agent(session: Session, token: str, *, now: datetime) -> AuthenticatedAgent:
    """Authenticate a token and resolve its active server without accepting client IDs."""

    public_id = parse_agent_api_key_public_id(token)
    if public_id is None:
        raise InvalidAgentCredentialsError

    statement = (
        select(AgentApiKey, Server)
        .join(Server, Server.id == AgentApiKey.server_id)
        .where(AgentApiKey.public_id == public_id)
    )
    row = session.execute(statement).one_or_none()

    if row is None:
        verify_agent_api_key(
            token,
            expected_public_id=public_id,
            expected_secret_hash=_DUMMY_SECRET_HASH,
        )
        raise InvalidAgentCredentialsError

    key, server = row
    credentials_match = verify_agent_api_key(
        token,
        expected_public_id=key.public_id,
        expected_secret_hash=key.secret_hash,
    )
    credential_is_usable = (
        credentials_match
        and key.revoked_at is None
        and (key.expires_at is None or key.expires_at > now)
    )
    if not credential_is_usable:
        raise InvalidAgentCredentialsError
    if not server.is_active:
        raise InactiveServerError

    return AuthenticatedAgent(key=key, server_id=server.id, public_id=key.public_id)
