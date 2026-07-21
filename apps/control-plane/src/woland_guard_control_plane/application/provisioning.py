"""Local provisioning service for test servers and one-time agent credentials."""

from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy.orm import Session

from woland_guard_control_plane.application.agent_keys import generate_agent_api_key
from woland_guard_control_plane.infrastructure.database.models import AgentApiKey, Server


@dataclass(frozen=True, slots=True)
class ProvisionedAgent:
    """Identifiers plus the plaintext token returned exactly once to the caller."""

    server_id: UUID
    key_id: UUID
    public_id: str
    token: str = field(repr=False)


def provision_test_server(
    session: Session,
    *,
    name: str,
    hostname: str,
    label: str | None = None,
) -> ProvisionedAgent:
    """Create one test server and one key without persisting the plaintext token."""

    normalized_name = name.strip()
    normalized_hostname = hostname.strip()
    if not normalized_name or len(normalized_name) > 100:
        raise ValueError("server name must contain 1 to 100 characters")
    if not normalized_hostname or len(normalized_hostname) > 253:
        raise ValueError("hostname must contain 1 to 253 characters")
    if label is not None and len(label) > 100:
        raise ValueError("label must not exceed 100 characters")

    server = Server(name=normalized_name, hostname=normalized_hostname)
    session.add(server)
    session.flush()

    material = generate_agent_api_key()
    api_key = AgentApiKey(
        server_id=server.id,
        public_id=material.public_id,
        secret_hash=material.secret_hash,
        label=label,
    )
    session.add(api_key)
    session.flush()

    return ProvisionedAgent(
        server_id=server.id,
        key_id=api_key.id,
        public_id=material.public_id,
        token=material.token,
    )
