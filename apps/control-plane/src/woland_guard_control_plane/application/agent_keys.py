"""Generation and verification primitives for agent API keys."""

from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe

TOKEN_PREFIX = "wgak_"  # noqa: S105 - public credential format marker, not a secret
SECRET_HASH_SIZE = 32


@dataclass(frozen=True, slots=True)
class AgentApiKeyMaterial:
    """One-time key material returned when an agent credential is created."""

    public_id: str
    token: str = field(repr=False)
    secret_hash: bytes = field(repr=False)


def generate_agent_api_key() -> AgentApiKeyMaterial:
    """Generate a random credential and the digest that is safe to persist."""

    public_id = token_urlsafe(12)
    secret = token_urlsafe(32)
    token = f"{TOKEN_PREFIX}{public_id}.{secret}"
    return AgentApiKeyMaterial(
        public_id=public_id,
        token=token,
        secret_hash=_hash_secret(secret),
    )


def verify_agent_api_key(
    token: str,
    *,
    expected_public_id: str,
    expected_secret_hash: bytes,
) -> bool:
    """Verify a presented token without persisting or logging its plaintext secret."""

    if len(expected_secret_hash) != SECRET_HASH_SIZE:
        return False

    if not token.startswith(TOKEN_PREFIX):
        return False

    token_body = token.removeprefix(TOKEN_PREFIX)
    if token_body.count(".") != 1:
        return False

    public_id, secret = token_body.split(".", maxsplit=1)
    if not public_id or not secret:
        return False

    public_id_matches = compare_digest(public_id, expected_public_id)
    secret_matches = compare_digest(_hash_secret(secret), expected_secret_hash)
    return public_id_matches and secret_matches


def parse_agent_api_key_public_id(token: str) -> str | None:
    """Extract a public identifier only from a structurally valid agent token."""

    if not token.startswith(TOKEN_PREFIX):
        return None

    token_body = token.removeprefix(TOKEN_PREFIX)
    if token_body.count(".") != 1:
        return None

    public_id, secret = token_body.split(".", maxsplit=1)
    if not public_id or not secret:
        return None
    return public_id


def _hash_secret(secret: str) -> bytes:
    """Hash a high-entropy random secret for database storage."""

    return sha256(secret.encode("utf-8")).digest()
