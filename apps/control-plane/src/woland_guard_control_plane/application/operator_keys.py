"""Generation and constant-time verification primitives for operator API keys."""

import re
from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe

TOKEN_PREFIX = "wgok_"  # noqa: S105 - public credential format marker, not a secret
SECRET_HASH_SIZE = 32
PUBLIC_ID_LENGTH = 16
SECRET_LENGTH = 43
_TOKEN_BODY_PATTERN = re.compile(
    rf"^(?P<public_id>[A-Za-z0-9_-]{{{PUBLIC_ID_LENGTH}}})\."
    rf"(?P<secret>[A-Za-z0-9_-]{{{SECRET_LENGTH}}})$"
)


@dataclass(frozen=True, slots=True)
class OperatorApiKeyMaterial:
    """One-time operator credential material; only its digest may be persisted."""

    public_id: str
    token: str = field(repr=False)
    secret_hash: bytes = field(repr=False)


def generate_operator_api_key() -> OperatorApiKeyMaterial:
    """Generate an operator token and the fixed-size digest safe for PostgreSQL."""

    public_id = token_urlsafe(12)
    secret = token_urlsafe(32)
    token = f"{TOKEN_PREFIX}{public_id}.{secret}"
    return OperatorApiKeyMaterial(
        public_id=public_id,
        token=token,
        secret_hash=_hash_secret(secret),
    )


def verify_operator_api_key(
    token: str,
    *,
    expected_public_id: str,
    expected_secret_hash: bytes,
) -> bool:
    """Verify a structurally valid token with constant-time digest comparisons."""

    if len(expected_secret_hash) != SECRET_HASH_SIZE:
        return False

    parsed = _parse_token(token)
    if parsed is None:
        return False
    public_id, secret = parsed
    public_id_matches = compare_digest(public_id, expected_public_id)
    secret_matches = compare_digest(_hash_secret(secret), expected_secret_hash)
    return public_id_matches and secret_matches


def parse_operator_api_key_public_id(token: str) -> str | None:
    """Return the lookup-safe public ID from an exactly shaped operator token."""

    parsed = _parse_token(token)
    return parsed[0] if parsed is not None else None


def _parse_token(token: str) -> tuple[str, str] | None:
    if not token.startswith(TOKEN_PREFIX):
        return None
    match = _TOKEN_BODY_PATTERN.fullmatch(token.removeprefix(TOKEN_PREFIX))
    if match is None:
        return None
    return match.group("public_id"), match.group("secret")


def _hash_secret(secret: str) -> bytes:
    return sha256(secret.encode("utf-8")).digest()
