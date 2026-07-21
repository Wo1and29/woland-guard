"""Database-backed authentication for local operator identities."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.operator_keys import (
    SECRET_HASH_SIZE,
    parse_operator_api_key_public_id,
    verify_operator_api_key,
)
from woland_guard_control_plane.infrastructure.database.models import (
    Operator,
    OperatorApiKey,
    OperatorRole,
)

_DUMMY_SECRET_HASH = bytes(SECRET_HASH_SIZE)


class InvalidOperatorCredentialsError(Exception):
    """One indistinguishable failure for every unusable operator credential."""


@dataclass(frozen=True, slots=True)
class AuthenticatedOperator:
    """An authenticated identity independent from future session mechanisms."""

    operator_id: UUID
    key_id: UUID
    username: str
    role: OperatorRole
    public_id: str
    key: OperatorApiKey


def authenticate_operator(
    session: Session,
    token: str,
    *,
    now: datetime,
) -> AuthenticatedOperator:
    """Resolve an active operator through one valid, unexpired, unrevoked API key."""

    public_id = parse_operator_api_key_public_id(token)
    if public_id is None:
        raise InvalidOperatorCredentialsError

    statement = (
        select(OperatorApiKey, Operator)
        .join(Operator, Operator.id == OperatorApiKey.operator_id)
        .where(OperatorApiKey.public_id == public_id)
    )
    row = session.execute(statement).one_or_none()
    if row is None:
        verify_operator_api_key(
            token,
            expected_public_id=public_id,
            expected_secret_hash=_DUMMY_SECRET_HASH,
        )
        raise InvalidOperatorCredentialsError

    key, operator = row
    credentials_match = verify_operator_api_key(
        token,
        expected_public_id=key.public_id,
        expected_secret_hash=key.secret_hash,
    )
    credential_is_usable = (
        credentials_match
        and operator.is_active
        and key.revoked_at is None
        and (key.expires_at is None or key.expires_at > now)
    )
    if not credential_is_usable:
        raise InvalidOperatorCredentialsError

    return AuthenticatedOperator(
        operator_id=operator.id,
        key_id=key.id,
        username=operator.username,
        role=OperatorRole(operator.role),
        public_id=key.public_id,
        key=key,
    )
