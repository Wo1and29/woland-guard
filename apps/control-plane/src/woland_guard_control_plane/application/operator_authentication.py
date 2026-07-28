"""Database-backed authentication for local operator identities."""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.operator_keys import (
    SECRET_HASH_SIZE,
    parse_operator_api_key_public_id,
    verify_operator_api_key,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.infrastructure.database.models import (
    Operator,
    OperatorApiKey,
    OperatorAuthMethodType,
    OperatorRole,
)

_DUMMY_SECRET_HASH = bytes(SECRET_HASH_SIZE)


class InvalidOperatorCredentialsError(Exception):
    """One indistinguishable failure for every unusable operator credential."""


@dataclass(frozen=True, slots=True)
class AuthenticatedOperatorApiKey:
    """API-key authentication result kept outside provider-neutral services."""

    principal: OperatorPrincipal
    public_id: str
    key: OperatorApiKey = field(repr=False, compare=False)

    @property
    def operator_id(self) -> UUID:
        return self.principal.operator_id

    @property
    def key_id(self) -> UUID:
        return self.principal.auth_method_id

    @property
    def username(self) -> str:
        return self.principal.username

    @property
    def role(self) -> OperatorRole:
        return self.principal.role


# Internal compatibility alias while callers migrate to the explicit wrapper name.
AuthenticatedOperator = AuthenticatedOperatorApiKey


def authenticate_operator(
    session: Session,
    token: str,
    *,
    now: datetime,
) -> AuthenticatedOperatorApiKey:
    """Resolve an active operator through one valid, unexpired, unrevoked API key."""

    return _authenticate_operator(session, token, now=now, lock_key=False)


def authenticate_operator_for_web_session(
    session: Session,
    token: str,
    *,
    now: datetime,
) -> AuthenticatedOperatorApiKey:
    """Lock and resolve one API key for an atomic browser-session exchange."""

    return _authenticate_operator(session, token, now=now, lock_key=True)


def _authenticate_operator(
    session: Session,
    token: str,
    *,
    now: datetime,
    lock_key: bool,
) -> AuthenticatedOperatorApiKey:
    """Resolve credentials, optionally serializing lifecycle changes for one key."""

    public_id = parse_operator_api_key_public_id(token)
    if public_id is None:
        raise InvalidOperatorCredentialsError

    statement = (
        select(OperatorApiKey, Operator)
        .join(Operator, Operator.id == OperatorApiKey.operator_id)
        .where(OperatorApiKey.public_id == public_id)
    )
    if lock_key:
        statement = statement.with_for_update(of=OperatorApiKey)
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

    return AuthenticatedOperatorApiKey(
        principal=OperatorPrincipal(
            operator_id=operator.id,
            username=operator.username,
            role=OperatorRole(operator.role),
            auth_method_type=OperatorAuthMethodType.OPERATOR_API_KEY,
            auth_method_id=key.id,
        ),
        public_id=key.public_id,
        key=key,
    )
