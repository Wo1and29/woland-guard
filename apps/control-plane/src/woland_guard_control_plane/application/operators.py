"""Local operator and API-key lifecycle services used by the administrative CLI."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import record_local_cli_action
from woland_guard_control_plane.application.operator_keys import generate_operator_api_key
from woland_guard_control_plane.infrastructure.database.models import (
    Operator,
    OperatorApiKey,
    OperatorRole,
)

_USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")


class OperatorManagementError(ValueError):
    """A safe validation or lifecycle conflict for local operator management."""


@dataclass(frozen=True, slots=True)
class ProvisionedOperator:
    id: UUID
    username: str
    role: OperatorRole


@dataclass(frozen=True, slots=True)
class IssuedOperatorApiKey:
    operator_id: UUID
    key_id: UUID
    public_id: str
    expires_at: datetime | None
    rotated_from_id: UUID | None
    token: str = field(repr=False)


def create_operator(
    session: Session,
    *,
    username: str,
    role: OperatorRole,
) -> ProvisionedOperator:
    """Create one active identity without coupling it to an authentication method."""

    if not _USERNAME_PATTERN.fullmatch(username):
        raise OperatorManagementError("username must match ^[a-z][a-z0-9_.-]{2,63}$")
    operator = Operator(username=username, role=role.value)
    session.add(operator)
    session.flush()
    record_local_cli_action(
        session,
        action="operator.created",
        target_type="operator",
        target_id=operator.id,
        details={"role": role.value},
    )
    return ProvisionedOperator(id=operator.id, username=operator.username, role=role)


def issue_operator_api_key(
    session: Session,
    *,
    operator_id: UUID,
    label: str | None = None,
    expires_at: datetime | None = None,
    now: datetime | None = None,
) -> IssuedOperatorApiKey:
    """Issue a new independently revocable key and return its secret exactly once."""

    current_time = _as_utc(now or datetime.now(UTC))
    normalized_expiry = _validate_expiry(expires_at, now=current_time)
    normalized_label = _normalize_label(label)
    operator = session.get(Operator, operator_id)
    if operator is None:
        raise OperatorManagementError("operator does not exist")
    if not operator.is_active:
        raise OperatorManagementError("operator is inactive")
    issued = _create_key(
        session,
        operator=operator,
        label=normalized_label,
        expires_at=normalized_expiry,
        rotated_from_id=None,
        created_at=current_time,
    )
    record_local_cli_action(
        session,
        action="operator_api_key.issued",
        target_type="operator_api_key",
        target_id=issued.key_id,
        details={"operator_id": str(operator.id)},
    )
    return issued


def rotate_operator_api_key(
    session: Session,
    *,
    key_id: UUID,
    label: str | None = None,
    expires_at: datetime | None = None,
    now: datetime | None = None,
) -> IssuedOperatorApiKey:
    """Atomically revoke one key and issue a single replacement for its operator."""

    current_time = _as_utc(now or datetime.now(UTC))
    key = session.get(OperatorApiKey, key_id, with_for_update=True)
    if key is None:
        raise OperatorManagementError("operator API key does not exist")
    if key.revoked_at is not None:
        raise OperatorManagementError("operator API key is already revoked")
    normalized_expiry = _validate_expiry(
        expires_at if expires_at is not None else key.expires_at,
        now=current_time,
    )
    operator = session.get(Operator, key.operator_id)
    if operator is None or not operator.is_active:
        raise OperatorManagementError("operator is unavailable")

    replacement = _create_key(
        session,
        operator=operator,
        label=_normalize_label(label) if label is not None else key.label,
        expires_at=normalized_expiry,
        rotated_from_id=key.id,
        created_at=current_time,
    )
    key.revoked_at = current_time
    record_local_cli_action(
        session,
        action="operator_api_key.rotated",
        target_type="operator_api_key",
        target_id=replacement.key_id,
        details={
            "operator_id": str(operator.id),
            "replaced_key_id": str(key.id),
        },
    )
    session.flush()
    return replacement


def revoke_operator_api_key(
    session: Session,
    *,
    key_id: UUID,
    now: datetime | None = None,
) -> bool:
    """Revoke a key once; return False for an already revoked credential."""

    current_time = _as_utc(now or datetime.now(UTC))
    key = session.get(OperatorApiKey, key_id, with_for_update=True)
    if key is None:
        raise OperatorManagementError("operator API key does not exist")
    if key.revoked_at is not None:
        return False
    key.revoked_at = current_time
    record_local_cli_action(
        session,
        action="operator_api_key.revoked",
        target_type="operator_api_key",
        target_id=key.id,
        details={"operator_id": str(key.operator_id)},
    )
    session.flush()
    return True


def _create_key(
    session: Session,
    *,
    operator: Operator,
    label: str | None,
    expires_at: datetime | None,
    rotated_from_id: UUID | None,
    created_at: datetime,
) -> IssuedOperatorApiKey:
    material = generate_operator_api_key()
    key = OperatorApiKey(
        operator_id=operator.id,
        public_id=material.public_id,
        secret_hash=material.secret_hash,
        label=label,
        rotated_from_id=rotated_from_id,
        created_at=created_at,
        expires_at=expires_at,
    )
    session.add(key)
    session.flush()
    return IssuedOperatorApiKey(
        operator_id=operator.id,
        key_id=key.id,
        public_id=key.public_id,
        expires_at=key.expires_at,
        rotated_from_id=key.rotated_from_id,
        token=material.token,
    )


def _normalize_label(label: str | None) -> str | None:
    if label is None:
        return None
    normalized = label.strip()
    if not normalized or len(normalized) > 100:
        raise OperatorManagementError("key label must contain 1 to 100 characters")
    return normalized


def _validate_expiry(expires_at: datetime | None, *, now: datetime) -> datetime | None:
    if expires_at is None:
        return None
    normalized = _as_utc(expires_at)
    if normalized <= now:
        raise OperatorManagementError("key expiry must be in the future")
    return normalized


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperatorManagementError("timestamps must include a timezone")
    return value.astimezone(UTC)
