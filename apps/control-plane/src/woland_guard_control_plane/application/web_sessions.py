"""Opaque operator web-session lifecycle with provider-neutral principals."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import record_operator_action
from woland_guard_control_plane.application.operator_authentication import (
    AuthenticatedOperatorApiKey,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.application.rbac import Permission, role_has_permission
from woland_guard_control_plane.infrastructure.database.models import (
    Operator,
    OperatorAuthMethodType,
    OperatorRole,
    OperatorWebSession,
)

TOKEN_BYTES = 32
TOKEN_TEXT_LENGTH = 43
TOKEN_DIGEST_BYTES = 32
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class WebSessionError(ValueError):
    """Safe web-session validation or lifecycle error."""


class InvalidWebSessionError(WebSessionError):
    """One indistinguishable failure for every unusable session."""


class WebSessionPermissionError(WebSessionError):
    """The current locked operator role cannot perform a requested mutation."""


@dataclass(frozen=True, slots=True)
class IssuedWebSession:
    """One-time browser material returned only after a pending DB insert."""

    session_id: UUID
    absolute_expires_at: datetime
    session_token: str = field(repr=False)
    csrf_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthenticatedWebSession:
    """Detached session authentication result without plaintext credentials."""

    principal: OperatorPrincipal
    session_id: UUID
    csrf_token_digest: bytes = field(repr=False)


def generate_web_token() -> str:
    """Return a canonical unpadded base64url token containing 256 random bits."""

    token = token_urlsafe(TOKEN_BYTES)
    if len(token) != TOKEN_TEXT_LENGTH or _decode_token(token) is None:
        raise RuntimeError("secure token generator returned an invalid token")
    return token


def web_token_digest(token: str) -> bytes | None:
    """Return SHA-256 over a strictly canonical 256-bit token."""

    raw = _decode_token(token)
    return sha256(raw).digest() if raw is not None else None


def create_operator_web_session(
    session: Session,
    *,
    authenticated: AuthenticatedOperatorApiKey,
    now: datetime,
    idle_seconds: int,
    absolute_seconds: int,
    request_id: str,
) -> IssuedWebSession:
    """Create a web session and its login audit inside the caller transaction."""

    current_time = _as_utc(now)
    if idle_seconds <= 0 or absolute_seconds <= 0:
        raise WebSessionError("web session lifetime is invalid")
    absolute_expires_at = current_time + timedelta(seconds=absolute_seconds)
    if authenticated.key.expires_at is not None:
        key_expiry = _as_utc(authenticated.key.expires_at)
        absolute_expires_at = min(absolute_expires_at, key_expiry)
    if absolute_expires_at <= current_time:
        raise InvalidWebSessionError("operator credentials are unavailable")
    idle_expires_at = min(
        current_time + timedelta(seconds=idle_seconds),
        absolute_expires_at,
    )
    session_token = generate_web_token()
    csrf_token = generate_web_token()
    token_digest = web_token_digest(session_token)
    csrf_digest = web_token_digest(csrf_token)
    if token_digest is None or csrf_digest is None:
        raise RuntimeError("secure token generation failed validation")

    stored = OperatorWebSession(
        operator_id=authenticated.principal.operator_id,
        authenticated_by_api_key_id=authenticated.principal.auth_method_id,
        token_digest=token_digest,
        csrf_token_digest=csrf_digest,
        created_at=current_time,
        last_seen_at=current_time,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
        updated_at=current_time,
    )
    session.add(stored)
    session.flush()
    record_operator_action(
        session,
        actor=authenticated.principal,
        action="operator_web_session.started",
        target_type="operator_web_session",
        target_id=stored.id,
        request_id=request_id,
        incident_history_id=None,
        details={},
    )
    return IssuedWebSession(
        session_id=stored.id,
        absolute_expires_at=stored.absolute_expires_at,
        session_token=session_token,
        csrf_token=csrf_token,
    )


def authenticate_web_session(
    session: Session,
    token: str,
    *,
    now: datetime,
    idle_seconds: int,
    touch_interval_seconds: int,
) -> AuthenticatedWebSession:
    """Resolve one active session and perform at most one conditional touch."""

    return _authenticate_web_session(
        session,
        token,
        now=now,
        idle_seconds=idle_seconds,
        touch_interval_seconds=touch_interval_seconds,
        touch=True,
    )


def authenticate_web_session_without_touch(
    session: Session,
    token: str,
    *,
    now: datetime,
    idle_seconds: int,
    touch_interval_seconds: int,
) -> AuthenticatedWebSession:
    """Resolve one active session without changing lifecycle timestamps."""

    return _authenticate_web_session(
        session,
        token,
        now=now,
        idle_seconds=idle_seconds,
        touch_interval_seconds=touch_interval_seconds,
        touch=False,
    )


def _authenticate_web_session(
    session: Session,
    token: str,
    *,
    now: datetime,
    idle_seconds: int,
    touch_interval_seconds: int,
    touch: bool,
) -> AuthenticatedWebSession:
    """Resolve one session and optionally perform its bounded conditional touch."""

    current_time = _as_utc(now)
    digest = web_token_digest(token)
    if digest is None:
        raise InvalidWebSessionError("invalid web session")
    row = session.execute(
        select(OperatorWebSession, Operator)
        .join(Operator, Operator.id == OperatorWebSession.operator_id)
        .where(OperatorWebSession.token_digest == digest)
    ).one_or_none()
    if row is None:
        raise InvalidWebSessionError("invalid web session")
    stored, operator = row
    usable = (
        compare_digest(stored.token_digest, digest)
        and stored.revoked_at is None
        and stored.idle_expires_at > current_time
        and stored.absolute_expires_at > current_time
        and operator.is_active
    )
    if not usable:
        raise InvalidWebSessionError("invalid web session")
    if idle_seconds <= 0 or touch_interval_seconds <= 0:
        raise WebSessionError("web session timing is invalid")

    if touch and stored.last_seen_at <= current_time - timedelta(seconds=touch_interval_seconds):
        proposed_idle_expiry = current_time + timedelta(seconds=idle_seconds)
        session.execute(
            update(OperatorWebSession)
            .where(
                OperatorWebSession.id == stored.id,
                OperatorWebSession.revoked_at.is_(None),
                OperatorWebSession.idle_expires_at > current_time,
                OperatorWebSession.absolute_expires_at > current_time,
                OperatorWebSession.last_seen_at
                <= current_time - timedelta(seconds=touch_interval_seconds),
            )
            .values(
                last_seen_at=func.greatest(OperatorWebSession.last_seen_at, current_time),
                idle_expires_at=func.least(
                    OperatorWebSession.absolute_expires_at,
                    func.greatest(OperatorWebSession.idle_expires_at, proposed_idle_expiry),
                ),
                updated_at=func.greatest(OperatorWebSession.updated_at, current_time),
            )
        )

    principal = OperatorPrincipal(
        operator_id=operator.id,
        username=operator.username,
        role=OperatorRole(operator.role),
        auth_method_type=OperatorAuthMethodType.WEB_SESSION,
        auth_method_id=stored.id,
    )
    return AuthenticatedWebSession(
        principal=principal,
        session_id=stored.id,
        csrf_token_digest=stored.csrf_token_digest,
    )


def verify_csrf_tokens(
    *,
    cookie_token: str,
    form_token: str,
    expected_digest: bytes | None,
) -> bool:
    """Verify cookie/form equality and optional session binding in constant time."""

    cookie_raw = _decode_token(cookie_token)
    form_raw = _decode_token(form_token)
    if cookie_raw is None or form_raw is None:
        return False
    tokens_match = compare_digest(cookie_raw, form_raw)
    if expected_digest is None:
        return tokens_match
    if len(expected_digest) != TOKEN_DIGEST_BYTES:
        return False
    digest_matches = compare_digest(sha256(form_raw).digest(), expected_digest)
    return tokens_match and digest_matches


def lock_web_session_for_mutation(
    session: Session,
    *,
    authenticated: AuthenticatedWebSession,
    session_token: str,
    required_permission: Permission,
    now: datetime,
) -> OperatorPrincipal:
    """Lock and revalidate the session and current operator authorization."""

    current_time = _as_utc(now)
    digest = web_token_digest(session_token)
    if digest is None:
        raise InvalidWebSessionError("invalid web session")
    row = session.execute(
        select(OperatorWebSession, Operator)
        .join(Operator, Operator.id == OperatorWebSession.operator_id)
        .where(OperatorWebSession.id == authenticated.session_id)
        .with_for_update(of=(OperatorWebSession, Operator))
    ).one_or_none()
    if row is None:
        raise InvalidWebSessionError("invalid web session")
    stored, operator = row
    binding_is_valid = (
        compare_digest(stored.token_digest, digest)
        and compare_digest(stored.csrf_token_digest, authenticated.csrf_token_digest)
        and stored.id == authenticated.session_id
        and stored.operator_id == authenticated.principal.operator_id
        and authenticated.principal.auth_method_type is OperatorAuthMethodType.WEB_SESSION
        and authenticated.principal.auth_method_id == stored.id
    )
    lifecycle_is_valid = (
        stored.revoked_at is None
        and stored.idle_expires_at > current_time
        and stored.absolute_expires_at > current_time
        and operator.id == stored.operator_id
        and operator.is_active
    )
    if not binding_is_valid or not lifecycle_is_valid:
        raise InvalidWebSessionError("invalid web session")

    current_role = OperatorRole(operator.role)
    if not role_has_permission(current_role, required_permission):
        raise WebSessionPermissionError("web session permission is unavailable")
    return OperatorPrincipal(
        operator_id=operator.id,
        username=operator.username,
        role=current_role,
        auth_method_type=OperatorAuthMethodType.WEB_SESSION,
        auth_method_id=stored.id,
    )


def revoke_operator_web_session(
    session: Session,
    *,
    authenticated: AuthenticatedWebSession,
    request_id: str,
    now: datetime,
) -> None:
    """Revoke the current session and record logout atomically."""

    current_time = _as_utc(now)
    stored = session.scalar(
        select(OperatorWebSession)
        .where(OperatorWebSession.id == authenticated.session_id)
        .with_for_update()
    )
    if stored is None or stored.revoked_at is not None:
        raise InvalidWebSessionError("invalid web session")
    stored.revoked_at = current_time
    stored.updated_at = current_time
    record_operator_action(
        session,
        actor=authenticated.principal,
        action="operator_web_session.ended",
        target_type="operator_web_session",
        target_id=stored.id,
        request_id=request_id,
        incident_history_id=None,
        details={},
    )
    session.flush()


def revoke_sessions_authenticated_by_key(
    session: Session,
    *,
    key_id: UUID,
    now: datetime,
) -> int:
    """Revoke every still-active session established by one API key."""

    current_time = _as_utc(now)
    result = session.execute(
        update(OperatorWebSession)
        .where(
            OperatorWebSession.authenticated_by_api_key_id == key_id,
            OperatorWebSession.revoked_at.is_(None),
        )
        .values(revoked_at=current_time, updated_at=current_time)
    )
    if not isinstance(result, CursorResult):
        raise RuntimeError("session revocation did not return an update result")
    return int(result.rowcount or 0)


def _decode_token(token: str) -> bytes | None:
    if type(token) is not str or _TOKEN_PATTERN.fullmatch(token) is None:
        return None
    try:
        raw = base64.b64decode(f"{token}=", altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) != TOKEN_BYTES:
        return None
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return raw if compare_digest(canonical, token) else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise WebSessionError("web session timestamps must include a timezone")
    return value.astimezone(UTC)
