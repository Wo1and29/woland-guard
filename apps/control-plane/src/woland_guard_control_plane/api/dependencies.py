"""Reusable authenticated-operator and RBAC dependencies for human-facing APIs."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import Depends, Header, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from woland_guard_control_plane.api.errors import ApiError
from woland_guard_control_plane.application.operator_authentication import (
    AuthenticatedOperatorApiKey,
    InvalidOperatorCredentialsError,
    authenticate_operator,
)
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.rbac import Permission, role_has_permission
from woland_guard_control_plane.database import get_session

logger = logging.getLogger("uvicorn.error")


def get_authenticated_operator(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> AuthenticatedOperatorApiKey:
    """Authenticate one operator API key and persist successful key usage."""

    request_id = str(request.state.request_id)
    token = _bearer_token(authorization, request=request)
    now = datetime.now(UTC)
    try:
        with session.begin():
            authenticated = authenticate_operator(session, token, now=now)
            authenticated.key.last_used_at = now
    except InvalidOperatorCredentialsError:
        _log_security_event(request, "operator_authentication_failed")
        raise _invalid_credentials_error() from None
    except SQLAlchemyError:
        logger.error(
            "request_id=%s security_event=operator_authentication_database_error",
            request_id,
        )
        raise ApiError(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "operator authentication unavailable",
        ) from None
    return authenticated


def require_permission(
    permission: Permission,
) -> Callable[..., AuthenticatedOperatorApiKey]:
    """Build a FastAPI dependency backed only by the centralized RBAC matrix."""

    def authorize(
        request: Request,
        operator: Annotated[AuthenticatedOperatorApiKey, Depends(get_authenticated_operator)],
    ) -> AuthenticatedOperatorApiKey:
        if not role_has_permission(operator.role, permission):
            _log_security_event(request, "operator_authorization_denied")
            raise ApiError(status.HTTP_403_FORBIDDEN, "insufficient operator permission")
        return operator

    return authorize


def _bearer_token(authorization: str | None, *, request: Request) -> str:
    if authorization is None:
        _log_security_event(request, "operator_authentication_failed")
        raise _invalid_credentials_error()
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or separator != " " or not token or " " in token:
        _log_security_event(request, "operator_authentication_failed")
        raise _invalid_credentials_error()
    return token


def _invalid_credentials_error() -> ApiError:
    return ApiError(
        status.HTTP_401_UNAUTHORIZED,
        "invalid operator credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _log_security_event(request: Request, event: str) -> None:
    limiter = cast(
        FixedWindowRateLimiter,
        request.app.state.operator_security_log_limiter,
    )
    if limiter.consume(event) is None:
        logger.warning(
            "request_id=%s security_event=%s",
            str(request.state.request_id),
            event,
        )
