"""Cookie-based Dashboard session authentication dependencies."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.rbac import Permission, role_has_permission
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    InvalidWebSessionError,
    authenticate_web_session,
    authenticate_web_session_without_touch,
)
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.i18n import current_language, t
from woland_guard_control_plane.web.security import SESSION_COOKIE_NAME

logger = logging.getLogger("uvicorn.error")


def get_authenticated_web_session(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> AuthenticatedWebSession:
    """Authenticate only the opaque session cookie and commit any conditional touch."""

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token is None:
        raise WebError(401, t(current_language(request), "err.login_required"))
    settings = request.app.state.settings
    if not isinstance(settings, Settings):
        raise RuntimeError("dashboard settings are not configured")
    try:
        with session.begin():
            authenticated = authenticate_web_session(
                session,
                token,
                now=datetime.now(UTC),
                idle_seconds=settings.web_session_idle_seconds,
                touch_interval_seconds=settings.web_session_touch_interval_seconds,
            )
    except InvalidWebSessionError:
        raise WebError(401, t(current_language(request), "err.login_required")) from None
    except SQLAlchemyError:
        raise WebError(503, t(current_language(request), "err.service_unavailable")) from None
    return authenticated


def get_authenticated_web_session_for_mutation(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> AuthenticatedWebSession:
    """Authenticate an unsafe request without touching session state before CSRF checks."""

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token is None:
        raise WebError(401, t(current_language(request), "err.login_required"))
    settings = request.app.state.settings
    if not isinstance(settings, Settings):
        raise RuntimeError("dashboard settings are not configured")
    try:
        with session.begin():
            authenticated = authenticate_web_session_without_touch(
                session,
                token,
                now=datetime.now(UTC),
                idle_seconds=settings.web_session_idle_seconds,
                touch_interval_seconds=settings.web_session_touch_interval_seconds,
            )
    except InvalidWebSessionError:
        raise WebError(401, t(current_language(request), "err.login_required")) from None
    except SQLAlchemyError:
        raise WebError(503, t(current_language(request), "err.service_unavailable")) from None
    return authenticated


def require_dashboard_permission(
    permission: Permission,
) -> Callable[..., AuthenticatedWebSession]:
    """Authorize a session principal through the one centralized RBAC matrix."""

    def authorize(
        request: Request,
        authenticated: Annotated[
            AuthenticatedWebSession,
            Depends(get_authenticated_web_session),
        ],
    ) -> AuthenticatedWebSession:
        if not role_has_permission(authenticated.principal.role, permission):
            limiter = cast(FixedWindowRateLimiter, request.app.state.security_log_limiter)
            if limiter.consume("dashboard_authorization_denied") is None:
                logger.warning(
                    "request_id=%s security_event=dashboard_authorization_denied",
                    str(request.state.request_id),
                )
            raise WebError(403, t(current_language(request), "err.insufficient_permissions"))
        return authenticated

    return authorize


def require_dashboard_mutation_permission(
    permission: Permission,
) -> Callable[..., AuthenticatedWebSession]:
    """Perform preliminary no-touch authorization before Origin and CSRF checks."""

    def authorize(
        request: Request,
        authenticated: Annotated[
            AuthenticatedWebSession,
            Depends(get_authenticated_web_session_for_mutation),
        ],
    ) -> AuthenticatedWebSession:
        if not role_has_permission(authenticated.principal.role, permission):
            limiter = cast(FixedWindowRateLimiter, request.app.state.security_log_limiter)
            if limiter.consume("dashboard_authorization_denied") is None:
                logger.warning(
                    "request_id=%s security_event=dashboard_authorization_denied",
                    str(request.state.request_id),
                )
            raise WebError(403, t(current_language(request), "err.insufficient_permissions"))
        return authenticated

    return authorize
