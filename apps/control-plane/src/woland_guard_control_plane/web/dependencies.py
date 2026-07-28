"""Cookie-based Dashboard session authentication dependencies."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    InvalidWebSessionError,
    authenticate_web_session,
    authenticate_web_session_without_touch,
)
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.security import SESSION_COOKIE_NAME


def get_authenticated_web_session(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> AuthenticatedWebSession:
    """Authenticate only the opaque session cookie and commit any conditional touch."""

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token is None:
        raise WebError(401, "Требуется вход.")
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
        raise WebError(401, "Требуется вход.") from None
    except SQLAlchemyError:
        raise WebError(503, "Сервис временно недоступен.") from None
    return authenticated


def get_authenticated_web_session_for_mutation(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> AuthenticatedWebSession:
    """Authenticate an unsafe request without touching session state before CSRF checks."""

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token is None:
        raise WebError(401, "Требуется вход.")
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
        raise WebError(401, "Требуется вход.") from None
    except SQLAlchemyError:
        raise WebError(503, "Сервис временно недоступен.") from None
    return authenticated
