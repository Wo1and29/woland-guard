"""Minimal login, authenticated session and logout HTML routes."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from math import ceil
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import Response

from woland_guard_control_plane.application.login_rate_limit import LoginRateLimiter
from woland_guard_control_plane.application.operator_authentication import (
    InvalidOperatorCredentialsError,
    authenticate_operator_for_web_session,
)
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.rbac import Permission, role_has_permission
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    InvalidWebSessionError,
    create_operator_web_session,
    generate_web_token,
    revoke_operator_web_session,
    verify_csrf_tokens,
)
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.web.dependencies import (
    get_authenticated_web_session,
    get_authenticated_web_session_for_mutation,
)
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.form_body import BoundedFormError, parse_bounded_form
from woland_guard_control_plane.web.security import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    SESSION_COOKIE_NAME,
    OriginValidationError,
    delete_secure_cookie,
    require_exact_origin,
    set_secure_cookie,
)

logger = logging.getLogger("uvicorn.error")
router = APIRouter()


@router.get("/login", response_class=HTMLResponse, name="dashboard_login")
def login_page(request: Request) -> HTMLResponse:
    """Issue one pre-auth CSRF token and render a non-cacheable login form."""

    token = generate_web_token()
    response = cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={"csrf_token": token},
        ),
    )
    set_secure_cookie(response, name=CSRF_COOKIE_NAME, value=token, max_age=600)
    return response


@router.post("/login", name="dashboard_login_submit", response_model=None)
def login(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Exchange one valid operator API key for opaque session cookies."""

    settings = _settings(request)
    _require_origin(request, settings)
    form = _form(
        request,
        allowed={"credential", CSRF_FORM_FIELD},
        required={"credential", CSRF_FORM_FIELD},
    )
    cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not verify_csrf_tokens(
        cookie_token=cookie_csrf,
        form_token=form[CSRF_FORM_FIELD],
        expected_digest=None,
    ):
        raise WebError(403, "Запрос отклонён.")

    limiter = cast(LoginRateLimiter, request.app.state.login_rate_limiter)
    decision = limiter.consume(form["credential"])
    if decision is not None:
        _log_security_event(request, "dashboard_login_rate_limited", scope=decision.scope)
        response = _error_response(request, 429, "Слишком много попыток входа.")
        response.headers["Retry-After"] = str(decision.retry_after_seconds)
        return response

    now = datetime.now(UTC)
    try:
        with session.begin():
            authenticated = authenticate_operator_for_web_session(
                session,
                form["credential"],
                now=now,
            )
            if not role_has_permission(
                authenticated.principal.role,
                Permission.ACCESS_DASHBOARD,
            ):
                raise WebError(403, "Недостаточно прав для Dashboard.")
            issued = create_operator_web_session(
                session,
                authenticated=authenticated,
                now=now,
                idle_seconds=settings.web_session_idle_seconds,
                absolute_seconds=settings.web_session_absolute_seconds,
                request_id=_request_id(request),
            )
            authenticated.key.last_used_at = now
    except InvalidOperatorCredentialsError:
        _log_security_event(request, "dashboard_login_failed")
        raise WebError(401, "Неверные учётные данные.") from None
    except SQLAlchemyError:
        raise WebError(503, "Сервис входа временно недоступен.") from None

    max_age = max(1, ceil((issued.absolute_expires_at - now).total_seconds()))
    success_response = RedirectResponse(_external_path(request, "/"), status_code=303)
    set_secure_cookie(
        success_response,
        name=SESSION_COOKIE_NAME,
        value=issued.session_token,
        max_age=max_age,
    )
    set_secure_cookie(
        success_response,
        name=CSRF_COOKIE_NAME,
        value=issued.csrf_token,
        max_age=max_age,
    )
    return success_response


@router.get("/", response_class=HTMLResponse, name="dashboard_session")
def session_page(
    request: Request,
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(get_authenticated_web_session),
    ],
) -> HTMLResponse:
    """Render the minimal 7A session page without Dashboard data."""

    csrf_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not verify_csrf_tokens(
        cookie_token=csrf_token,
        form_token=csrf_token,
        expected_digest=authenticated.csrf_token_digest,
    ):
        raise WebError(401, "Требуется повторный вход.")
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="auth/session.html",
            context={
                "username": authenticated.principal.username,
                "csrf_token": csrf_token,
            },
        ),
    )


@router.post("/logout", name="dashboard_logout")
def logout(
    request: Request,
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(get_authenticated_web_session_for_mutation),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> RedirectResponse:
    """Commit session revoke/audit before clearing either browser cookie."""

    settings = _settings(request)
    _require_origin(request, settings)
    form = _form(
        request,
        allowed={CSRF_FORM_FIELD},
        required={CSRF_FORM_FIELD},
    )
    cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not verify_csrf_tokens(
        cookie_token=cookie_csrf,
        form_token=form[CSRF_FORM_FIELD],
        expected_digest=authenticated.csrf_token_digest,
    ):
        raise WebError(403, "Запрос отклонён.")
    try:
        with session.begin():
            revoke_operator_web_session(
                session,
                authenticated=authenticated,
                request_id=_request_id(request),
                now=datetime.now(UTC),
            )
    except InvalidWebSessionError:
        raise WebError(401, "Требуется вход.") from None
    except SQLAlchemyError:
        raise WebError(503, "Выход временно недоступен.") from None

    response = RedirectResponse(_external_path(request, "/login"), status_code=303)
    delete_secure_cookie(response, name=SESSION_COOKIE_NAME)
    delete_secure_cookie(response, name=CSRF_COOKIE_NAME)
    return response


def _form(
    request: Request,
    *,
    allowed: set[str],
    required: set[str],
) -> dict[str, str]:
    body = getattr(request.state, "bounded_form_body", None)
    if type(body) is not bytes:
        raise WebError(400, "Некорректная форма.")
    try:
        return parse_bounded_form(
            body,
            allowed_fields=allowed,
            required_fields=required,
            max_fields=len(allowed),
        )
    except BoundedFormError as error:
        raise WebError(error.status_code, "Некорректная форма.") from None


def _require_origin(request: Request, settings: Settings) -> None:
    try:
        require_exact_origin(request.scope, settings.web_public_origin)
    except OriginValidationError:
        _log_security_event(request, "dashboard_origin_rejected")
        raise WebError(403, "Запрос отклонён.") from None


def _settings(request: Request) -> Settings:
    settings = request.app.state.settings
    if not isinstance(settings, Settings):
        raise RuntimeError("dashboard settings are not configured")
    return settings


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unavailable"))


def _external_path(request: Request, path: str) -> str:
    root = request.scope.get("root_path", "").rstrip("/")
    return f"{root}{path}"


def _error_response(request: Request, status_code: int, detail: str) -> HTMLResponse:
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name=f"errors/{status_code}.html",
            context={"detail": detail, "request_id": _request_id(request)},
            status_code=status_code,
        ),
    )


def _log_security_event(request: Request, event: str, *, scope: str | None = None) -> None:
    limiter = cast(FixedWindowRateLimiter, request.app.state.security_log_limiter)
    if limiter.consume(event) is None:
        suffix = "" if scope is None else f" limiter_scope={scope}"
        logger.warning(
            "request_id=%s security_event=%s%s",
            _request_id(request),
            event,
            suffix,
        )
