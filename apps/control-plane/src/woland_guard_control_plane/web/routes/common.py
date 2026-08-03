"""Shared safe HTML context and URL construction for Dashboard GET pages."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast
from urllib.parse import urlencode

from fastapi import Request
from starlette.responses import HTMLResponse

from woland_guard_control_plane.application.rbac import Permission, role_has_permission
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    verify_csrf_tokens,
)
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.i18n import current_language, t
from woland_guard_control_plane.web.security import CSRF_COOKIE_NAME

QueryValue = str | int | Sequence[str]


def current_url(request: Request) -> str:
    """The path the user is actually looking at, for post-toggle redirects."""

    suffix = f"?{request.url.query}" if request.url.query else ""
    return f"{request.url.path}{suffix}"


def dashboard_context(
    request: Request,
    authenticated: AuthenticatedWebSession,
    *,
    active_navigation: str,
) -> dict[str, Any]:
    """Build the shared shell only after validating the session-bound CSRF cookie."""

    csrf_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not verify_csrf_tokens(
        cookie_token=csrf_token,
        form_token=csrf_token,
        expected_digest=authenticated.csrf_token_digest,
    ):
        raise WebError(401, t(current_language(request), "err.reauth_required"))
    principal = authenticated.principal
    next_url = current_url(request)
    return {
        "active_navigation": active_navigation,
        "can_view_audit": role_has_permission(principal.role, Permission.VIEW_AUDIT_LOG),
        "csrf_token": csrf_token,
        "lang": current_language(request),
        "operator_role": principal.role.value,
        "operator_username": principal.username,
        "paths": {
            "audit": external_path(request, "/audit"),
            "home": external_path(request, "/"),
            "incidents": external_path(request, "/incidents"),
            "lang_en": page_url(request, "/lang/en", {"next": next_url}),
            "lang_ru": page_url(request, "/lang/ru", {"next": next_url}),
            "logout": external_path(request, "/logout"),
            "rules": external_path(request, "/rules"),
            "servers": external_path(request, "/servers"),
            "static_css": external_path(request, "/static/dashboard.css"),
        },
    }


def render_dashboard(
    request: Request,
    *,
    template: str,
    context: Mapping[str, Any],
    status_code: int = 200,
) -> HTMLResponse:
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name=template,
            context=dict(context),
            status_code=status_code,
        ),
    )


def external_path(request: Request, path: str) -> str:
    root = request.scope.get("root_path", "").rstrip("/")
    return f"{root}{path}"


def page_url(
    request: Request,
    path: str,
    parameters: Mapping[str, QueryValue | None],
) -> str:
    """Encode only normalized query values into a relative Dashboard URL."""

    pairs: list[tuple[str, str]] = []
    for name, value in parameters.items():
        if value is None:
            continue
        if isinstance(value, str | int):
            pairs.append((name, str(value)))
        else:
            pairs.extend((name, item) for item in value)
    query = urlencode(pairs)
    base = external_path(request, path)
    return base if not query else f"{base}?{query}"
