"""Shared strict transport checks for unsafe Dashboard form routes."""

import logging
from collections.abc import Collection
from typing import cast

from fastapi import Request

from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    verify_csrf_tokens,
)
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.form_body import BoundedFormError, parse_bounded_form
from woland_guard_control_plane.web.i18n import current_language, t
from woland_guard_control_plane.web.security import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    OriginValidationError,
    require_exact_origin,
)

logger = logging.getLogger("uvicorn.error")


def parse_dashboard_mutation_form(
    request: Request,
    *,
    allowed_fields: Collection[str],
    required_fields: Collection[str],
) -> dict[str, str]:
    """Validate Origin, exact form schema and session-bound CSRF without state changes."""

    settings = request.app.state.settings
    if not isinstance(settings, Settings):
        raise RuntimeError("dashboard settings are not configured")
    try:
        require_exact_origin(request.scope, settings.web_public_origin)
    except OriginValidationError:
        _log_security_event(request, "dashboard_origin_rejected")
        raise WebError(403, t(current_language(request), "err.request_rejected")) from None
    body = getattr(request.state, "bounded_form_body", None)
    if type(body) is not bytes:
        raise WebError(400, t(current_language(request), "err.invalid_form"))
    try:
        return parse_bounded_form(
            body,
            allowed_fields=allowed_fields,
            required_fields=required_fields,
            max_fields=len(allowed_fields),
        )
    except BoundedFormError as error:
        raise WebError(
            error.status_code, t(current_language(request), "err.invalid_form")
        ) from None


def require_dashboard_csrf(
    request: Request,
    *,
    authenticated: AuthenticatedWebSession,
    form: dict[str, str],
) -> None:
    """Reject a form unless cookie, field and locked session digest agree."""

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    form_token = form.get(CSRF_FORM_FIELD, "")
    if not verify_csrf_tokens(
        cookie_token=cookie_token,
        form_token=form_token,
        expected_digest=authenticated.csrf_token_digest,
    ):
        _log_security_event(request, "dashboard_csrf_rejected")
        raise WebError(403, t(current_language(request), "err.request_rejected"))


def _log_security_event(request: Request, event: str) -> None:
    limiter = cast(FixedWindowRateLimiter, request.app.state.security_log_limiter)
    if limiter.consume(event) is None:
        logger.warning(
            "request_id=%s security_event=%s",
            str(getattr(request.state, "request_id", "unavailable")),
            event,
        )
