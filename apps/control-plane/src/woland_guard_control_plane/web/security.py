"""Dashboard Origin, cookie and response-header security policy."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from email.utils import format_datetime
from urllib.parse import urlsplit

from starlette.datastructures import MutableHeaders
from starlette.responses import Response
from starlette.types import Message, Receive, Scope, Send

SESSION_COOKIE_NAME = "__Host-wg_session"
CSRF_COOKIE_NAME = "__Host-wg_csrf"
CSRF_FORM_FIELD = "_csrf"
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    ),
}
_UNEXPECTED_ERROR_LOGGED = "wg_unexpected_error_logged"
logger = logging.getLogger("uvicorn.error")


class OriginValidationError(ValueError):
    """Safe failure for missing, duplicated, or cross-origin mutation requests."""


class DashboardSecurityHeadersMiddleware:
    """Apply one policy to every response emitted by the mounted Dashboard app."""

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        *,
        enable_hsts: bool,
    ) -> None:
        self.app = app
        self._enable_hsts = enable_hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        response_started = False
        response_complete = False

        async def secure_send(message: Message) -> None:
            nonlocal response_complete, response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if self._enable_hsts:
                    headers["Strict-Transport-Security"] = "max-age=31536000"
            elif message["type"] == "http.response.body" and not message.get(
                "more_body",
                False,
            ):
                response_complete = True
            await send(message)

        try:
            await self.app(scope, receive, secure_send)
        except Exception:
            if not response_started:
                raise
            log_unexpected_dashboard_error(scope)
            if not response_complete:
                await send({"type": "http.response.body", "body": b"", "more_body": False})


def log_unexpected_dashboard_error(scope: Scope) -> None:
    """Emit one static unexpected-error event without the exception object."""

    state = scope.setdefault("state", {})
    if state.get(_UNEXPECTED_ERROR_LOGGED, False):
        return
    logger.error(
        "request_id=%s event=dashboard_unexpected_error",
        str(state.get("request_id", "unavailable")),
    )
    state[_UNEXPECTED_ERROR_LOGGED] = True


def require_exact_origin(scope: Scope, expected_origin: str) -> None:
    """Require one exact configured Origin without trusting forwarded headers."""

    origins = [value for name, value in scope.get("headers", []) if name.lower() == b"origin"]
    if len(origins) != 1:
        raise OriginValidationError("request origin is not allowed")
    try:
        supplied = origins[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise OriginValidationError("request origin is not allowed") from error
    expected = expected_origin.rstrip("/")
    parsed = urlsplit(supplied)
    if (
        supplied == "null"
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or supplied.rstrip("/") != expected
    ):
        raise OriginValidationError("request origin is not allowed")


def set_secure_cookie(response: Response, *, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def delete_secure_cookie(response: Response, *, name: str) -> None:
    response.set_cookie(
        key=name,
        value="",
        max_age=0,
        expires=format_datetime(datetime(1970, 1, 1, tzinfo=UTC), usegmt=True),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
