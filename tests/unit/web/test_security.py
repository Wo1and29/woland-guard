"""Dashboard response-header, Origin, cookie and template security tests."""

import asyncio
import logging
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import HTMLResponse
from starlette.types import Message, Receive, Scope, Send

from woland_guard_control_plane.api.middleware import RequestIdMiddleware
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.web.app import create_dashboard_app
from woland_guard_control_plane.web.security import (
    SECURITY_HEADERS,
    DashboardSecurityHeadersMiddleware,
    OriginValidationError,
    delete_secure_cookie,
    require_exact_origin,
)


@pytest.mark.parametrize("status", [200, 303, 400, 401, 403, 413, 422, 500, 503])
def test_security_headers_cover_every_dashboard_response_status(status: int) -> None:
    app = FastAPI()

    @app.get("/test")
    def endpoint() -> HTMLResponse:
        return HTMLResponse("safe", status_code=status)

    app.add_middleware(DashboardSecurityHeadersMiddleware, enable_hsts=False)
    with TestClient(app, raise_server_exceptions=False) as client:
        result = client.get("/test", follow_redirects=False)

    for name, value in SECURITY_HEADERS.items():
        assert result.headers[name] == value
    assert "strict-transport-security" not in result.headers


def test_origin_is_exact_and_does_not_use_forwarded_headers() -> None:
    require_exact_origin(
        {
            "type": "http",
            "headers": [
                (b"origin", b"https://dashboard.invalid"),
                (b"x-forwarded-host", b"attacker.invalid"),
            ],
        },
        "https://dashboard.invalid",
    )
    with pytest.raises(OriginValidationError):
        require_exact_origin(
            {"type": "http", "headers": [(b"origin", b"https://attacker.invalid")]},
            "https://dashboard.invalid",
        )


def test_cookie_deletion_uses_host_cookie_attributes() -> None:
    response = HTMLResponse("safe")
    delete_secure_cookie(response, name="__Host-wg_session")
    header = response.headers["set-cookie"]

    assert "Max-Age=0" in header
    assert "expires=" in header.casefold()
    assert "Path=/" in header
    assert "HttpOnly" in header
    assert "SameSite=strict" in header
    assert "Secure" in header
    assert "Domain=" not in header


def test_templates_have_no_inline_or_external_resources() -> None:
    root = (
        Path(__file__).parents[3]
        / "apps/control-plane/src/woland_guard_control_plane/web/templates"
    )
    documents = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.html"))
    lowered = documents.casefold()

    assert "<script" not in lowered
    assert "<style" not in lowered
    assert " style=" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered


def test_unexpected_error_uses_one_safe_handler_and_keeps_security_headers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "canary-session-cookie-secret"
    dashboard = create_dashboard_app(
        Settings(app_env="test", web_public_origin="https://localhost:8000")
    )
    assert isinstance(dashboard.app, FastAPI)

    @dashboard.app.get("/synthetic-error")
    def synthetic_error() -> None:
        raise RuntimeError(canary)

    wrapped = RequestIdMiddleware(dashboard)
    with caplog.at_level(logging.ERROR, logger="uvicorn.error"):
        with TestClient(
            wrapped,
            base_url="https://localhost:8000",
            raise_server_exceptions=True,
        ) as client:
            response = client.get("/synthetic-error")

    assert response.status_code == 500
    request_id = response.headers["x-request-id"]
    assert request_id in response.text
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    messages = [record.getMessage() for record in caplog.records]
    error_events = [message for message in messages if "unexpected_error" in message]
    assert error_events == [f"request_id={request_id} event=dashboard_unexpected_error"]
    assert canary not in response.text
    assert all(canary not in message for message in messages)


def test_exception_after_response_start_never_emits_a_second_response() -> None:
    sent: list[Message] = []

    async def started_app(_scope: Scope, _receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            }
        )
        await send({"type": "http.response.body", "body": b"safe", "more_body": True})
        raise RuntimeError("synthetic post-start failure")

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    async def exercise() -> None:
        middleware = DashboardSecurityHeadersMiddleware(started_app, enable_hsts=False)
        await middleware(
            {
                "type": "http",
                "method": "GET",
                "path": "/synthetic",
                "headers": [],
                "state": {"request_id": "post-start-request"},
            },
            receive,
            send,
        )

    asyncio.run(exercise())
    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert len(starts) == 1
    assert sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    headers = dict(starts[0]["headers"])
    for name, value in SECURITY_HEADERS.items():
        assert headers[name.lower().encode("ascii")] == value.encode("ascii")
