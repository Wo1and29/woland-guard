from __future__ import annotations

import http.client
import ssl
from pathlib import Path

import pytest
from playwright.sync_api import Browser
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse
from starlette.routing import Route

from tests.browser.harness import BrowserEnvironment, LocalHttpsServer


async def readiness(_: Request) -> PlainTextResponse:
    return PlainTextResponse("ready")


def _origin_probe_application(observed: list[str | None]) -> Starlette:
    async def form(request: Request) -> HTMLResponse:
        policy = request.path_params["policy"]
        headers = {"Referrer-Policy": "no-referrer"} if policy == "none" else {}
        return HTMLResponse(
            '<form method="post" action="/submit"><button>submit</button></form>',
            headers=headers,
        )

    async def submit(request: Request) -> PlainTextResponse:
        observed.append(request.headers.get("origin"))
        return PlainTextResponse("submitted")

    return Starlette(
        routes=[
            Route("/form/{policy}", form),
            Route("/submit", submit, methods=["POST"]),
        ]
    )


@pytest.mark.browser
def test_prebound_socket_serves_tls_and_shuts_down_cooperatively(
    chromium_browser: Browser,
) -> None:
    application = Starlette(routes=[Route("/ready", readiness)])
    harness = LocalHttpsServer(application, readiness_path="/ready")

    with harness:
        strict_context = ssl.create_default_context(cafile=str(harness.ca_path))
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            harness.port,
            context=strict_context,
            timeout=2,
        )
        try:
            connection.request("GET", "/ready")
            strict_response = connection.getresponse()
            assert strict_response.status == 200
        finally:
            connection.close()

        context = chromium_browser.new_context(
            accept_downloads=False,
            ignore_https_errors=True,
            service_workers="block",
        )
        try:
            page = context.new_page()
            browser_response = page.goto(f"{harness.origin}/ready")
            assert browser_response is not None
            assert browser_response.status == 200
            assert page.text_content("body") == "ready"
        finally:
            context.close()


@pytest.mark.browser
@pytest.mark.docker
def test_real_application_process_uses_isolated_https_and_postgresql(
    chromium_browser: Browser,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    with BrowserEnvironment(project_root) as environment:
        context = chromium_browser.new_context(
            accept_downloads=False,
            ignore_https_errors=True,
            service_workers="block",
        )
        try:
            page = context.new_page()
            response = page.goto(f"{environment.origin}/dashboard/login")
            assert response is not None
            assert response.status == 200
            assert page.get_by_role("heading", name="Вход оператора").count() == 1
        finally:
            context.close()


@pytest.mark.browser
def test_origin_probe_distinguishes_tls_from_referrer_policy(
    chromium_browser: Browser,
) -> None:
    observed: list[str | None] = []
    harness = LocalHttpsServer(_origin_probe_application(observed), readiness_path="/form/default")
    with harness:
        origin = harness.origin
        context = chromium_browser.new_context(ignore_https_errors=True)
        try:
            page = context.new_page()
            page.goto(f"{harness.origin}/form/default")
            page.get_by_role("button", name="submit").click()
            page.wait_for_url(f"{harness.origin}/submit")
            page.goto(f"{harness.origin}/form/none")
            page.get_by_role("button", name="submit").click()
            page.wait_for_url(f"{harness.origin}/submit")
        finally:
            context.close()
    assert observed == [origin, "null"]
