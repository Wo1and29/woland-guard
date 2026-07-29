from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest
from playwright.sync_api import Browser, BrowserContext, Page
from sqlalchemy import delete

from tests.browser.guards import BrowserOperationError, PageRequestGuard, safe_browser_operation
from tests.browser.harness import BrowserEnvironment
from tests.browser.synthetic_data import BrowserSeed
from tests.browser.test_workflows import _login
from woland_guard_control_plane.infrastructure.database.models import DetectionRuleVersion
from woland_guard_control_plane.web.security import SECURITY_HEADERS

pytestmark = [pytest.mark.browser, pytest.mark.docker]


def test_keyset_next_page_has_no_duplicates_and_reset_preserves_filters(
    browser_page: tuple[BrowserContext, Page, PageRequestGuard],
    browser_environment: BrowserEnvironment,
    browser_seed: BrowserSeed,
) -> None:
    _, page, guard = browser_page
    _login(page, browser_environment.origin, browser_seed.analyst)
    page.get_by_role("link", name="Серверы").click()
    page.get_by_label("Префикс имени или hostname").fill("browser-server")
    page.get_by_label("Состояние").select_option("active")
    page.get_by_label("Сортировка").select_option("name_asc")
    page.get_by_label("Размер").select_option("25")
    page.get_by_role("button", name="Применить").click()

    first_page = set(page.locator(".card-grid article h2 a").all_inner_texts())
    assert len(first_page) == 25
    next_link = page.get_by_role("link", name="Следующая страница")
    query = parse_qs(urlsplit(next_link.get_attribute("href") or "").query)
    assert query.get("q") == ["browser-server"]
    assert query.get("state") == ["active"]
    assert query.get("sort") == ["name_asc"]
    assert query.get("page_size") == ["25"]
    assert "cursor" in query

    next_link.click()
    second_page = set(page.locator(".card-grid article h2 a").all_inner_texts())
    assert len(second_page) == 4
    assert first_page.isdisjoint(second_page)

    reset_link = page.get_by_role("link", name="К началу")
    reset_query = parse_qs(urlsplit(reset_link.get_attribute("href") or "").query)
    assert "cursor" not in reset_query
    assert reset_query.get("q") == ["browser-server"]
    assert reset_query.get("state") == ["active"]
    assert reset_query.get("sort") == ["name_asc"]
    reset_link.click()
    assert set(page.locator(".card-grid article h2 a").all_inner_texts()) == first_page
    guard.assert_clean()


def test_dashboard_error_pages_remain_safe_html(
    browser_page: tuple[BrowserContext, Page, PageRequestGuard],
    browser_environment: BrowserEnvironment,
    browser_seed: BrowserSeed,
) -> None:
    _, page, guard = browser_page
    _login(page, browser_environment.origin, browser_seed.analyst)
    unsafe_values = (
        browser_seed.xss_canary,
        "synthetic reason must not reflect",
        "synthetic csrf must not reflect",
        "synthetic idempotency must not reflect",
        "synthetic exception must not reflect",
    )

    guard.allow_expected_http_error_console()
    not_found = page.goto(f"{browser_environment.origin}/dashboard/incidents/{uuid4()}")
    _assert_error_page(not_found, page, 404, unsafe_values)

    guard.allow_expected_http_error_console()
    method_not_allowed = page.goto(
        f"{browser_environment.origin}/dashboard/incidents/"
        f"{browser_seed.primary_incident_id}/comments"
    )
    _assert_error_page(method_not_allowed, page, 405, unsafe_values)

    guard.allow_expected_http_error_console()
    validation = page.goto(f"{browser_environment.origin}/dashboard/incidents?q=")
    _assert_error_page(validation, page, 422, unsafe_values)

    row_id, canary = _insert_corrupt_rule(browser_environment)
    try:
        guard.allow_expected_http_error_console()
        unavailable = page.goto(f"{browser_environment.origin}/dashboard/rules")
        _assert_error_page(unavailable, page, 503, (*unsafe_values, canary))
    finally:
        with browser_environment.postgres.session_factory.begin() as session:
            session.execute(delete(DetectionRuleVersion).where(DetectionRuleVersion.id == row_id))
    guard.assert_clean()


def test_http_and_websocket_guards_block_page_connections(
    chromium_browser: Browser,
    browser_environment: BrowserEnvironment,
) -> None:
    context = chromium_browser.new_context(
        accept_downloads=False,
        ignore_https_errors=True,
        service_workers="block",
    )
    guard = PageRequestGuard(browser_environment.origin)
    guard.install(context)
    page = context.new_page()
    guard.attach_page(page)
    try:
        page.goto(f"{browser_environment.origin}/dashboard/login")
        page.evaluate("() => { new WebSocket('wss://external.invalid/socket'); }")
        page.wait_for_timeout(50)
        assert "page_websocket_blocked" in guard.categories

        with pytest.raises(BrowserOperationError, match="browser operation failed"):
            safe_browser_operation(lambda: page.goto("https://external.invalid/"))
        assert "external_page_request_blocked" in guard.categories
    finally:
        context.close()


def _assert_error_page(
    response: object,
    page: Page,
    status: int,
    unsafe_values: tuple[str, ...],
) -> None:
    if response is None or response.status != status:  # type: ignore[attr-defined]
        raise AssertionError("Dashboard returned an unexpected error status") from None
    assert page.get_by_role("heading", name=f"Ошибка {status}").count() == 1
    assert page.locator("main").count() == 1
    body = page.locator("body").inner_text()
    assert "Request ID:" in body
    for value in unsafe_values:
        if value in body:
            raise AssertionError("Dashboard error page reflected unsafe input") from None
    headers = response.headers  # type: ignore[attr-defined]
    for name, value in SECURITY_HEADERS.items():
        assert headers[name.casefold()] == value
    assert headers["x-request-id"] in body


def _insert_corrupt_rule(environment: BrowserEnvironment) -> tuple[UUID, str]:
    row_id = uuid4()
    canary = "browser-corrupt-rule-canary"
    with environment.postgres.session_factory.begin() as session:
        session.add(
            DetectionRuleVersion(
                id=row_id,
                rule_key=f"browser_corrupt_{row_id.hex[:8]}",
                version=1,
                schema_version=1,
                enabled=True,
                severity="high",
                checksum="f" * 64,
                definition={"unsafe": canary},
                is_active=True,
                activated_at=datetime.now(UTC),
            )
        )
    return row_id, canary
