from __future__ import annotations

from pathlib import Path

import pytest
from playwright.sync_api import Browser, BrowserContext, Page

from tests.browser.guards import (
    PageRequestGuard,
    review_screenshots_enabled,
    safe_browser_operation,
)
from tests.browser.harness import BrowserEnvironment
from tests.browser.synthetic_data import BrowserSeed
from tests.browser.test_workflows import _login

pytestmark = [pytest.mark.browser, pytest.mark.docker]

DESKTOP_VIEWPORTS = ((1440, 900), (1024, 768), (769, 900))
MOBILE_VIEWPORTS = ((767, 900), (390, 844), (360, 800))


def test_dashboard_has_no_document_overflow_across_viewports(
    chromium_browser: Browser,
    browser_environment: BrowserEnvironment,
    browser_seed: BrowserSeed,
    browser_artifact_root: Path,
    browser_security_audit: None,
) -> None:
    del browser_security_audit
    for width, height in (*DESKTOP_VIEWPORTS, *MOBILE_VIEWPORTS):
        context, page, guard = _guarded_page(
            chromium_browser,
            browser_environment.origin,
            width=width,
            height=height,
        )
        try:
            _login(page, browser_environment.origin, browser_seed.analyst)
            paths = (
                "/dashboard/",
                "/dashboard/servers",
                "/dashboard/incidents",
                f"/dashboard/incidents/{browser_seed.primary_incident_id}",
                "/dashboard/rules",
            )
            for path in paths:
                page.goto(f"{browser_environment.origin}{path}")
                _assert_page_semantics_and_overflow(page)
            if review_screenshots_enabled() and (width, height) in {(1440, 900), (390, 844)}:
                directory = browser_artifact_root / "screenshots"
                directory.mkdir(mode=0o700, exist_ok=True)
                name = "desktop-overview.png" if width == 1440 else "mobile-incident.png"
                target = directory / name
                if width == 1440:
                    page.goto(f"{browser_environment.origin}/dashboard/")
                else:
                    page.goto(
                        f"{browser_environment.origin}/dashboard/incidents/"
                        f"{browser_seed.primary_incident_id}"
                    )
                page.screenshot(path=target, full_page=True)
            guard.assert_clean()
        finally:
            context.close()


def test_admin_audit_is_responsive_and_semantic(
    chromium_browser: Browser,
    browser_environment: BrowserEnvironment,
    browser_seed: BrowserSeed,
    browser_security_audit: None,
) -> None:
    del browser_security_audit
    for width, height in ((1440, 900), (390, 844)):
        context, page, guard = _guarded_page(
            chromium_browser,
            browser_environment.origin,
            width=width,
            height=height,
        )
        try:
            _login(page, browser_environment.origin, browser_seed.admin)
            page.goto(f"{browser_environment.origin}/dashboard/audit")
            _assert_page_semantics_and_overflow(page)
            assert page.locator("table caption").inner_text() == "Audit log"
            guard.assert_clean()
        finally:
            context.close()


def test_keyboard_only_login_mutations_and_logout(
    browser_page: tuple[BrowserContext, Page, PageRequestGuard],
    browser_environment: BrowserEnvironment,
    browser_seed: BrowserSeed,
) -> None:
    _, page, guard = browser_page
    page.goto(f"{browser_environment.origin}/dashboard/login")
    page.keyboard.press("Tab")
    assert page.evaluate("() => document.activeElement?.id") == "credential"
    _assert_visible_focus(page)
    safe_browser_operation(
        lambda: page.keyboard.insert_text(browser_seed.analyst.token.reveal_for_browser_fill())
    )
    page.keyboard.press("Tab")
    assert page.evaluate("() => document.activeElement?.textContent?.trim()") == "Войти"
    page.keyboard.press("Enter")
    page.wait_for_url(f"{browser_environment.origin}/dashboard/")

    page.keyboard.press("Tab")
    assert page.evaluate("() => document.activeElement?.classList.contains('skip-link')") is True
    _assert_visible_focus(page)
    page.keyboard.press("Enter")
    assert page.evaluate("() => document.activeElement?.id") == "dashboard-content"

    page.goto(
        f"{browser_environment.origin}/dashboard/incidents/{browser_seed.secondary_incident_id}"
    )
    _tab_until(page, selector='select[name="status"]')
    _assert_visible_focus(page)
    _tab_until(page, selector='button[type="submit"]', text="Изменить статус")
    page.keyboard.press("Enter")
    page.wait_for_url(f"{browser_environment.origin}/dashboard/incidents/*")

    _tab_until(page, selector='textarea[name="comment"]')
    _assert_visible_focus(page)
    page.keyboard.insert_text("Keyboard-only synthetic comment")
    _tab_until(page, selector='button[type="submit"]', text="Сохранить комментарий")
    page.keyboard.press("Enter")
    page.wait_for_url(f"{browser_environment.origin}/dashboard/incidents/*")
    assert "Keyboard-only synthetic comment" in page.locator("body").inner_text()

    _tab_until(page, selector='button[type="submit"]', text="Выйти")
    page.keyboard.press("Enter")
    page.wait_for_url(f"{browser_environment.origin}/dashboard/login")
    assert page.get_by_role("heading", name="Вход оператора").count() == 1
    guard.assert_clean()


def _guarded_page(
    browser: Browser,
    origin: str,
    *,
    width: int,
    height: int,
) -> tuple[BrowserContext, Page, PageRequestGuard]:
    context = browser.new_context(
        accept_downloads=False,
        ignore_https_errors=True,
        service_workers="block",
        viewport={"width": width, "height": height},
    )
    context.set_default_timeout(5_000)
    context.set_default_navigation_timeout(10_000)
    guard = PageRequestGuard(origin)
    guard.install(context)
    page = context.new_page()
    guard.attach_page(page)
    return context, page, guard


def _assert_page_semantics_and_overflow(page: Page) -> None:
    assert page.get_by_role("heading", level=1).count() == 1
    assert page.locator("main").count() == 1
    assert page.get_by_role("navigation", name="Основная навигация").count() == 1
    assert page.evaluate(
        "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"
    )
    for wrapper in page.locator(".table-wrap").all():
        box = wrapper.bounding_box()
        assert box is not None
        viewport_width = page.viewport_size["width"] if page.viewport_size else 0
        assert box["x"] >= -1
        assert box["x"] + box["width"] <= viewport_width + 1
        assert wrapper.get_attribute("tabindex") == "0"
        assert wrapper.get_attribute("aria-label")
    for table in page.locator("table").all():
        assert table.locator("caption").count() == 1
        assert all(
            value == "col"
            for value in table.locator("thead th").evaluate_all(
                "elements => elements.map(element => element.getAttribute('scope'))"
            )
        )
    foreground, background = page.evaluate(
        """() => {
          const style = getComputedStyle(document.body);
          return [style.color, style.backgroundColor];
        }"""
    )
    assert _contrast_ratio(_rgb(foreground), _rgb(background)) >= 4.5


def _tab_until(page: Page, *, selector: str, text: str | None = None) -> None:
    for _ in range(40):
        page.keyboard.press("Tab")
        active = page.locator(":focus")
        if active.count() != 1 or not active.evaluate(
            "(element, selector) => element.matches(selector)", selector
        ):
            continue
        if text is None or active.inner_text().strip() == text:
            return
    raise AssertionError("keyboard focus did not reach the expected control") from None


def _assert_visible_focus(page: Page) -> None:
    width = page.locator(":focus").evaluate("element => getComputedStyle(element).outlineWidth")
    if width in {"0px", ""}:
        raise AssertionError("keyboard focus indicator was not visible") from None


def _rgb(value: str) -> tuple[int, int, int]:
    if not value.startswith("rgb(") or not value.endswith(")"):
        raise AssertionError("browser returned a non-opaque computed color") from None
    parts = value.removeprefix("rgb(").removesuffix(")").replace(",", " ").split()
    channels = tuple(int(part.strip()) for part in parts)
    if len(channels) != 3:
        raise AssertionError("browser returned an invalid computed color") from None
    return channels


def _contrast_ratio(foreground: tuple[int, int, int], background: tuple[int, int, int]) -> float:
    bright = max(_luminance(foreground), _luminance(background))
    dark = min(_luminance(foreground), _luminance(background))
    return (bright + 0.05) / (dark + 0.05)


def _luminance(color: tuple[int, int, int]) -> float:
    channels = []
    for value in color:
        normalized = value / 255
        channels.append(
            normalized / 12.92 if normalized <= 0.04045 else ((normalized + 0.055) / 1.055) ** 2.4
        )
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
