from __future__ import annotations

from pathlib import Path

import pytest
from playwright.sync_api import BrowserContext, Page

from tests.browser.guards import (
    PageRequestGuard,
    assert_secret_absent,
    audit_browser_artifacts,
    review_screenshots_enabled,
)
from tests.browser.harness import BrowserEnvironment
from tests.browser.synthetic_data import BrowserSeed
from tests.browser.test_workflows import _login

pytestmark = [pytest.mark.browser, pytest.mark.docker]


def test_operator_credentials_do_not_enter_logs_or_default_artifacts(
    browser_page: tuple[BrowserContext, Page, PageRequestGuard],
    browser_environment: BrowserEnvironment,
    browser_seed: BrowserSeed,
    browser_artifact_root: Path,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _, page, guard = browser_page
    _login(page, browser_environment.origin, browser_seed.analyst)
    page.get_by_role("button", name="Выйти").click()
    guard.assert_clean()

    captured = capfd.readouterr()
    values = [captured.out, captured.err, *(record.getMessage() for record in caplog.records)]
    if browser_environment.application is not None:
        values.extend(browser_environment.application.logs)
    for secret in browser_seed.secrets:
        assert_secret_absent(secret, values)
    audit_browser_artifacts(browser_artifact_root, browser_seed.secrets)
    if not review_screenshots_enabled() and any(browser_artifact_root.rglob("*.png")):
        raise AssertionError("default browser run created a screenshot") from None


def test_no_trace_video_har_or_storage_state_is_configured(project_root: Path) -> None:
    browser_sources = (project_root / "tests" / "browser" / "conftest.py").read_text(
        encoding="utf-8"
    )
    forbidden_configuration = (
        "record_har_path=",
        "record_video_dir=",
        "storage_state=",
        ".start_chunk(",
        ".tracing.start(",
    )
    for value in forbidden_configuration:
        if value in browser_sources:
            raise AssertionError("browser suite enabled a forbidden artifact channel") from None
