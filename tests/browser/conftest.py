from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

from tests.browser.guards import (
    BrowserOperationError,
    PageRequestGuard,
    audit_browser_artifacts,
    safe_browser_operation,
)
from tests.browser.harness import BrowserEnvironment, BrowserHarnessError
from tests.browser.synthetic_data import BrowserSeed, seed_browser_database

_RUN_BROWSER_ENV = "WG_RUN_BROWSER_TESTS"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if os.environ.get(_RUN_BROWSER_ENV) == "1":
        return
    skip = pytest.mark.skip(reason=f"set {_RUN_BROWSER_ENV}=1 to run browser tests")
    for item in items:
        if item.get_closest_marker("browser") is not None:
            item.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def enforce_browser_run_safety(request: pytest.FixtureRequest) -> None:
    if os.environ.get(_RUN_BROWSER_ENV) != "1":
        return
    if bool(request.config.getoption("showlocals", default=False)):
        pytest.exit("browser tests refuse pytest local-variable output")
    if os.environ.get("PWDEBUG"):
        pytest.exit("browser tests refuse Playwright debug mode")
    if "pw:api" in os.environ.get("DEBUG", "").casefold():
        pytest.exit("browser tests refuse Playwright API debug logging")

    project_root = Path(__file__).resolve().parents[2]
    expected = (project_root / ".playwright-browsers").resolve()
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if configured is None or Path(configured).resolve() != expected:
        pytest.exit("browser cache must use the project-local ignored directory")


@pytest.fixture(scope="session")
def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def browser_artifact_root(project_root: Path) -> Iterator[Path]:
    root = project_root / ".pytest-browser"
    if root.exists() and any(root.iterdir()):
        pytest.exit("browser artifact directory must be empty before the test run")
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    try:
        yield root
    finally:
        if root.exists() and not any(root.iterdir()):
            root.rmdir()


@pytest.fixture(scope="session")
def browser_environment(project_root: Path) -> Iterator[BrowserEnvironment]:
    environment = BrowserEnvironment(project_root)
    try:
        yield environment.start()
    finally:
        environment.stop()


@pytest.fixture(scope="session")
def browser_seed(
    browser_environment: BrowserEnvironment,
    project_root: Path,
) -> Iterator[BrowserSeed]:
    seed = seed_browser_database(
        browser_environment.postgres.session_factory,
        project_root=project_root,
    )
    try:
        yield seed
    finally:
        del seed


@pytest.fixture(scope="session")
def chromium_browser() -> Iterator[Browser]:
    playwright = sync_playwright().start()
    browser: Browser | None = None
    cleanup_failed = False
    try:
        browser = safe_browser_operation(
            lambda: playwright.chromium.launch(channel="chromium", headless=True)
        )
        yield browser
    finally:
        if browser is not None:
            try:
                safe_browser_operation(browser.close)
            except BrowserOperationError:
                cleanup_failed = True
        try:
            playwright.stop()
        except Exception:
            cleanup_failed = True
        if cleanup_failed:
            raise BrowserHarnessError("browser runtime cleanup failed") from None


@pytest.fixture
def browser_page(
    chromium_browser: Browser,
    browser_environment: BrowserEnvironment,
    browser_security_audit: None,
) -> Iterator[tuple[BrowserContext, Page, PageRequestGuard]]:
    del browser_security_audit
    context = safe_browser_operation(
        lambda: chromium_browser.new_context(
            accept_downloads=False,
            ignore_https_errors=True,
            service_workers="block",
            viewport={"width": 1440, "height": 900},
        )
    )
    try:
        context.set_default_timeout(5_000)
        context.set_default_navigation_timeout(10_000)
        guard = PageRequestGuard(browser_environment.origin)
        guard.install(context)
        page = safe_browser_operation(context.new_page)
        guard.attach_page(page)
        try:
            yield context, page, guard
        finally:
            guard.assert_clean()
    finally:
        safe_browser_operation(context.close)


@pytest.fixture(scope="session")
def browser_security_audit(
    browser_artifact_root: Path,
    browser_seed: BrowserSeed,
) -> Iterator[None]:
    try:
        yield
    finally:
        audit_browser_artifacts(browser_artifact_root, browser_seed.secrets)
