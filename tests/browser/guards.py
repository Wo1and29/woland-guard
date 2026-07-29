from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from playwright.sync_api import (
    BrowserContext,
    ConsoleMessage,
    Dialog,
    Page,
    Route,
    WebSocketRoute,
)
from playwright.sync_api import (
    Error as PlaywrightError,
)
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError


class BrowserOperationError(RuntimeError):
    """A static browser failure that never exposes Playwright call logs."""


@dataclass(frozen=True, slots=True)
class SecretValue:
    _value: str = field(repr=False)

    def reveal_for_browser_fill(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


class PageRequestGuard:
    def __init__(self, allowed_origin: str) -> None:
        parsed = urlsplit(allowed_origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise BrowserOperationError("browser origin is not one canonical loopback HTTPS origin")
        self._allowed = parsed
        self._violations: list[str] = []
        self._expected_http_console_errors = 0

    def install(self, context: BrowserContext) -> None:
        context.route("**/*", self._route_request)
        context.route_web_socket("**/*", self._route_web_socket)
        context.on("requestfailed", lambda _request: self._record("page_request_failed"))

    def attach_page(self, page: Page) -> None:
        page.on("console", self._console_message)
        page.on("pageerror", lambda _error: self._record("page_error"))
        page.on("dialog", self._dialog)

    def assert_clean(self) -> None:
        if self._violations:
            raise BrowserOperationError("browser page violated its safe execution boundary")

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(self._violations)

    def allow_expected_http_error_console(self) -> None:
        """Allow one Chromium resource-status console error for an asserted HTML error page."""

        self._expected_http_console_errors += 1

    def _route_request(self, route: Route) -> None:
        if self._is_allowed_http_url(route.request.url):
            route.continue_()
            return
        self._record("external_page_request_blocked")
        route.abort("blockedbyclient")

    def _route_web_socket(self, _web_socket: WebSocketRoute) -> None:
        self._record("page_websocket_blocked")

    def _is_allowed_http_url(self, value: str) -> bool:
        try:
            parsed = urlsplit(value)
            return _same_origin(parsed, self._allowed)
        except ValueError:
            return False

    def _console_message(self, message: ConsoleMessage) -> None:
        if message.type == "error":
            if self._expected_http_console_errors > 0:
                self._expected_http_console_errors -= 1
                return
            self._record("browser_console_error")

    def _dialog(self, dialog: Dialog) -> None:
        self._record("browser_dialog_opened")
        dialog.dismiss()

    def _record(self, category: str) -> None:
        self._violations.append(category)


def safe_browser_operation[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (PlaywrightError, PlaywrightTimeoutError):
        raise BrowserOperationError("browser operation failed") from None


def assert_secret_absent(secret: SecretValue, values: Iterable[str]) -> None:
    canary = secret.reveal_for_browser_fill()
    for value in values:
        if canary in value:
            raise AssertionError("credential canary was present in captured output") from None


def audit_browser_artifacts(root: Path, secrets: Iterable[SecretValue]) -> None:
    if not root.exists():
        return
    forbidden_suffixes = {".har", ".trace", ".webm", ".zip"}
    canaries = tuple(secret.reveal_for_browser_fill().encode("utf-8") for secret in secrets)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.casefold() in forbidden_suffixes:
            raise AssertionError("a forbidden browser artifact was created") from None
        size = path.stat().st_size
        if size > 2_000_000:
            raise AssertionError("an unexpected large browser artifact was created") from None
        content = path.read_bytes()
        if any(canary in content for canary in canaries):
            raise AssertionError("credential canary was present in browser artifacts") from None


def review_screenshots_enabled() -> bool:
    return os.environ.get("WG_BROWSER_REVIEW_SCREENSHOTS") == "1"


def _same_origin(candidate: SplitResult, allowed: SplitResult) -> bool:
    if candidate.scheme not in {"http", "https"}:
        return False
    return (
        candidate.scheme == allowed.scheme
        and candidate.hostname == allowed.hostname
        and candidate.port == allowed.port
        and candidate.username is None
        and candidate.password is None
    )
