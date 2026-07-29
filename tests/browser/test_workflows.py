from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from playwright.sync_api import BrowserContext, Page
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from tests.browser.guards import (
    PageRequestGuard,
    assert_secret_absent,
    safe_browser_operation,
)
from tests.browser.harness import BrowserEnvironment
from tests.browser.synthetic_data import BrowserOperator, BrowserSeed
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    Incident,
    IncidentComment,
    IncidentHistoryEntry,
    OperatorIdempotencyRecord,
    OutboxMessage,
)

pytestmark = [pytest.mark.browser, pytest.mark.docker]


@dataclass(frozen=True, slots=True)
class MutationCounts:
    history: int
    comments: int
    status_audit: int
    comment_audit: int
    idempotency: int
    outbox: int


def test_complete_analyst_admin_and_viewer_workflow(
    browser_page: tuple[BrowserContext, Page, PageRequestGuard],
    browser_environment: BrowserEnvironment,
    browser_seed: BrowserSeed,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    context, page, guard = browser_page
    responses: list[tuple[str, str, int]] = []
    page.on("response", lambda response: _record_response(response, responses))

    _login(page, browser_environment.origin, browser_seed.analyst)
    _assert_session_cookie_policy(context)
    assert page.get_by_role("heading", name="Обзор").count() == 1

    page.get_by_role("link", name="Серверы").click()
    assert page.get_by_role("heading", name="Серверы").count() == 1
    page.get_by_role("link", name=browser_seed.primary_server_name).click()
    assert page.get_by_role("heading", name=browser_seed.primary_server_name).count() == 1

    page.get_by_role("link", name="Инциденты").click()
    page.get_by_label("Префикс title/rule key").fill("Browser synthetic")
    page.get_by_label("Точный incident UUID").fill(str(browser_seed.primary_incident_id))
    page.get_by_label("Точный server UUID").fill(str(browser_seed.primary_server_id))
    page.get_by_label("Rule key", exact=True).fill(browser_seed.rule_key)
    page.get_by_role("button", name="Применить").click()
    primary_title = "Browser synthetic incident 00"
    page.get_by_role("link", name=primary_title).click()
    assert page.get_by_role("heading", name=primary_title).count() == 1

    counts_before = _mutation_counts(
        browser_environment.postgres.session_factory,
        browser_seed.primary_incident_id,
    )
    responses.clear()
    page.get_by_label("Новый статус").select_option("investigating")
    page.get_by_role("button", name="Изменить статус").click()
    page.wait_for_url(f"{browser_environment.origin}/dashboard/incidents/*")
    _assert_prg(responses, suffix="/transitions")
    assert "new → investigating" in page.locator("body").inner_text()

    comment_key = page.locator(
        'form[action$="/comments"] input[name="idempotency_key"]'
    ).input_value()
    responses.clear()
    page.get_by_label("Комментарий").fill(browser_seed.xss_canary)
    page.get_by_role("button", name="Сохранить комментарий").click()
    page.wait_for_url(f"{browser_environment.origin}/dashboard/incidents/*")
    _assert_prg(responses, suffix="/comments")
    assert page.locator(".comment-body").last.text_content() == browser_seed.xss_canary
    assert page.locator(".comment-body img").count() == 0
    assert page.evaluate("() => window.wgCanary ?? null") is None

    counts_after_mutations = _mutation_counts(
        browser_environment.postgres.session_factory,
        browser_seed.primary_incident_id,
    )
    assert counts_after_mutations.history == counts_before.history + 1
    assert counts_after_mutations.comments == counts_before.comments + 1
    assert counts_after_mutations.status_audit == counts_before.status_audit + 1
    assert counts_after_mutations.comment_audit == counts_before.comment_audit + 1
    assert counts_after_mutations.idempotency == counts_before.idempotency + 2
    assert counts_after_mutations.outbox == counts_before.outbox

    page.reload()
    assert (
        _mutation_counts(
            browser_environment.postgres.session_factory,
            browser_seed.primary_incident_id,
        )
        == counts_after_mutations
    )

    page.get_by_label("Комментарий").fill("Different synthetic comment")
    page.locator('form[action$="/comments"] input[name="idempotency_key"]').evaluate(
        "(element, value) => { element.value = value; }",
        comment_key,
    )
    responses.clear()
    guard.allow_expected_http_error_console()
    page.get_by_role("button", name="Сохранить комментарий").click()
    assert page.get_by_role("heading", name="Ошибка 409").count() == 1
    assert _last_mutation_status(responses) == 409
    assert browser_seed.xss_canary not in page.locator("body").inner_text()
    assert (
        _mutation_counts(
            browser_environment.postgres.session_factory,
            browser_seed.primary_incident_id,
        )
        == counts_after_mutations
    )

    page.goto(
        f"{browser_environment.origin}/dashboard/incidents/{browser_seed.primary_incident_id}"
    )
    session_value = _session_cookie_value(context)
    page.get_by_role("button", name="Выйти").click()
    assert page.get_by_role("heading", name="Вход оператора").count() == 1
    assert "__Host-wg_session" not in _cookie_names(context)

    context.add_cookies(
        [
            {
                "name": "__Host-wg_session",
                "value": session_value,
                "url": browser_environment.origin,
            }
        ]
    )
    guard.allow_expected_http_error_console()
    invalidated = page.goto(f"{browser_environment.origin}/dashboard/")
    assert invalidated is not None and invalidated.status == 401
    context.clear_cookies()

    _login(page, browser_environment.origin, browser_seed.admin)
    page.get_by_role("link", name="Аудит").click()
    audit_text = page.locator("body").inner_text()
    assert "incident.status_changed" in audit_text
    assert "incident.comment_added" in audit_text
    assert browser_seed.xss_canary not in audit_text
    page.get_by_role("button", name="Выйти").click()

    guard.allow_expected_http_error_console()
    _login(page, browser_environment.origin, browser_seed.viewer, expected_status=403)
    assert page.get_by_role("heading", name="Ошибка 403").count() == 1
    assert "__Host-wg_session" not in _cookie_names(context)

    guard.assert_clean()
    captured = capfd.readouterr()
    log_values = [record.getMessage() for record in caplog.records]
    if browser_environment.application is not None:
        log_values.extend(browser_environment.application.logs)
    for secret in browser_seed.secrets:
        assert_secret_absent(secret, (captured.out, captured.err, *log_values))


def _login(
    page: Page,
    origin: str,
    operator: BrowserOperator,
    *,
    expected_status: int = 200,
) -> None:
    safe_browser_operation(lambda: page.goto(f"{origin}/dashboard/login"))
    csrf_cookies = [
        cookie for cookie in page.context.cookies() if cookie["name"] == "__Host-wg_csrf"
    ]
    if len(csrf_cookies) != 1:
        raise AssertionError("Dashboard login did not issue one CSRF cookie") from None
    hidden_csrf = page.locator('input[name="_csrf"]').input_value()
    if not hidden_csrf or hidden_csrf != csrf_cookies[0]["value"]:
        raise AssertionError("Dashboard login CSRF binding was not browser-compatible") from None
    safe_browser_operation(
        lambda: page.get_by_label("API-ключ оператора").fill(
            operator.token.reveal_for_browser_fill()
        )
    )
    observed_statuses: list[int] = []

    def submit() -> None:
        with (
            page.expect_request(
                lambda request: (
                    request.method == "POST" and urlsplit(request.url).path == "/dashboard/login"
                )
            ) as request_info,
            page.expect_response(
                lambda response: (
                    response.request.method == "POST"
                    and urlsplit(response.url).path == "/dashboard/login"
                )
            ) as response_info,
        ):
            page.get_by_role("button", name="Войти").click()
        supplied_origin = request_info.value.all_headers().get("origin")
        if supplied_origin != origin:
            raise AssertionError("Browser login did not send the configured Origin") from None
        observed_statuses.append(response_info.value.status)

    safe_browser_operation(submit)
    if expected_status == 200:
        if observed_statuses != [303]:
            raise AssertionError("Dashboard login returned an unexpected safe status") from None
        safe_browser_operation(lambda: page.wait_for_url(f"{origin}/dashboard/"))
        return
    if not observed_statuses or observed_statuses[-1] != expected_status:
        raise AssertionError("Dashboard login returned an unexpected safe status") from None


def _record_response(response: object, output: list[tuple[str, str, int]]) -> None:
    request = response.request  # type: ignore[attr-defined]
    path = urlsplit(response.url).path  # type: ignore[attr-defined]
    output.append((str(request.method), path, int(response.status)))  # type: ignore[attr-defined]


def _assert_prg(responses: Sequence[tuple[str, str, int]], *, suffix: str) -> None:
    if not any(
        method == "POST" and path.endswith(suffix) and status == 303
        for method, path, status in responses
    ):
        raise AssertionError("Dashboard mutation did not use the expected PRG boundary") from None
    if not any(
        method == "GET" and "/dashboard/incidents/" in path and status == 200
        for method, path, status in responses
    ):
        raise AssertionError("Dashboard mutation did not finish on the expected GET") from None


def _last_mutation_status(responses: Sequence[tuple[str, str, int]]) -> int | None:
    for method, _path, status in reversed(responses):
        if method == "POST":
            return status
    return None


def _cookie_names(context: BrowserContext) -> set[str]:
    return {str(cookie["name"]) for cookie in context.cookies()}


def _session_cookie_value(context: BrowserContext) -> str:
    for cookie in context.cookies():
        if cookie["name"] == "__Host-wg_session":
            return str(cookie["value"])
    raise AssertionError("authenticated browser context had no session cookie") from None


def _assert_session_cookie_policy(context: BrowserContext) -> None:
    metadata = {
        str(cookie["name"]): (
            bool(cookie["secure"]),
            bool(cookie["httpOnly"]),
            str(cookie["sameSite"]),
            str(cookie["path"]),
        )
        for cookie in context.cookies()
        if cookie["name"] in {"__Host-wg_session", "__Host-wg_csrf"}
    }
    expected = (True, True, "Strict", "/")
    if metadata != {"__Host-wg_session": expected, "__Host-wg_csrf": expected}:
        raise AssertionError(
            "Dashboard cookies did not preserve their security attributes"
        ) from None


def _mutation_counts(
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> MutationCounts:
    with session_factory() as session:
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AssertionError("browser incident was not found")
        return MutationCounts(
            history=int(
                session.scalar(
                    select(func.count())
                    .select_from(IncidentHistoryEntry)
                    .where(IncidentHistoryEntry.incident_id == incident_id)
                )
                or 0
            ),
            comments=int(
                session.scalar(
                    select(func.count())
                    .select_from(IncidentComment)
                    .where(IncidentComment.incident_id == incident_id)
                )
                or 0
            ),
            status_audit=int(
                session.scalar(
                    select(func.count())
                    .select_from(AuditLogEntry)
                    .where(AuditLogEntry.action == "incident.status_changed")
                )
                or 0
            ),
            comment_audit=int(
                session.scalar(
                    select(func.count())
                    .select_from(AuditLogEntry)
                    .where(AuditLogEntry.action == "incident.comment_added")
                )
                or 0
            ),
            idempotency=int(
                session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) or 0
            ),
            outbox=int(session.scalar(select(func.count()).select_from(OutboxMessage)) or 0),
        )
