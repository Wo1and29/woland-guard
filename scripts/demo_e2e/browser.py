"""One desktop browser smoke over the same database populated by the 8B pipeline."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from tests.browser.guards import PageRequestGuard, safe_browser_operation
from tests.browser.harness import (
    ApplicationProcess,
    EphemeralDatabaseConfiguration,
    TemporaryTlsMaterial,
)

from scripts.demo_e2e.contracts import (
    DemoDatabaseConfiguration,
    DemoE2EError,
    RecoveryArtifactKind,
)
from scripts.demo_e2e.pipeline import DemoProvisioning, database_snapshot
from scripts.demo_e2e.recovery import RecoveryLedgerStore
from woland_guard_control_plane.application.audit import (
    AuditValidationError,
    validate_audit_action,
)
from woland_guard_control_plane.infrastructure.database.models import (
    AuditActorType,
    AuditLogEntry,
    Incident,
    IncidentComment,
    OperatorAuthMethodType,
    OperatorWebSession,
)

XSS_CANARY = '<img src=x onerror="window.wgDemoCanary=1">Synthetic 8B comment'


class DemoBrowserError(DemoE2EError):
    """Browser verification failed without exposing a Playwright call log."""


@dataclass(frozen=True, slots=True)
class BrowserWorkflowEvidence:
    incident_id: UUID
    history_delta: int
    comment_delta: int
    status_audit_delta: int
    comment_audit_delta: int


def run_browser_workflow(
    *,
    database: DemoDatabaseConfiguration,
    session_factory: sessionmaker[Session],
    provisioning: DemoProvisioning,
    ledger: RecoveryLedgerStore,
) -> BrowserWorkflowEvidence:
    _enforce_browser_environment()
    incident_id = _select_incident(session_factory, provisioning.server_id)
    before = database_snapshot(session_factory, provisioning)
    before_status_audit = _audit_count(session_factory, "incident.status_changed")
    before_comment_audit = _audit_count(session_factory, "incident.comment_added")
    tls = TemporaryTlsMaterial().start()
    if tls.ca_path is None:
        raise DemoBrowserError("browser TLS artifact is unavailable")
    tls_root = tls.ca_path.parent
    ledger.add_artifact(RecoveryArtifactKind.TLS, tls_root)
    application = ApplicationProcess(
        database=EphemeralDatabaseConfiguration(
            host=database.host,
            port=database.port,
            database=database.database,
            username=database.username,
            password=database.password.reveal(),
        ),
        tls=tls,
    )
    playwright = None
    browser: Browser | None = None
    context: BrowserContext | None = None
    cleanup_failed = False
    try:
        application.start()
        playwright = sync_playwright().start()
        browser = safe_browser_operation(
            lambda: playwright.chromium.launch(channel="chromium", headless=True)
        )
        context = safe_browser_operation(
            lambda: browser.new_context(
                accept_downloads=False,
                ignore_https_errors=True,
                service_workers="block",
                viewport={"width": 1440, "height": 900},
            )
        )
        context.set_default_timeout(5_000)
        context.set_default_navigation_timeout(10_000)
        guard = PageRequestGuard(application.origin)
        guard.install(context)
        page = safe_browser_operation(context.new_page)
        guard.attach_page(page)
        _analyst_workflow(page, application.origin, provisioning, incident_id)
        _admin_workflow(page, application.origin, provisioning)
        guard.allow_expected_http_error_console()
        _login(
            page,
            application.origin,
            provisioning.viewer.token.reveal(),
            expected_status=403,
        )
        if page.get_by_role("heading", name="Ошибка 403").count() != 1:
            raise DemoBrowserError("viewer Dashboard denial was not rendered safely")
        guard.assert_clean()
        for secret in provisioning.secrets:
            if any(secret in value for value in application.logs):
                raise DemoBrowserError("browser application output contained credential material")
    except DemoE2EError:
        raise
    except Exception:
        raise DemoBrowserError("browser workflow failed safely") from None
    finally:
        if context is not None:
            try:
                safe_browser_operation(context.close)
            except Exception:
                cleanup_failed = True
        if browser is not None:
            try:
                safe_browser_operation(browser.close)
            except Exception:
                cleanup_failed = True
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                cleanup_failed = True
        try:
            application.stop()
        except Exception:
            cleanup_failed = True
        try:
            tls.stop()
            ledger.remove_artifact(RecoveryArtifactKind.TLS, tls_root)
        except Exception:
            cleanup_failed = True
        if cleanup_failed:
            raise DemoBrowserError("browser workflow cleanup failed") from None

    after = database_snapshot(session_factory, provisioning)
    status_delta = _audit_count(session_factory, "incident.status_changed") - before_status_audit
    comment_delta = _audit_count(session_factory, "incident.comment_added") - before_comment_audit
    evidence = BrowserWorkflowEvidence(
        incident_id=incident_id,
        history_delta=after.history - before.history,
        comment_delta=after.comments - before.comments,
        status_audit_delta=status_delta,
        comment_audit_delta=comment_delta,
    )
    if evidence != BrowserWorkflowEvidence(incident_id, 1, 1, 1, 1):
        raise DemoBrowserError("browser mutation deltas were not exact")
    if (
        after.events != before.events
        or after.incidents != before.incidents
        or after.evidence != before.evidence
        or after.outbox != before.outbox
        or after.delivered != before.delivered
        or after.failed != before.failed
        or after.pending != before.pending
        or after.processing != before.processing
    ):
        raise DemoBrowserError("browser workflow changed an unrelated persistence aggregate")
    with session_factory() as session:
        active_sessions = int(
            session.scalar(
                select(func.count())
                .select_from(OperatorWebSession)
                .where(OperatorWebSession.revoked_at.is_(None))
            )
            or 0
        )
    if active_sessions:
        raise DemoBrowserError("browser workflow left an active web session")
    _verify_raw_audit_contracts(
        session_factory,
        incident_id=incident_id,
        provisioning=provisioning,
    )
    return evidence


def _analyst_workflow(
    page: Page,
    origin: str,
    provisioning: DemoProvisioning,
    incident_id: UUID,
) -> None:
    _login(page, origin, provisioning.analyst.token.reveal())
    if page.get_by_role("heading", name="Обзор").count() != 1:
        raise DemoBrowserError("analyst overview was not rendered")
    page.get_by_role("link", name="Инциденты").click()
    if page.get_by_role("heading", name="Инциденты").count() != 1:
        raise DemoBrowserError("incident list was not rendered")
    page.goto(f"{origin}/dashboard/incidents/{incident_id}")
    if page.locator('form[action$="/transitions"]').count() != 1:
        raise DemoBrowserError("incident transition form was unavailable")
    responses: list[tuple[str, str, int]] = []
    page.on(
        "response",
        lambda response: responses.append(
            (
                str(response.request.method),
                urlsplit(response.url).path,
                int(response.status),
            )
        ),
    )
    page.get_by_label("Новый статус").select_option("investigating")
    page.get_by_role("button", name="Изменить статус").click()
    page.wait_for_url(f"{origin}/dashboard/incidents/*")
    _require_prg(responses, "/transitions")
    responses.clear()
    page.get_by_label("Комментарий").fill(XSS_CANARY)
    page.get_by_role("button", name="Сохранить комментарий").click()
    page.wait_for_url(f"{origin}/dashboard/incidents/*")
    _require_prg(responses, "/comments")
    if (
        page.locator(".comment-body").last.text_content() != XSS_CANARY
        or page.locator(".comment-body img").count() != 0
        or page.evaluate("() => window.wgDemoCanary ?? null") is not None
    ):
        raise DemoBrowserError("comment XSS boundary failed")
    page.reload()
    page.get_by_role("button", name="Выйти").click()
    if page.get_by_role("heading", name="Вход оператора").count() != 1:
        raise DemoBrowserError("analyst logout did not return to login")


def _admin_workflow(page: Page, origin: str, provisioning: DemoProvisioning) -> None:
    _login(page, origin, provisioning.admin.token.reveal())
    page.get_by_role("link", name="Аудит").click()
    text = page.locator("body").inner_text()
    if (
        "incident.status_changed" not in text
        or "incident.comment_added" not in text
        or XSS_CANARY in text
    ):
        raise DemoBrowserError("admin audit presentation did not preserve safe metadata")
    page.get_by_role("button", name="Выйти").click()


def _login(page: Page, origin: str, token: str, *, expected_status: int = 303) -> None:
    page.goto(f"{origin}/dashboard/login")
    csrf = page.locator('input[name="_csrf"]').input_value()
    cookies = [cookie for cookie in page.context.cookies() if cookie["name"] == "__Host-wg_csrf"]
    if len(cookies) != 1 or not csrf or csrf != cookies[0]["value"]:
        raise DemoBrowserError("Dashboard pre-auth CSRF binding is invalid")
    page.get_by_label("API-ключ оператора").fill(token)
    observed: list[int] = []
    with page.expect_response(
        lambda response: (
            response.request.method == "POST" and urlsplit(response.url).path == "/dashboard/login"
        )
    ) as response_info:
        page.get_by_role("button", name="Войти").click()
    observed.append(response_info.value.status)
    if observed != [expected_status]:
        raise DemoBrowserError("Dashboard login returned an unexpected safe status")
    if expected_status == 303:
        page.wait_for_url(f"{origin}/dashboard/")
        session_cookies = [
            cookie for cookie in page.context.cookies() if cookie["name"] == "__Host-wg_session"
        ]
        if len(session_cookies) != 1:
            raise DemoBrowserError("Dashboard session cookie is unavailable")


def _require_prg(responses: list[tuple[str, str, int]], suffix: str) -> None:
    if not any(
        method == "POST" and path.endswith(suffix) and status == 303
        for method, path, status in responses
    ) or not any(
        method == "GET" and path.startswith("/dashboard/incidents/") and status == 200
        for method, path, status in responses
    ):
        raise DemoBrowserError("Dashboard mutation did not use PRG")


def _select_incident(session_factory: sessionmaker[Session], server_id: UUID) -> UUID:
    with session_factory() as session:
        incident_id = session.scalar(
            select(Incident.id)
            .where(Incident.server_id == server_id, Incident.status == "new")
            .order_by(Incident.created_at, Incident.id)
            .limit(1)
        )
    if incident_id is None:
        raise DemoBrowserError("pipeline incident is unavailable for browser verification")
    return incident_id


def _audit_count(session_factory: sessionmaker[Session], action: str) -> int:
    with session_factory() as session:
        return int(
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == action)
            )
            or 0
        )


def _verify_raw_audit_contracts(
    session_factory: sessionmaker[Session],
    *,
    incident_id: UUID,
    provisioning: DemoProvisioning,
) -> None:
    with session_factory() as session:
        status_rows = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action == "incident.status_changed",
                AuditLogEntry.operator_id == provisioning.analyst.operator_id,
                AuditLogEntry.target_id == incident_id,
            )
        ).all()
        comment_rows = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action == "incident.comment_added",
                AuditLogEntry.operator_id == provisioning.analyst.operator_id,
            )
        ).all()
        comment_target_id = (
            session.scalar(
                select(IncidentComment.id).where(
                    IncidentComment.id == comment_rows[0].target_id,
                    IncidentComment.incident_id == incident_id,
                )
            )
            if len(comment_rows) == 1
            else None
        )
    if len(status_rows) != 1 or len(comment_rows) != 1:
        raise DemoBrowserError("browser raw audit row cardinality was not exact")
    if comment_target_id is None:
        raise DemoBrowserError("browser comment audit target metadata was invalid")
    _validate_raw_audit_rows(
        status=status_rows[0],
        comment=comment_rows[0],
        incident_id=incident_id,
        comment_target_id=comment_target_id,
        analyst_username=provisioning.analyst.username,
    )


def _validate_raw_audit_rows(
    *,
    status: AuditLogEntry,
    comment: AuditLogEntry,
    incident_id: UUID,
    comment_target_id: UUID,
    analyst_username: str,
) -> None:
    common_valid = all(
        row.actor_type == "operator"
        and row.actor_username_snapshot == analyst_username
        and row.auth_method_type == "web_session"
        and row.auth_method_id is not None
        for row in (status, comment)
    )
    if not common_valid or status.auth_method_type is None or comment.auth_method_type is None:
        raise DemoBrowserError("browser raw audit actor metadata was invalid")
    try:
        status_details = validate_audit_action(
            action=status.action,
            actor_type=AuditActorType(status.actor_type),
            auth_method_type=OperatorAuthMethodType(status.auth_method_type),
            target_type=status.target_type,
            details=status.details,
        )
        comment_details = validate_audit_action(
            action=comment.action,
            actor_type=AuditActorType(comment.actor_type),
            auth_method_type=OperatorAuthMethodType(comment.auth_method_type),
            target_type=comment.target_type,
            details=comment.details,
        )
    except (AuditValidationError, TypeError, ValueError):
        raise DemoBrowserError("browser raw audit details violated the closed contract") from None
    if (
        status.action != "incident.status_changed"
        or status.target_id != incident_id
        or status.incident_history_id is None
        or status_details.get("history_id") != str(status.incident_history_id)
    ):
        raise DemoBrowserError("browser status audit details violated the closed contract")
    if (
        comment.action != "incident.comment_added"
        or comment.target_id != comment_target_id
        or comment.incident_history_id is not None
        or comment_details != {"incident_id": str(incident_id)}
    ):
        raise DemoBrowserError("browser comment audit details violated the closed contract")


def _enforce_browser_environment() -> None:
    if os.environ.get("PWDEBUG") or "pw:api" in os.environ.get("DEBUG", "").casefold():
        raise DemoBrowserError("browser verification refuses debug logging")
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        raise DemoBrowserError("browser installation path is not explicitly configured")
