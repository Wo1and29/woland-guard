"""PostgreSQL-backed read-only Dashboard routes, RBAC and security boundaries."""

import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import insert
from sqlalchemy.engine import Connection

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from tests.integration.test_dashboard_queries import _create_incident_with_evidence
from woland_guard_control_plane.application import rule_queries
from woland_guard_control_plane.application.dashboard_pagination import (
    DashboardCursorContext,
    DashboardListType,
    encode_dashboard_cursor,
)
from woland_guard_control_plane.application.detection.rules import (
    canonical_rule,
    load_rules_directory,
    rule_checksum,
)
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    DetectionRuleVersion,
    OperatorRole,
    Server,
)
from woland_guard_control_plane.web.security import SECURITY_HEADERS

pytestmark = pytest.mark.integration
ORIGIN = "https://localhost:8000"
RULES_DIR = Path(__file__).parents[2] / "detection-rules"
AUDIT_CANARY = "canary-audit-untrusted-json"


def _client(api_app: object) -> TestClient:
    return TestClient(api_app, base_url=ORIGIN, raise_server_exceptions=False)  # type: ignore[arg-type]


def _login(client: TestClient, operator: RegisteredOperator) -> None:
    page = client.get("/dashboard/login")
    assert page.status_code == 200
    csrf = client.cookies.get("__Host-wg_csrf")
    assert csrf is not None
    response = client.post(
        "/dashboard/login",
        content=f"credential={operator.token}&_csrf={csrf}",
        headers={
            "Origin": ORIGIN,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def _insert_corrupt_rule(rule_key: str) -> tuple[UUID, str]:
    row_id = uuid4()
    canary = f"canary-{rule_key}"
    with get_session_factory().begin() as session:
        session.add(
            DetectionRuleVersion(
                id=row_id,
                rule_key=rule_key,
                version=1,
                schema_version=1,
                enabled=True,
                severity="high",
                checksum="d" * 64,
                definition={"unsafe": canary},
                is_active=True,
                activated_at=datetime.now(UTC),
            )
        )
    return row_id, canary


def _assert_safe_rule_503(
    response: Response,
    caplog: pytest.LogCaptureFixture,
    row_id: UUID,
    canary: str,
) -> None:
    assert response.status_code == 503
    assert response.headers["x-request-id"] in response.text
    assert canary not in response.text
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    messages = [record.getMessage() for record in caplog.records]
    matching = [message for message in messages if "dashboard_rule_definition_invalid" in message]
    assert len(matching) == 1
    assert str(row_id) in matching[0]
    assert all(canary not in message for message in messages)


def test_analyst_can_read_pages_but_audit_remains_admin_only(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        session.add(Server(name="read-only-server", hostname="read-only.invalid"))
    with _client(api_app) as client:
        _login(client, operator)
        for path in (
            "/dashboard/",
            "/dashboard/servers",
            "/dashboard/incidents",
            "/dashboard/rules",
        ):
            response = client.get(path)
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/html")
            assert operator.username in response.text
        denied = client.get("/dashboard/audit")
    assert denied.status_code == 403


def test_viewer_does_not_gain_dashboard_access(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.VIEWER)
    with _client(api_app) as client:
        page = client.get("/dashboard/login")
        csrf = client.cookies.get("__Host-wg_csrf")
        assert page.status_code == 200 and csrf is not None
        response = client.post(
            "/dashboard/login",
            content=f"credential={operator.token}&_csrf={csrf}",
            headers={
                "Origin": ORIGIN,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            follow_redirects=False,
        )
    assert response.status_code == 403
    assert client.cookies.get("__Host-wg_session") is None


def test_incident_html_contains_only_allowlisted_evidence(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    incident_id, canary = _create_incident_with_evidence()
    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        _login(client, operator)
        response = client.get(f"/dashboard/incidents/{incident_id}")
    assert response.status_code == 200
    assert "linux.ssh.authentication_failed" in response.text
    assert canary not in response.text
    for forbidden in ("source_ip", "attributes", "correlation", "payload"):
        assert forbidden not in response.text.casefold()


def test_corrupt_audit_details_degrade_one_row_without_hiding_metadata(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    canary = "canary-audit-credential"
    target_id = uuid4()
    with _client(api_app) as client:
        _login(client, operator)
        with get_session_factory().begin() as session:
            session.add(
                AuditLogEntry(
                    actor_type="local_cli",
                    operator_id=None,
                    actor_username_snapshot=None,
                    auth_method_type=None,
                    auth_method_id=None,
                    action="operator.created",
                    target_type="operator",
                    target_id=target_id,
                    incident_history_id=None,
                    request_id=None,
                    details={"role": "admin", "credential": canary},
                )
            )
        response = client.get("/dashboard/audit")
    assert response.status_code == 200
    assert "operator.created" in response.text
    assert str(target_id) in response.text
    assert "Детали недоступны" in response.text
    assert canary not in response.text
    assert "operator_web_session.started" in response.text


@pytest.mark.parametrize(
    ("action", "details"),
    [
        ("operator.created", [AUDIT_CANARY]),
        ("operator.created", AUDIT_CANARY),
        ("operator.created", 7),
        ("operator.created", True),
        ("operator.created", None),
        ("operator.created", {"role": "admin", "extra": AUDIT_CANARY}),
        ("operator.created", {}),
        ("operator.created", {"role": 7}),
        ("unknown.action", {"role": "admin"}),
    ],
    ids=(
        "array",
        "string",
        "number",
        "boolean",
        "json-null",
        "extra-field",
        "missing-field",
        "wrong-scalar",
        "unknown-action",
    ),
)
def test_every_untrusted_audit_json_shape_degrades_without_page_failure(
    api_app: object,
    register_operator: OperatorFactory,
    caplog: pytest.LogCaptureFixture,
    action: str,
    details: object,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    target_id = uuid4()
    with _client(api_app) as client:
        _login(client, operator)
        with get_session_factory().begin() as session:
            session.execute(
                insert(AuditLogEntry),
                [
                    {
                        "actor_type": "local_cli",
                        "operator_id": None,
                        "actor_username_snapshot": None,
                        "auth_method_type": None,
                        "auth_method_id": None,
                        "action": action,
                        "target_type": "operator",
                        "target_id": target_id,
                        "incident_history_id": None,
                        "request_id": None,
                        "details": details,
                        "created_at": datetime.now(UTC),
                    }
                ],
            )
        caplog.clear()
        response = client.get("/dashboard/audit")
    assert response.status_code == 200
    assert str(target_id) in response.text
    assert "Детали недоступны" in response.text
    assert "operator_web_session.started" in response.text
    assert AUDIT_CANARY not in response.text
    assert all(AUDIT_CANARY not in record.getMessage() for record in caplog.records)


def test_corrupt_rule_returns_one_safe_503_log(
    api_app: object,
    register_operator: OperatorFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    row_id = uuid4()
    canary = "canary-rule-json"
    with get_session_factory().begin() as session:
        session.add(
            DetectionRuleVersion(
                id=row_id,
                rule_key="corrupt_dashboard_rule",
                version=1,
                schema_version=1,
                enabled=True,
                severity="high",
                checksum="c" * 64,
                definition={"unsafe": canary},
                is_active=True,
                activated_at=datetime.now(UTC),
            )
        )
    with _client(api_app) as client:
        _login(client, operator)
        with caplog.at_level(logging.ERROR, logger="uvicorn.error"):
            response = client.get("/dashboard/rules")
    assert response.status_code == 503
    assert canary not in response.text
    assert response.headers["x-request-id"] in response.text
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    messages = [record.getMessage() for record in caplog.records]
    matching = [message for message in messages if "dashboard_rule_definition_invalid" in message]
    assert len(matching) == 1
    assert str(row_id) in matching[0]
    assert all(canary not in message for message in messages)


@pytest.mark.parametrize(
    "query",
    (
        "condition=threshold",
        "severity=critical",
        "enabled=no",
        "q=does_not_match",
    ),
)
def test_corrupt_active_rule_cannot_be_hidden_by_filters_or_search(
    api_app: object,
    register_operator: OperatorFactory,
    caplog: pytest.LogCaptureFixture,
    query: str,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    row_id, canary = _insert_corrupt_rule("corrupt_hidden_rule")
    with _client(api_app) as client:
        _login(client, operator)
        caplog.clear()
        with caplog.at_level(logging.ERROR, logger="uvicorn.error"):
            response = client.get(f"/dashboard/rules?{query}")
    _assert_safe_rule_503(response, caplog, row_id, canary)


def test_corrupt_active_rule_after_first_page_boundary_still_returns_503(
    api_app: object,
    register_operator: OperatorFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    base_rule = load_rules_directory(RULES_DIR)[0]
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        for index in range(25):
            rule = base_rule.model_copy(update={"rule_key": f"page_rule_{index:02d}"})
            session.add(
                DetectionRuleVersion(
                    rule_key=rule.rule_key,
                    version=rule.version,
                    schema_version=rule.schema_version,
                    enabled=rule.enabled,
                    severity=rule.severity.value,
                    checksum=rule_checksum(rule),
                    definition=canonical_rule(rule),
                    is_active=True,
                    activated_at=now,
                )
            )
    row_id, canary = _insert_corrupt_rule("zz_corrupt_after_boundary")
    with _client(api_app) as client:
        _login(client, operator)
        caplog.clear()
        with caplog.at_level(logging.ERROR, logger="uvicorn.error"):
            response = client.get("/dashboard/rules?page_size=25")
    _assert_safe_rule_503(response, caplog, row_id, canary)


def test_active_rule_validation_hard_limit_fails_closed(
    api_app: object,
    register_operator: OperatorFactory,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    base_rule = load_rules_directory(RULES_DIR)[0]
    with get_session_factory().begin() as session:
        for index in range(2):
            rule = base_rule.model_copy(update={"rule_key": f"bounded_rule_{index}"})
            session.add(
                DetectionRuleVersion(
                    rule_key=rule.rule_key,
                    version=rule.version,
                    schema_version=rule.schema_version,
                    enabled=rule.enabled,
                    severity=rule.severity.value,
                    checksum=rule_checksum(rule),
                    definition=canonical_rule(rule),
                    is_active=True,
                    activated_at=datetime.now(UTC),
                )
            )
    monkeypatch.setattr(rule_queries, "MAX_ACTIVE_RULES_FOR_DASHBOARD", 1)
    with _client(api_app) as client:
        _login(client, operator)
        caplog.clear()
        with caplog.at_level(logging.ERROR, logger="uvicorn.error"):
            response = client.get("/dashboard/rules")
    assert response.status_code == 503
    assert response.headers["x-request-id"] in response.text
    messages = [record.getMessage() for record in caplog.records]
    matching = [
        message
        for message in messages
        if "dashboard_active_rule_validation_limit_exceeded" in message
    ]
    assert len(matching) == 1


@pytest.mark.parametrize(
    ("path", "forbidden_relation"),
    (
        ("/dashboard/servers?q=", "servers"),
        ("/dashboard/incidents?q=", "incidents"),
        ("/dashboard/rules?q=", "detection_rule_versions"),
        ("/dashboard/incidents?rule_key=%00", "incidents"),
        ("/dashboard/incidents?rule_key=", "incidents"),
    ),
)
def test_invalid_search_and_rule_key_return_422_before_application_query(
    api_app: object,
    register_operator: OperatorFactory,
    path: str,
    forbidden_relation: str,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    statements: list[str] = []

    def record_statement(
        _connection: Connection,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(statement.casefold())

    with _client(api_app) as client:
        _login(client, operator)
        sqlalchemy_event.listen(get_engine(), "before_cursor_execute", record_statement)
        try:
            response = client.get(path)
        finally:
            sqlalchemy_event.remove(get_engine(), "before_cursor_execute", record_statement)
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["x-request-id"] in response.text
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert "%00" not in response.text
    assert not any(f"from {forbidden_relation}" in statement for statement in statements)


def test_dashboard_local_html_errors_do_not_change_rest_json(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        _login(client, operator)
        responses = (
            client.get("/dashboard/not-a-route"),
            client.post(
                "/dashboard/servers",
                content="",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            client.get("/dashboard/servers?state=not-a-state"),
            client.get("/dashboard/servers?q=canary%00query"),
        )
        api_response = client.get(f"/api/v1/incidents/{uuid4()}")
    assert [response.status_code for response in responses] == [404, 405, 422, 422]
    for response in responses:
        assert response.headers["content-type"].startswith("text/html")
        assert response.headers["x-request-id"] in response.text
        assert "canary" not in response.text
        for name, value in SECURITY_HEADERS.items():
            assert response.headers[name] == value
    assert api_response.status_code == 401
    assert api_response.headers["content-type"].startswith("application/json")


def test_untrusted_cursor_is_context_bound_but_not_an_authorization_token(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    context = DashboardCursorContext(
        list_type=DashboardListType.SERVERS,
        filters={"id": None, "state": "all"},
        search=None,
        sort="name_asc",
        page_size=25,
    )
    arbitrary_position = encode_dashboard_cursor(
        context,
        keys=("arbitrary-position", uuid4()),
    )
    with _client(api_app) as client:
        _login(client, operator)
        accepted = client.get(f"/dashboard/servers?cursor={arbitrary_position}")
        malformed = client.get("/dashboard/servers?cursor=not+canonical")
        wrong_route = client.get(f"/dashboard/rules?cursor={arbitrary_position}")
    assert accepted.status_code == 200
    assert malformed.status_code == 400
    assert wrong_route.status_code == 400
    assert all(response.status_code < 500 for response in (accepted, malformed, wrong_route))


def test_static_css_is_public_but_wrapped_and_cannot_traverse(api_app: object) -> None:
    with _client(api_app) as client:
        css = client.get("/dashboard/static/dashboard.css")
        traversal = client.get("/dashboard/static/%2e%2e/app.py")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    for name, value in SECURITY_HEADERS.items():
        assert css.headers[name] == value
    assert "@import" not in css.text.casefold()
    assert "sourcemappingurl" not in css.text.casefold()
    assert traversal.status_code == 404
    assert "create_dashboard_app" not in traversal.text
    for name, value in SECURITY_HEADERS.items():
        assert traversal.headers[name] == value


def test_server_detail_never_calls_configuration_state_online(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with get_session_factory().begin() as session:
        server = Server(name="inactive-config", hostname="inactive.invalid", is_active=False)
        session.add(server)
        session.flush()
        server_id = server.id
    with _client(api_app) as client:
        _login(client, operator)
        response = client.get(f"/dashboard/servers/{server_id}")
    assert response.status_code == 200
    assert "Состояние конфигурации" in response.text
    assert "healthcheck" in response.text
    assert "не являются healthcheck или online/offline статусом" in response.text.casefold()
