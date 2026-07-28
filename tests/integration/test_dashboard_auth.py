"""PostgreSQL-backed regressions for Dashboard authentication stage 7A."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.orm.session import SessionTransaction

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from woland_guard_control_plane.application import operators as operator_services
from woland_guard_control_plane.application import web_sessions
from woland_guard_control_plane.application.operator_authentication import (
    authenticate_operator,
    authenticate_operator_for_web_session,
)
from woland_guard_control_plane.application.operator_keys import generate_operator_api_key
from woland_guard_control_plane.application.operators import (
    IssuedOperatorApiKey,
    issue_operator_api_key,
    revoke_operator_api_key,
    rotate_operator_api_key,
)
from woland_guard_control_plane.application.web_sessions import (
    create_operator_web_session,
    revoke_sessions_authenticated_by_key,
)
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    OperatorApiKey,
    OperatorAuthMethodType,
    OperatorRole,
    OperatorWebSession,
)
from woland_guard_control_plane.web.routes import auth as auth_routes
from woland_guard_control_plane.web.security import SECURITY_HEADERS

pytestmark = pytest.mark.integration

ORIGIN = "https://localhost:8000"


def _client(api_app: object) -> TestClient:
    return TestClient(api_app, base_url=ORIGIN, raise_server_exceptions=False)  # type: ignore[arg-type]


def _csrf(client: TestClient) -> str:
    value = client.cookies.get("__Host-wg_csrf")
    assert value is not None
    return value


def _login(
    client: TestClient,
    operator: RegisteredOperator,
    *,
    content_type: str = "application/x-www-form-urlencoded",
) -> httpx2.Response:
    page = client.get("/dashboard/login")
    assert page.status_code == 200
    csrf = _csrf(client)
    return client.post(
        "/dashboard/login",
        content=f"credential={operator.token}&_csrf={csrf}",
        headers={"Origin": ORIGIN, "Content-Type": content_type},
        follow_redirects=False,
    )


def _make_session_touch_due(session_token: str) -> tuple[datetime, datetime, datetime]:
    digest = web_sessions.web_token_digest(session_token)
    assert digest is not None
    current_time = datetime.now(UTC)
    with get_session_factory().begin() as session:
        stored = session.scalar(
            select(OperatorWebSession).where(OperatorWebSession.token_digest == digest)
        )
        assert stored is not None
        stored.created_at = current_time - timedelta(hours=1)
        stored.last_seen_at = current_time - timedelta(minutes=10)
        stored.idle_expires_at = current_time + timedelta(minutes=30)
        stored.updated_at = current_time - timedelta(minutes=10)
        return stored.last_seen_at, stored.idle_expires_at, stored.updated_at


def _session_lifecycle(session_token: str) -> tuple[datetime, datetime, datetime, datetime | None]:
    digest = web_sessions.web_token_digest(session_token)
    assert digest is not None
    with get_session_factory()() as session:
        stored = session.scalar(
            select(OperatorWebSession).where(OperatorWebSession.token_digest == digest)
        )
        assert stored is not None
        return (
            stored.last_seen_at,
            stored.idle_expires_at,
            stored.updated_at,
            stored.revoked_at,
        )


def _assert_backend_waits_for_row_lock(backend_pid: int) -> None:
    for _ in range(500):
        with get_session_factory()() as inspector:
            blockers = inspector.scalar(
                text("SELECT cardinality(pg_blocking_pids(:backend_pid))"),
                {"backend_pid": backend_pid},
            )
        if blockers and int(blockers) > 0:
            return
    pytest.fail("PostgreSQL backend did not enter a row-lock wait")


@pytest.mark.parametrize(
    "content_type",
    [
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=UTF-8",
        "application/x-www-form-urlencoded; CHARSET=utf-8",
    ],
)
def test_browser_form_login_creates_session_and_audit(
    api_app: object,
    register_operator: OperatorFactory,
    content_type: str,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        response = _login(client, operator, content_type=content_type)
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard/"
        assert response.headers["cache-control"] == "no-store"
        session_page = client.get("/dashboard/")

    assert session_page.status_code == 200
    assert operator.username in session_page.text
    assert operator.token not in response.text + session_page.text
    with get_session_factory()() as session:
        stored = session.scalar(select(OperatorWebSession))
        audit = session.scalar(
            select(AuditLogEntry).where(AuditLogEntry.action == "operator_web_session.started")
        )
        assert stored is not None and stored.revoked_at is None
        assert audit is not None
        assert audit.auth_method_type == OperatorAuthMethodType.OPERATOR_API_KEY.value
        assert audit.auth_method_id == operator.key_id
        assert audit.target_id == stored.id
        assert audit.incident_history_id is None
        assert audit.details == {}


@pytest.mark.parametrize(
    "content_type",
    [
        "application/x-www-form-urlencoded; charset=latin-1",
        "application/x-www-form-urlencoded; charset=utf-8; charset=utf-8",
        "application/x-www-form-urlencoded; charset=utf-8; extra=1",
        "multipart/form-data; boundary=synthetic",
        "application/json",
    ],
)
def test_login_rejects_non_browser_form_media_types(
    api_app: object,
    content_type: str,
) -> None:
    with _client(api_app) as client:
        response = client.post(
            "/dashboard/login",
            content="credential=x&_csrf=x",
            headers={"Origin": ORIGIN, "Content-Type": content_type},
        )

    assert response.status_code == 415
    assert response.headers["cache-control"] == "no-store"


def test_login_rejects_content_encoding_and_chunk_equivalent_oversize(
    api_app: object,
) -> None:
    with _client(api_app) as client:
        encoded = client.post(
            "/dashboard/login",
            content=b"safe",
            headers={
                "Origin": ORIGIN,
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Encoding": "gzip",
            },
        )
        oversized = client.post(
            "/dashboard/login",
            content=b"x" * 16_385,
            headers={
                "Origin": ORIGIN,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

    assert encoded.status_code == 415
    assert oversized.status_code == 413


def test_viewer_cannot_create_dashboard_session(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.VIEWER)
    with _client(api_app) as client:
        response = _login(client, operator)

    assert response.status_code == 403
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(OperatorWebSession)) == 0


def test_login_rate_limit_is_safe_and_has_retry_after(api_app: object) -> None:
    unknown_credential = generate_operator_api_key().token
    with _client(api_app) as client:
        client.get("/dashboard/login")
        csrf = _csrf(client)
        responses = [
            client.post(
                "/dashboard/login",
                content=f"credential={unknown_credential}&_csrf={csrf}",
                headers={
                    "Origin": ORIGIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            for _ in range(6)
        ]

    assert [response.status_code for response in responses[:5]] == [401] * 5
    assert responses[-1].status_code == 429
    assert int(responses[-1].headers["retry-after"]) >= 1
    assert unknown_credential not in "".join(response.text for response in responses)


def test_session_absolute_expiry_is_capped_by_login_key_expiry(
    register_operator: OperatorFactory,
) -> None:
    key_expiry = datetime.now(UTC) + timedelta(minutes=10)
    operator = register_operator(role=OperatorRole.ADMIN, expires_at=key_expiry)
    with get_session_factory().begin() as session:
        authenticated = authenticate_operator(session, operator.token, now=datetime.now(UTC))
        issued = web_sessions.create_operator_web_session(
            session,
            authenticated=authenticated,
            now=datetime.now(UTC),
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="expiry-cap",
        )

    assert issued.absolute_expires_at == key_expiry


def test_dashboard_ignores_bearer_and_rest_ignores_dashboard_cookies(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    with _client(api_app) as client:
        dashboard = client.get(
            "/dashboard/",
            headers={"Authorization": f"Bearer {operator.token}"},
        )
        client.cookies.set("__Host-wg_session", "synthetic")
        api_response = client.get("/health/live")

    assert dashboard.status_code == 401
    assert api_response.status_code == 200
    assert api_response.headers["content-type"].startswith("application/json")


def test_successful_logout_commits_audit_then_deletes_both_cookies(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    with _client(api_app) as client:
        assert _login(client, operator).status_code == 303
        session_token = client.cookies.get("__Host-wg_session")
        assert session_token is not None
        before_last_seen, before_idle_expiry, _before_updated = _make_session_touch_due(
            session_token
        )
        csrf = _csrf(client)
        response = client.post(
            "/dashboard/logout",
            content=f"_csrf={csrf}",
            headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        reuse = client.get("/dashboard/")

    assert response.status_code == 303
    cookie_headers = response.headers.get_list("set-cookie")
    assert len(cookie_headers) == 2
    assert all("Max-Age=0" in value and "Secure" in value for value in cookie_headers)
    assert all("HttpOnly" in value and "SameSite=strict" in value for value in cookie_headers)
    assert all("Path=/" in value and "Domain=" not in value for value in cookie_headers)
    assert reuse.status_code == 401
    with get_session_factory()() as session:
        stored = session.scalar(select(OperatorWebSession))
        ended = session.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "operator_web_session.ended")
        ).all()
        assert stored is not None and stored.revoked_at is not None
        assert stored.last_seen_at == before_last_seen
        assert stored.idle_expires_at == before_idle_expiry
        assert len(ended) == 1
        assert ended[0].auth_method_type == OperatorAuthMethodType.WEB_SESSION.value
        assert ended[0].auth_method_id == stored.id
        assert ended[0].details == {}


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [("origin", 403), ("origin_missing", 403), ("csrf", 403), ("csrf_missing", 422)],
)
def test_logout_validation_failure_neither_revokes_nor_deletes_cookies(
    api_app: object,
    register_operator: OperatorFactory,
    failure: str,
    expected_status: int,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        assert _login(client, operator).status_code == 303
        session_token = client.cookies.get("__Host-wg_session")
        assert session_token is not None
        expected_lifecycle = (*_make_session_touch_due(session_token), None)
        csrf = _csrf(client)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if failure != "origin_missing":
            headers["Origin"] = "https://invalid.example" if failure == "origin" else ORIGIN
        content = (
            ""
            if failure == "csrf_missing"
            else (f"_csrf={'invalid' if failure == 'csrf' else csrf}")
        )
        response = client.post(
            "/dashboard/logout",
            content=content,
            headers=headers,
            follow_redirects=False,
        )

    assert response.status_code == expected_status
    assert not response.headers.get_list("set-cookie")
    assert _session_lifecycle(session_token) == expected_lifecycle
    with get_session_factory()() as session:
        ended_count = session.scalar(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.action == "operator_web_session.ended")
        )
        assert ended_count == 0


def test_logout_rejects_csrf_from_another_session_without_touching_state(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as first_client, _client(api_app) as second_client:
        assert _login(first_client, operator).status_code == 303
        assert _login(second_client, operator).status_code == 303
        first_session_token = first_client.cookies.get("__Host-wg_session")
        assert first_session_token is not None
        expected_lifecycle = (*_make_session_touch_due(first_session_token), None)
        other_csrf = _csrf(second_client)
        first_client.cookies.set("__Host-wg_csrf", other_csrf)
        response = first_client.post(
            "/dashboard/logout",
            content=f"_csrf={other_csrf}",
            headers={
                "Origin": ORIGIN,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            follow_redirects=False,
        )

    assert response.status_code == 403
    assert not response.headers.get_list("set-cookie")
    assert _session_lifecycle(first_session_token) == expected_lifecycle
    with get_session_factory()() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "operator_web_session.ended")
            )
            == 0
        )


def test_logout_audit_failure_rolls_back_and_preserves_cookies(
    api_app: object,
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    with _client(api_app) as client:
        assert _login(client, operator).status_code == 303
        csrf = _csrf(client)

        def fail_audit(*args: object, **kwargs: object) -> None:
            raise ValueError("synthetic audit failure with private material")

        monkeypatch.setattr(web_sessions, "record_operator_action", fail_audit)
        response = client.post(
            "/dashboard/logout",
            content=f"_csrf={csrf}",
            headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )

    assert response.status_code == 500
    assert "private material" not in response.text
    assert not response.headers.get_list("set-cookie")
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    with get_session_factory()() as session:
        stored = session.scalar(select(OperatorWebSession))
        assert stored is not None and stored.revoked_at is None


def test_logout_commit_failure_is_not_success_and_preserves_cookies(
    api_app: object,
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    with _client(api_app) as client:
        assert _login(client, operator).status_code == 303
        csrf = _csrf(client)
        original_commit = SessionTransaction.commit
        commits = 0

        def conditional_failure(
            transaction: SessionTransaction,
            _to_root: bool = False,
        ) -> None:
            nonlocal commits
            commits += 1
            if commits == 2:
                raise SQLAlchemyError("synthetic commit failure with private material")
            original_commit(transaction, _to_root)

        monkeypatch.setattr(SessionTransaction, "commit", conditional_failure)
        response = client.post(
            "/dashboard/logout",
            content=f"_csrf={csrf}",
            headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )

    assert response.status_code == 503
    assert response.status_code != 303
    assert "private material" not in response.text
    assert not response.headers.get_list("set-cookie")
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    with get_session_factory()() as session:
        stored = session.scalar(select(OperatorWebSession))
        ended_count = session.scalar(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.action == "operator_web_session.ended")
        )
        assert stored is not None and stored.revoked_at is None
        assert ended_count == 0


def test_rotation_and_revoke_only_invalidate_sessions_of_the_affected_key(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        first_auth = authenticate_operator(session, operator.token, now=now)
        first_session = web_sessions.create_operator_web_session(
            session,
            authenticated=first_auth,
            now=now,
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="first-login",
        )
        independent_key = issue_operator_api_key(
            session,
            operator_id=operator.operator_id,
            label="independent-key",
            now=now,
        )
    with get_session_factory().begin() as session:
        second_auth = authenticate_operator(
            session,
            independent_key.token,
            now=now + timedelta(seconds=1),
        )
        second_session = web_sessions.create_operator_web_session(
            session,
            authenticated=second_auth,
            now=now + timedelta(seconds=1),
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="second-login",
        )

    with get_session_factory().begin() as session:
        rotate_operator_api_key(
            session,
            key_id=operator.key_id,
            now=now + timedelta(seconds=2),
        )

    with get_session_factory()() as session:
        first_stored = session.get(OperatorWebSession, first_session.session_id)
        second_stored = session.get(OperatorWebSession, second_session.session_id)
        assert first_stored is not None
        assert first_stored.revoked_at == now + timedelta(seconds=2)
        assert second_stored is not None and second_stored.revoked_at is None

    with get_session_factory().begin() as session:
        assert revoke_operator_api_key(
            session,
            key_id=independent_key.key_id,
            now=now + timedelta(seconds=3),
        )
        assert not revoke_operator_api_key(
            session,
            key_id=independent_key.key_id,
            now=now + timedelta(seconds=4),
        )

    with get_session_factory()() as session:
        first_stored = session.get(OperatorWebSession, first_session.session_id)
        second_stored = session.get(OperatorWebSession, second_session.session_id)
        assert first_stored is not None
        assert first_stored.revoked_at == now + timedelta(seconds=2)
        assert second_stored is not None
        assert second_stored.revoked_at == now + timedelta(seconds=3)


def test_login_lock_serializes_revoke_and_leaves_no_active_session(
    api_app: object,
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    login_has_lock = Event()
    allow_login = Event()
    revoke_started = Event()
    revoke_backend_pid: list[int] = []
    original_create_session = create_operator_web_session

    def pause_after_login_lock(*args: object, **kwargs: object) -> object:
        login_has_lock.set()
        assert allow_login.wait(timeout=10)
        return original_create_session(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(auth_routes, "create_operator_web_session", pause_after_login_lock)
    with _client(api_app) as client:
        client.get("/dashboard/login")
        csrf = _csrf(client)

        def submit_login() -> httpx2.Response:
            return client.post(
                "/dashboard/login",
                content=f"credential={operator.token}&_csrf={csrf}",
                headers={
                    "Origin": ORIGIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=False,
            )

        def revoke_key() -> bool:
            with get_session_factory().begin() as session:
                backend_pid = session.scalar(text("SELECT pg_backend_pid()"))
                assert backend_pid is not None
                revoke_backend_pid.append(int(backend_pid))
                revoke_started.set()
                return revoke_operator_api_key(session, key_id=operator.key_id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            login_future = executor.submit(submit_login)
            assert login_has_lock.wait(timeout=10)
            revoke_future = executor.submit(revoke_key)
            assert revoke_started.wait(timeout=10)
            _assert_backend_waits_for_row_lock(revoke_backend_pid[0])
            allow_login.set()
            assert login_future.result(timeout=10).status_code == 303
            assert revoke_future.result(timeout=10)

    with get_session_factory()() as session:
        active_sessions = session.scalar(
            select(func.count())
            .select_from(OperatorWebSession)
            .where(
                OperatorWebSession.authenticated_by_api_key_id == operator.key_id,
                OperatorWebSession.revoked_at.is_(None),
            )
        )
        assert active_sessions == 0


def test_revoke_lock_serializes_login_to_invalid_credentials(
    api_app: object,
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    revoke_has_lock = Event()
    allow_revoke = Event()
    login_started = Event()
    login_backend_pid: list[int] = []
    original_revoke_sessions = revoke_sessions_authenticated_by_key
    original_login_authentication = authenticate_operator_for_web_session

    def pause_revoke(*args: object, **kwargs: object) -> int:
        revoke_has_lock.set()
        assert allow_revoke.wait(timeout=10)
        return original_revoke_sessions(*args, **kwargs)  # type: ignore[arg-type]

    def observe_login_session(*args: object, **kwargs: object) -> object:
        login_session = args[0]
        assert isinstance(login_session, Session)
        backend_pid = login_session.scalar(text("SELECT pg_backend_pid()"))
        assert backend_pid is not None
        login_backend_pid.append(int(backend_pid))
        login_started.set()
        return original_login_authentication(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(operator_services, "revoke_sessions_authenticated_by_key", pause_revoke)
    monkeypatch.setattr(
        auth_routes,
        "authenticate_operator_for_web_session",
        observe_login_session,
    )
    with _client(api_app) as client:
        client.get("/dashboard/login")
        csrf = _csrf(client)

        def revoke_key() -> bool:
            with get_session_factory().begin() as session:
                return revoke_operator_api_key(session, key_id=operator.key_id)

        def submit_login() -> httpx2.Response:
            return client.post(
                "/dashboard/login",
                content=f"credential={operator.token}&_csrf={csrf}",
                headers={
                    "Origin": ORIGIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=False,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            revoke_future = executor.submit(revoke_key)
            assert revoke_has_lock.wait(timeout=10)
            login_future = executor.submit(submit_login)
            assert login_started.wait(timeout=10)
            _assert_backend_waits_for_row_lock(login_backend_pid[0])
            allow_revoke.set()
            assert revoke_future.result(timeout=10)
            login_response = login_future.result(timeout=10)

    assert login_response.status_code == 401
    assert "Неверные учётные данные" in login_response.text
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(OperatorWebSession)) == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "operator_web_session.started")
            )
            == 0
        )


def test_login_lock_serializes_rotation_and_preserves_independent_sessions(
    api_app: object,
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        independent_key = issue_operator_api_key(
            session,
            operator_id=operator.operator_id,
            label="independent-concurrency-key",
            now=now,
        )
    with get_session_factory().begin() as session:
        independent_auth = authenticate_operator(session, independent_key.token, now=now)
        independent_session = web_sessions.create_operator_web_session(
            session,
            authenticated=independent_auth,
            now=now,
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="independent-concurrency-session",
        )

    login_has_lock = Event()
    allow_login = Event()
    rotate_started = Event()
    rotate_backend_pid: list[int] = []
    original_create_session = create_operator_web_session

    def pause_after_login_lock(*args: object, **kwargs: object) -> object:
        login_has_lock.set()
        assert allow_login.wait(timeout=10)
        return original_create_session(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(auth_routes, "create_operator_web_session", pause_after_login_lock)
    with _client(api_app) as client:
        client.get("/dashboard/login")
        csrf = _csrf(client)

        def submit_login() -> httpx2.Response:
            return client.post(
                "/dashboard/login",
                content=f"credential={operator.token}&_csrf={csrf}",
                headers={
                    "Origin": ORIGIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=False,
            )

        def rotate_key() -> IssuedOperatorApiKey:
            with get_session_factory().begin() as session:
                backend_pid = session.scalar(text("SELECT pg_backend_pid()"))
                assert backend_pid is not None
                rotate_backend_pid.append(int(backend_pid))
                rotate_started.set()
                return rotate_operator_api_key(session, key_id=operator.key_id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            login_future = executor.submit(submit_login)
            assert login_has_lock.wait(timeout=10)
            rotate_future = executor.submit(rotate_key)
            assert rotate_started.wait(timeout=10)
            _assert_backend_waits_for_row_lock(rotate_backend_pid[0])
            allow_login.set()
            assert login_future.result(timeout=10).status_code == 303
            replacement = rotate_future.result(timeout=10)

    with get_session_factory()() as session:
        replacements = session.scalars(
            select(OperatorApiKey).where(OperatorApiKey.rotated_from_id == operator.key_id)
        ).all()
        old_active_sessions = session.scalar(
            select(func.count())
            .select_from(OperatorWebSession)
            .where(
                OperatorWebSession.authenticated_by_api_key_id == operator.key_id,
                OperatorWebSession.revoked_at.is_(None),
            )
        )
        independent_stored = session.get(OperatorWebSession, independent_session.session_id)
        assert len(replacements) == 1
        assert replacements[0].id == replacement.key_id
        assert old_active_sessions == 0
        assert independent_stored is not None and independent_stored.revoked_at is None


def test_session_touch_is_atomic_and_never_shortens_concurrent_expiry(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    created_at = datetime.now(UTC)
    with get_session_factory().begin() as session:
        authenticated = authenticate_operator(session, operator.token, now=created_at)
        issued = web_sessions.create_operator_web_session(
            session,
            authenticated=authenticated,
            now=created_at,
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="touch-login",
        )
    barrier = Barrier(2)

    def touch(offset: int) -> None:
        with get_session_factory().begin() as session:
            barrier.wait(timeout=10)
            web_sessions.authenticate_web_session(
                session,
                issued.session_token,
                now=created_at + timedelta(seconds=offset),
                idle_seconds=1_800,
                touch_interval_seconds=300,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(touch, (301, 302)))

    with get_session_factory()() as session:
        stored = session.get(OperatorWebSession, issued.session_id)
        assert stored is not None
        assert stored.last_seen_at in {
            created_at + timedelta(seconds=301),
            created_at + timedelta(seconds=302),
        }
        assert stored.idle_expires_at >= created_at + timedelta(seconds=2_101)
        assert stored.idle_expires_at <= stored.absolute_expires_at


def test_rotation_audit_failure_rolls_back_key_replacement_and_session_revoke(
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        authenticated = authenticate_operator(session, operator.token, now=now)
        issued = web_sessions.create_operator_web_session(
            session,
            authenticated=authenticated,
            now=now,
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="rollback-login",
        )

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise ValueError("synthetic audit failure")

    monkeypatch.setattr(operator_services, "record_local_cli_action", fail_audit)
    with pytest.raises(ValueError, match="synthetic audit failure"):
        with get_session_factory().begin() as session:
            rotate_operator_api_key(session, key_id=operator.key_id, now=now + timedelta(seconds=1))

    with get_session_factory()() as session:
        key = session.get(OperatorApiKey, operator.key_id)
        stored = session.get(OperatorWebSession, issued.session_id)
        replacements = session.scalars(
            select(OperatorApiKey).where(OperatorApiKey.rotated_from_id == operator.key_id)
        ).all()
        assert key is not None and key.revoked_at is None
        assert stored is not None and stored.revoked_at is None
        assert replacements == []


def test_revoke_audit_failure_rolls_back_key_and_session_revoke(
    register_operator: OperatorFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        authenticated = authenticate_operator(session, operator.token, now=now)
        issued = web_sessions.create_operator_web_session(
            session,
            authenticated=authenticated,
            now=now,
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="revoke-rollback-login",
        )

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise ValueError("synthetic audit failure")

    monkeypatch.setattr(operator_services, "record_local_cli_action", fail_audit)
    with pytest.raises(ValueError, match="synthetic audit failure"):
        with get_session_factory().begin() as session:
            revoke_operator_api_key(session, key_id=operator.key_id, now=now + timedelta(seconds=1))

    with get_session_factory()() as session:
        key = session.get(OperatorApiKey, operator.key_id)
        stored = session.get(OperatorWebSession, issued.session_id)
        assert key is not None and key.revoked_at is None
        assert stored is not None and stored.revoked_at is None


def test_dashboard_security_headers_are_present_on_real_boundaries(
    api_app: object,
) -> None:
    with _client(api_app) as client:
        responses = [
            client.get("/dashboard/login"),
            client.get("/dashboard/"),
            client.post(
                "/dashboard/login",
                content="bad",
                headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
            ),
        ]
    for response in responses:
        for name, value in SECURITY_HEADERS.items():
            assert response.headers[name] == value


def test_get_logout_route_does_not_exist(api_app: object) -> None:
    with _client(api_app) as client:
        response = client.get("/dashboard/logout")
    assert response.status_code == 405


def test_credentials_and_cookie_values_never_reach_logs_audit_or_errors(
    api_app: object,
    register_operator: OperatorFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    caplog.set_level("INFO")
    with _client(api_app) as client:
        login_response = _login(client, operator)
        session_cookie = client.cookies.get("__Host-wg_session")
        csrf_cookie = _csrf(client)
        assert session_cookie is not None
        error_response = client.post(
            "/dashboard/logout",
            content="_csrf=malformed",
            headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
        )

    with get_session_factory()() as session:
        audit_text = "\n".join(
            f"{entry.action} {entry.details} {entry.request_id}"
            for entry in session.scalars(select(AuditLogEntry)).all()
        )
    boundary_text = login_response.text + error_response.text + audit_text
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    for canary in (operator.token, session_cookie, csrf_cookie):
        assert canary not in boundary_text
        assert canary not in log_text
