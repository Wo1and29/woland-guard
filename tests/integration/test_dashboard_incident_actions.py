"""PostgreSQL and HTTP regressions for Dashboard incident mutations."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from re import findall
from threading import Barrier, Event
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.session import SessionTransaction

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from tests.integration.test_dashboard_queries import _create_incident_with_evidence
from woland_guard_control_plane.application import incident_comments as comment_services
from woland_guard_control_plane.application.incident_comments import (
    COMMENT_IDEMPOTENCY_OPERATION,
    CommentOutcome,
    add_incident_comment,
    canonical_comment_hash,
    normalize_comment,
)
from woland_guard_control_plane.application.incident_workflow import (
    canonical_transition_hash,
    normalize_transition,
    transition_incident,
)
from woland_guard_control_plane.application.operator_authentication import (
    authenticate_operator,
)
from woland_guard_control_plane.application.operators import (
    issue_operator_api_key,
    revoke_operator_api_key,
    rotate_operator_api_key,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    InvalidWebSessionError,
    WebSessionPermissionError,
    authenticate_web_session_without_touch,
    create_operator_web_session,
    lock_web_session_for_mutation,
    web_token_digest,
)
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    Incident,
    IncidentComment,
    IncidentHistoryEntry,
    IncidentStatus,
    Operator,
    OperatorApiKey,
    OperatorIdempotencyRecord,
    OperatorRole,
    OperatorWebSession,
    OutboxMessage,
)
from woland_guard_control_plane.web.mutations import parse_dashboard_mutation_form
from woland_guard_control_plane.web.routes import incidents as incident_routes

pytestmark = pytest.mark.integration
ORIGIN = "https://localhost:8000"


def _client(api_app: object) -> TestClient:
    return TestClient(api_app, base_url=ORIGIN, raise_server_exceptions=False)  # type: ignore[arg-type]


def _login(client: TestClient, operator: RegisteredOperator) -> None:
    assert client.get("/dashboard/login").status_code == 200
    csrf = client.cookies.get("__Host-wg_csrf")
    assert csrf is not None
    response = client.post(
        "/dashboard/login",
        data={"credential": operator.token, "_csrf": csrf},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    value = client.cookies.get("__Host-wg_csrf")
    assert value is not None
    return value


def _session_token(client: TestClient) -> str:
    value = client.cookies.get("__Host-wg_session")
    assert value is not None
    return value


def _preauthenticate(token: str, settings: Settings) -> AuthenticatedWebSession:
    with get_session_factory().begin() as session:
        return authenticate_web_session_without_touch(
            session,
            token,
            now=datetime.now(UTC),
            idle_seconds=settings.web_session_idle_seconds,
            touch_interval_seconds=settings.web_session_touch_interval_seconds,
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


def test_comment_outcome_is_200_while_html_is_303_and_replay_is_single(
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with _client(api_app) as client:
        _login(client, operator)
        detail = client.get(f"/dashboard/incidents/{incident_id}")
        assert detail.status_code == 200
        keys = findall(r'name="idempotency_key" value="([^"]+)"', detail.text)
        assert len(keys) == 2
        for value in keys:
            assert str(UUID(value)) == value
        form = {
            "_csrf": _csrf(client),
            "comment": "Synthetic comment",
            "idempotency_key": keys[1],
        }
        first = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data=form,
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        replay = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data=form,
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    assert first.status_code == 303
    assert replay.status_code == 303
    assert replay.headers["Idempotency-Replayed"] == "true"
    with get_session_factory()() as session:
        records = session.scalars(
            select(OperatorIdempotencyRecord).where(
                OperatorIdempotencyRecord.operation == COMMENT_IDEMPOTENCY_OPERATION
            )
        ).all()
        assert len(records) == 1
        assert records[0].response_status == 200
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "incident.comment_added")
            )
            == 1
        )
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0
        assert "Synthetic comment" not in str(records[0].response_body)
    del integration_settings


def test_comment_idempotency_key_reuse_with_different_body_is_safe_409(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    key = str(uuid4())
    with _client(api_app) as client:
        _login(client, operator)
        first = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data={"_csrf": _csrf(client), "comment": "First", "idempotency_key": key},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        conflict = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data={"_csrf": _csrf(client), "comment": "Second", "idempotency_key": key},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
    assert first.status_code == 303
    assert conflict.status_code == 409
    assert "First" not in conflict.text and "Second" not in conflict.text
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "incident.comment_added")
            )
            == 1
        )
        assert session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) == 1


def test_missing_incident_comment_outcome_is_stored_as_404_and_replayed(
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    missing_incident_id = uuid4()
    with _client(api_app) as client:
        _login(client, operator)
        token = _session_token(client)
    preliminary = _preauthenticate(token, integration_settings)
    comment = normalize_comment("Missing incident")
    key = str(uuid4())
    request_hash = canonical_comment_hash(missing_incident_id, comment)
    with get_session_factory().begin() as session:
        first = add_incident_comment(
            session,
            actor=preliminary.principal,
            incident_id=missing_incident_id,
            comment=comment,
            idempotency_key=key,
            canonical_request_hash=request_hash,
            request_id="missing-first",
        )
    with get_session_factory().begin() as session:
        replay = add_incident_comment(
            session,
            actor=preliminary.principal,
            incident_id=missing_incident_id,
            comment=comment,
            idempotency_key=key,
            canonical_request_hash=request_hash,
            request_id="missing-replay",
        )
    assert (first.http_status, first.replayed) == (404, False)
    assert (replay.http_status, replay.replayed) == (404, True)
    with get_session_factory()() as session:
        record = session.scalar(select(OperatorIdempotencyRecord))
        assert record is not None and record.response_status == 404
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 0


def test_status_html_uses_existing_workflow_and_never_enqueues_notification(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with _client(api_app) as client:
        _login(client, operator)
        response = client.post(
            f"/dashboard/incidents/{incident_id}/transitions",
            data={
                "_csrf": _csrf(client),
                "status": "investigating",
                "expected_version": "1",
                "reason": "",
                "idempotency_key": str(uuid4()),
            },
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
    assert response.status_code == 303
    with get_session_factory()() as session:
        incident = session.get(Incident, incident_id)
        assert incident is not None
        assert (incident.status, incident.lock_version) == ("investigating", 2)
        history = session.scalars(
            select(IncidentHistoryEntry)
            .where(IncidentHistoryEntry.incident_id == incident_id)
            .order_by(IncidentHistoryEntry.version)
        ).all()
        assert [row.entry_type for row in history] == ["baseline", "status_transition"]
        assert history[-1].auth_method_type == "web_session"
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0


def test_terminal_incident_accepts_one_idempotent_comment_without_state_change(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    comment_key = str(uuid4())
    comment_text = "Terminal incident follow-up"

    with _client(api_app) as client:
        _login(client, operator)
        transitioned = client.post(
            f"/dashboard/incidents/{incident_id}/transitions",
            data={
                "_csrf": _csrf(client),
                "status": "resolved",
                "expected_version": "1",
                "reason": "Synthetic resolution",
                "idempotency_key": str(uuid4()),
            },
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        assert transitioned.status_code == 303

        with get_session_factory()() as session:
            incident_before = session.get(Incident, incident_id)
            assert incident_before is not None
            state_before = (incident_before.status, incident_before.lock_version)
            history_before = session.scalar(
                select(func.count())
                .select_from(IncidentHistoryEntry)
                .where(IncidentHistoryEntry.incident_id == incident_id)
            )
            outbox_before = session.scalar(select(func.count()).select_from(OutboxMessage))

        form = {
            "_csrf": _csrf(client),
            "comment": comment_text,
            "idempotency_key": comment_key,
        }
        created = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data=form,
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        replay = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data=form,
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    assert created.status_code == 303
    assert replay.status_code == 303
    assert replay.headers["Idempotency-Replayed"] == "true"
    with get_session_factory()() as session:
        incident_after = session.get(Incident, incident_id)
        assert incident_after is not None
        assert state_before == (IncidentStatus.RESOLVED.value, 2)
        assert (incident_after.status, incident_after.lock_version) == state_before
        assert (
            session.scalar(
                select(func.count())
                .select_from(IncidentHistoryEntry)
                .where(IncidentHistoryEntry.incident_id == incident_id)
            )
            == history_before
        )
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == outbox_before
        assert (
            session.scalar(
                select(func.count())
                .select_from(IncidentComment)
                .where(IncidentComment.incident_id == incident_id)
            )
            == 1
        )
        audits = session.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "incident.comment_added")
        ).all()
        assert len(audits) == 1
        assert audits[0].details == {"incident_id": str(incident_id)}
        assert comment_text not in str(audits[0].details)


def test_concurrent_status_transition_and_comment_both_commit_without_partial_rows(
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    transition_operator = register_operator(role=OperatorRole.ANALYST)
    comment_operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with _client(api_app) as transition_client:
        _login(transition_client, transition_operator)
        transition_token = _session_token(transition_client)
    with _client(api_app) as comment_client:
        _login(comment_client, comment_operator)
        comment_token = _session_token(comment_client)

    preliminary_transition = _preauthenticate(transition_token, integration_settings)
    preliminary_comment = _preauthenticate(comment_token, integration_settings)
    transition = normalize_transition(
        target_status=IncidentStatus.INVESTIGATING,
        expected_version=1,
        reason=None,
    )
    comment_text = "Concurrent synthetic comment"
    comment = normalize_comment(comment_text)
    transition_key = str(uuid4())
    comment_key = str(uuid4())
    start_barrier = Barrier(2)
    mutation_barrier = Barrier(2)

    def submit_transition() -> int:
        with get_session_factory().begin() as session:
            start_barrier.wait()
            actor = lock_web_session_for_mutation(
                session,
                authenticated=preliminary_transition,
                session_token=transition_token,
                required_permission=Permission.TRANSITION_INCIDENTS,
                now=datetime.now(UTC),
            )
            mutation_barrier.wait()
            outcome = transition_incident(
                session,
                actor=actor,
                incident_id=incident_id,
                transition=transition,
                idempotency_key=transition_key,
                canonical_request_hash=canonical_transition_hash(incident_id, transition),
                request_id="concurrent-status",
            )
            return outcome.http_status

    def submit_comment() -> int:
        with get_session_factory().begin() as session:
            start_barrier.wait()
            actor = lock_web_session_for_mutation(
                session,
                authenticated=preliminary_comment,
                session_token=comment_token,
                required_permission=Permission.COMMENT_INCIDENTS,
                now=datetime.now(UTC),
            )
            mutation_barrier.wait()
            outcome = add_incident_comment(
                session,
                actor=actor,
                incident_id=incident_id,
                comment=comment,
                idempotency_key=comment_key,
                canonical_request_hash=canonical_comment_hash(incident_id, comment),
                request_id="concurrent-comment",
            )
            return outcome.http_status

    with ThreadPoolExecutor(max_workers=2) as executor:
        status_future = executor.submit(submit_transition)
        comment_future = executor.submit(submit_comment)
        assert status_future.result(timeout=10) == 200
        assert comment_future.result(timeout=10) == 200

    with get_session_factory()() as session:
        incident = session.get(Incident, incident_id)
        assert incident is not None
        assert (incident.status, incident.lock_version) == (
            IncidentStatus.INVESTIGATING.value,
            2,
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(IncidentHistoryEntry)
                .where(
                    IncidentHistoryEntry.incident_id == incident_id,
                    IncidentHistoryEntry.entry_type == "status_transition",
                )
            )
            == 1
        )
        comments = session.scalars(
            select(IncidentComment).where(IncidentComment.incident_id == incident_id)
        ).all()
        assert len(comments) == 1
        assert comments[0].body == comment_text
        audits = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action.in_(("incident.status_changed", "incident.comment_added"))
            )
        ).all()
        assert sorted(row.action for row in audits) == [
            "incident.comment_added",
            "incident.status_changed",
        ]
        comment_audit = next(row for row in audits if row.action == "incident.comment_added")
        assert comment_audit.details == {"incident_id": str(incident_id)}
        assert comment_text not in str(comment_audit.details)
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0
        operations = session.scalars(
            select(OperatorIdempotencyRecord.operation).where(
                OperatorIdempotencyRecord.resource_id == incident_id
            )
        ).all()
        assert sorted(operations) == [
            "incident.comment.create.v1",
            "incident.status.transition.v1",
        ]


def test_comment_is_escaped_in_html_and_absent_from_audit_and_outbox(
    api_app: object,
    caplog: pytest.LogCaptureFixture,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    incident_id, _ = _create_incident_with_evidence()
    canary = '<script data-secret="canary-comment">alert(1)</script>'
    with _client(api_app) as client:
        _login(client, operator)
        response = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data={
                "_csrf": _csrf(client),
                "comment": canary,
                "idempotency_key": str(uuid4()),
            },
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        assert response.status_code == 303
        rendered = client.get(response.headers["location"])
    assert rendered.status_code == 200
    assert canary not in rendered.text
    assert str(escape(canary)) in rendered.text
    messages = [record.getMessage() for record in caplog.records]
    assert all(canary not in message for message in messages)
    with get_session_factory()() as session:
        audit = session.scalar(
            select(AuditLogEntry).where(AuditLogEntry.action == "incident.comment_added")
        )
        assert audit is not None
        assert audit.details == {"incident_id": str(incident_id)}
        assert canary not in str(audit.details)
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0


@pytest.mark.parametrize(
    "failure",
    ["origin_missing", "origin_wrong", "csrf_missing", "csrf_wrong", "csrf_other_session"],
)
def test_rejected_comment_request_does_not_touch_or_mutate_session(
    failure: str,
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with _client(api_app) as client:
        _login(client, operator)
        token = _session_token(client)
        csrf = _csrf(client)
        if failure == "csrf_other_session":
            other = register_operator(role=OperatorRole.ANALYST)
            with _client(api_app) as other_client:
                _login(other_client, other)
                submitted_csrf = _csrf(other_client)
        else:
            submitted_csrf = "invalid" if failure == "csrf_wrong" else csrf

        digest = web_token_digest(token)
        assert digest is not None
        now = datetime.now(UTC)
        with get_session_factory().begin() as session:
            stored = session.scalar(
                select(OperatorWebSession).where(OperatorWebSession.token_digest == digest)
            )
            assert stored is not None
            stored.created_at = now - timedelta(hours=1)
            stored.last_seen_at = now - timedelta(minutes=10)
            stored.idle_expires_at = now + timedelta(minutes=30)
            stored.updated_at = now - timedelta(minutes=10)
            before = (stored.last_seen_at, stored.idle_expires_at, stored.updated_at)

        form = {"comment": "Must not persist", "idempotency_key": str(uuid4())}
        if failure != "csrf_missing":
            form["_csrf"] = submitted_csrf
        headers: dict[str, str] = {}
        if failure != "origin_missing":
            headers["Origin"] = "https://wrong.invalid" if failure == "origin_wrong" else ORIGIN
        response = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data=form,
            headers=headers,
            follow_redirects=False,
        )

    assert response.status_code in {403, 422}
    assert "Must not persist" not in response.text
    with get_session_factory()() as session:
        stored = session.scalar(
            select(OperatorWebSession).where(OperatorWebSession.token_digest == digest)
        )
        assert stored is not None
        assert (stored.last_seen_at, stored.idle_expires_at, stored.updated_at) == before
        assert stored.revoked_at is None
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 0
        assert session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "incident.comment_added")
            )
            == 0
        )


def test_comment_audit_failure_rolls_back_all_rows_and_returns_safe_error(
    api_app: object,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    canary = "canary-comment-audit-failure"

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError(canary)

    monkeypatch.setattr(comment_services, "record_operator_action", fail_audit)
    with _client(api_app) as client:
        _login(client, operator)
        response = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data={
                "_csrf": _csrf(client),
                "comment": "Rollback comment",
                "idempotency_key": str(uuid4()),
            },
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
    assert response.status_code == 500
    assert canary not in response.text
    assert all(canary not in record.getMessage() for record in caplog.records)
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 0
        assert session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) == 0
        assert session.scalar(select(func.count()).select_from(OutboxMessage)) == 0


def test_comment_commit_failure_rolls_back_and_never_returns_success(
    api_app: object,
    monkeypatch: pytest.MonkeyPatch,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    original_commit = SessionTransaction.commit
    commit_count = 0

    def fail_mutation_commit(
        transaction: SessionTransaction,
        _to_root: bool = False,
    ) -> None:
        nonlocal commit_count
        commit_count += 1
        if commit_count == 2:
            raise SQLAlchemyError("synthetic private commit failure")
        original_commit(transaction, _to_root)

    with _client(api_app) as client:
        _login(client, operator)
        monkeypatch.setattr(SessionTransaction, "commit", fail_mutation_commit)
        response = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data={
                "_csrf": _csrf(client),
                "comment": "Rollback on commit",
                "idempotency_key": str(uuid4()),
            },
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
    assert response.status_code == 503
    assert response.status_code != 303
    assert "private commit failure" not in response.text
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 0
        assert session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "incident.comment_added")
            )
            == 0
        )


@pytest.mark.parametrize("change", ["role", "inactive"])
def test_locked_revalidation_ignores_stale_preliminary_principal(
    change: str,
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        _login(client, operator)
        token = _session_token(client)
    preliminary = _preauthenticate(token, integration_settings)
    assert preliminary.principal.role is OperatorRole.ANALYST
    with get_session_factory().begin() as session:
        stored_operator = session.get(Operator, operator.operator_id)
        assert stored_operator is not None
        if change == "role":
            stored_operator.role = OperatorRole.VIEWER.value
        else:
            stored_operator.is_active = False

    expected_error = WebSessionPermissionError if change == "role" else InvalidWebSessionError
    with pytest.raises(expected_error):
        with get_session_factory().begin() as session:
            lock_web_session_for_mutation(
                session,
                authenticated=preliminary,
                session_token=token,
                required_permission=Permission.COMMENT_INCIDENTS,
                now=datetime.now(UTC),
            )
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 0
        assert session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) == 0


@pytest.mark.parametrize(("change", "expected_status"), [("role", 403), ("inactive", 401)])
def test_http_mutation_revalidates_current_operator_after_preliminary_auth(
    change: str,
    expected_status: int,
    api_app: object,
    monkeypatch: pytest.MonkeyPatch,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    original_parser = parse_dashboard_mutation_form
    changed = False

    def change_operator_after_preliminary_auth(*args: object, **kwargs: object) -> dict[str, str]:
        nonlocal changed
        result = original_parser(*args, **kwargs)  # type: ignore[arg-type]
        if not changed:
            with get_session_factory().begin() as session:
                stored = session.get(Operator, operator.operator_id)
                assert stored is not None
                if change == "role":
                    stored.role = OperatorRole.VIEWER.value
                else:
                    stored.is_active = False
            changed = True
        return result

    monkeypatch.setattr(
        incident_routes,
        "parse_dashboard_mutation_form",
        change_operator_after_preliminary_auth,
    )
    with _client(api_app) as client:
        _login(client, operator)
        response = client.post(
            f"/dashboard/incidents/{incident_id}/comments",
            data={
                "_csrf": _csrf(client),
                "comment": "Must not be accepted",
                "idempotency_key": str(uuid4()),
            },
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
    assert response.status_code == expected_status
    assert "Must not be accepted" not in response.text
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 0
        assert session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "incident.comment_added")
            )
            == 0
        )


def test_same_comment_key_is_concurrently_inserted_once(
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with _client(api_app) as client:
        _login(client, operator)
        token = _session_token(client)
    preliminary = _preauthenticate(token, integration_settings)
    normalized = normalize_comment("Concurrent comment")
    key = str(uuid4())
    request_hash = canonical_comment_hash(incident_id, normalized)
    barrier = Barrier(2)

    def submit(request_id: str) -> CommentOutcome:
        with get_session_factory().begin() as session:
            barrier.wait()
            return add_incident_comment(
                session,
                actor=preliminary.principal,
                incident_id=incident_id,
                comment=normalized,
                idempotency_key=key,
                canonical_request_hash=request_hash,
                request_id=request_id,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(submit, ("parallel-a", "parallel-b")))
    assert [outcome.http_status for outcome in outcomes] == [200, 200]
    assert sorted(outcome.replayed for outcome in outcomes) == [False, True]
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "incident.comment_added")
            )
            == 1
        )


def test_mutation_session_lock_serializes_concurrent_revoke(
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with _client(api_app) as client:
        _login(client, operator)
        token = _session_token(client)
    preliminary = _preauthenticate(token, integration_settings)
    locked = Event()
    release = Event()
    revoke_pid: list[int] = []
    revoke_started = Event()

    def mutation() -> None:
        with get_session_factory().begin() as session:
            actor = lock_web_session_for_mutation(
                session,
                authenticated=preliminary,
                session_token=token,
                required_permission=Permission.COMMENT_INCIDENTS,
                now=datetime.now(UTC),
            )
            locked.set()
            assert release.wait(timeout=10)
            normalized = normalize_comment("Committed before revoke")
            add_incident_comment(
                session,
                actor=actor,
                incident_id=incident_id,
                comment=normalized,
                idempotency_key=str(uuid4()),
                canonical_request_hash=canonical_comment_hash(incident_id, normalized),
                request_id="lock-first",
            )

    def revoke() -> int:
        assert locked.wait(timeout=10)
        with get_session_factory().begin() as session:
            revoke_pid.append(int(session.scalar(text("SELECT pg_backend_pid()"))))
            revoke_started.set()
            return int(
                revoke_operator_api_key(
                    session,
                    key_id=operator.key_id,
                    now=datetime.now(UTC),
                )
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        mutation_future = executor.submit(mutation)
        assert locked.wait(timeout=10)
        revoke_future = executor.submit(revoke)
        assert revoke_started.wait(timeout=10)
        _assert_backend_waits_for_row_lock(revoke_pid[0])
        release.set()
        mutation_future.result(timeout=10)
        assert revoke_future.result(timeout=10) == 1
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 1
        stored = session.get(OperatorWebSession, preliminary.session_id)
        assert stored is not None and stored.revoked_at is not None


def test_revoke_commit_first_prevents_waiting_mutation(
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        _login(client, operator)
        token = _session_token(client)
    preliminary = _preauthenticate(token, integration_settings)
    revoked_but_open = Event()
    allow_commit = Event()
    mutation_pid: list[int] = []
    mutation_started = Event()

    def revoke() -> None:
        with get_session_factory().begin() as session:
            assert revoke_operator_api_key(
                session,
                key_id=operator.key_id,
                now=datetime.now(UTC),
            )
            revoked_but_open.set()
            assert allow_commit.wait(timeout=10)

    def mutation() -> None:
        assert revoked_but_open.wait(timeout=10)
        with pytest.raises(InvalidWebSessionError):
            with get_session_factory().begin() as session:
                mutation_pid.append(int(session.scalar(text("SELECT pg_backend_pid()"))))
                mutation_started.set()
                lock_web_session_for_mutation(
                    session,
                    authenticated=preliminary,
                    session_token=token,
                    required_permission=Permission.COMMENT_INCIDENTS,
                    now=datetime.now(UTC),
                )

    with ThreadPoolExecutor(max_workers=2) as executor:
        revoke_future = executor.submit(revoke)
        assert revoked_but_open.wait(timeout=10)
        mutation_future = executor.submit(mutation)
        assert mutation_started.wait(timeout=10)
        _assert_backend_waits_for_row_lock(mutation_pid[0])
        allow_commit.set()
        revoke_future.result(timeout=10)
        mutation_future.result(timeout=10)
    with get_session_factory()() as session:
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 0
        assert session.scalar(select(func.count()).select_from(OperatorIdempotencyRecord)) == 0


def test_mutation_session_lock_serializes_rotation_and_preserves_other_key_sessions(
    api_app: object,
    integration_settings: Settings,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        independent_key = issue_operator_api_key(
            session,
            operator_id=operator.operator_id,
            label="independent-mutation-key",
            now=now,
        )
        independent_auth = authenticate_operator(session, independent_key.token, now=now)
        independent_session = create_operator_web_session(
            session,
            authenticated=independent_auth,
            now=now,
            idle_seconds=integration_settings.web_session_idle_seconds,
            absolute_seconds=integration_settings.web_session_absolute_seconds,
            request_id="independent-mutation-session",
        )
    with _client(api_app) as client:
        _login(client, operator)
        token = _session_token(client)
    preliminary = _preauthenticate(token, integration_settings)
    mutation_locked = Event()
    allow_mutation_commit = Event()
    rotation_started = Event()
    rotation_pid: list[int] = []

    def mutation() -> None:
        with get_session_factory().begin() as session:
            actor = lock_web_session_for_mutation(
                session,
                authenticated=preliminary,
                session_token=token,
                required_permission=Permission.COMMENT_INCIDENTS,
                now=datetime.now(UTC),
            )
            mutation_locked.set()
            assert allow_mutation_commit.wait(timeout=10)
            normalized = normalize_comment("Committed before rotation")
            add_incident_comment(
                session,
                actor=actor,
                incident_id=incident_id,
                comment=normalized,
                idempotency_key=str(uuid4()),
                canonical_request_hash=canonical_comment_hash(incident_id, normalized),
                request_id="rotation-lock-first",
            )

    def rotate() -> UUID:
        assert mutation_locked.wait(timeout=10)
        with get_session_factory().begin() as session:
            rotation_pid.append(int(session.scalar(text("SELECT pg_backend_pid()"))))
            rotation_started.set()
            return rotate_operator_api_key(session, key_id=operator.key_id).key_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        mutation_future = executor.submit(mutation)
        assert mutation_locked.wait(timeout=10)
        rotation_future = executor.submit(rotate)
        assert rotation_started.wait(timeout=10)
        _assert_backend_waits_for_row_lock(rotation_pid[0])
        allow_mutation_commit.set()
        mutation_future.result(timeout=10)
        replacement_id = rotation_future.result(timeout=10)

    with get_session_factory()() as session:
        replacement = session.scalar(
            select(OperatorApiKey).where(OperatorApiKey.rotated_from_id == operator.key_id)
        )
        old_session = session.get(OperatorWebSession, preliminary.session_id)
        independent_stored = session.get(OperatorWebSession, independent_session.session_id)
        assert replacement is not None and replacement.id == replacement_id
        assert old_session is not None and old_session.revoked_at is not None
        assert independent_stored is not None and independent_stored.revoked_at is None
        assert session.scalar(select(func.count()).select_from(IncidentComment)) == 1


def test_get_mutation_routes_are_html_405(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with _client(api_app) as client:
        _login(client, operator)
        for suffix in ("transitions", "comments"):
            response = client.get(f"/dashboard/incidents/{incident_id}/{suffix}")
            assert response.status_code == 405
            assert response.headers["content-type"].startswith("text/html")
