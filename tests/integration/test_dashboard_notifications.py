"""PostgreSQL and HTTP regressions for the Dashboard Telegram settings page (ADR-0024)."""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from woland_guard_control_plane.application.notification_destinations import (
    DestinationSummary,
    create_telegram_destination,
)
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    NotificationDestination,
    NotificationSeverity,
    OperatorRole,
)

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


def _always_ready(_name: str) -> bool:
    return True


def _create_enabled_destination() -> DestinationSummary:
    with get_session_factory().begin() as session:
        created = create_telegram_destination(
            session,
            chat_id=(uuid4().int % (2**52 - 1)) + 1,
            token_file_name=f"{uuid4().hex}.token",
            minimum_severity=NotificationSeverity.HIGH,
            staging_readiness=_always_ready,
        )
        destination = session.get(NotificationDestination, created.destination_id)
        assert destination is not None
        destination.enabled = True
    return created


def test_analyst_cannot_reach_the_settings_page(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    """VIEWER lacks ACCESS_DASHBOARD entirely and cannot log in at all; ANALYST
    can use the dashboard but was never granted MANAGE_TELEGRAM_DESTINATIONS."""

    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        _login(client, operator)
        response = client.get("/dashboard/notifications")
        assert response.status_code == 403


def test_admin_sees_the_destination_and_no_enable_control(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    admin = register_operator(role=OperatorRole.ADMIN)
    _create_enabled_destination()
    with _client(api_app) as client:
        _login(client, admin)
        response = client.get("/dashboard/notifications")

    assert response.status_code == 200
    assert "/disable" in response.text
    # Enabling requires a staging check control-plane cannot perform (ADR-0024).
    assert "/enable" not in response.text


def test_disable_is_audited_as_the_operator_not_local_cli(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    admin = register_operator(role=OperatorRole.ADMIN)
    created = _create_enabled_destination()
    with _client(api_app) as client:
        _login(client, admin)
        response = client.post(
            f"/dashboard/notifications/{created.destination_id}/disable",
            data={"_csrf": _csrf(client)},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    assert response.status_code == 303
    with get_session_factory()() as session:
        destination = session.get(NotificationDestination, created.destination_id)
        assert destination is not None
        assert destination.enabled is False
        entry = session.execute(
            select(AuditLogEntry).where(
                AuditLogEntry.action == "notification_destination.disabled_by_operator"
            )
        ).scalar_one()
        assert entry.actor_type == "operator"
        assert entry.operator_id == admin.operator_id
        assert entry.actor_username_snapshot == admin.username


def test_disabling_twice_is_a_harmless_no_op_not_a_duplicate_audit_entry(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    admin = register_operator(role=OperatorRole.ADMIN)
    created = _create_enabled_destination()
    with _client(api_app) as client:
        _login(client, admin)
        for _ in range(2):
            response = client.post(
                f"/dashboard/notifications/{created.destination_id}/disable",
                data={"_csrf": _csrf(client)},
                headers={"Origin": ORIGIN},
                follow_redirects=False,
            )
            assert response.status_code == 303

    with get_session_factory()() as session:
        count = session.scalar(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.action == "notification_destination.disabled_by_operator")
        )
        assert count == 1


def test_severity_change_is_audited_with_both_values(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    admin = register_operator(role=OperatorRole.ADMIN)
    created = _create_enabled_destination()
    assert created.minimum_severity == "high"
    with _client(api_app) as client:
        _login(client, admin)
        response = client.post(
            f"/dashboard/notifications/{created.destination_id}/severity",
            data={"_csrf": _csrf(client), "minimum_severity": "low"},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    assert response.status_code == 303
    with get_session_factory()() as session:
        destination = session.get(NotificationDestination, created.destination_id)
        assert destination is not None
        assert destination.minimum_severity == "low"
        entry = session.execute(
            select(AuditLogEntry).where(
                AuditLogEntry.action
                == "notification_destination.minimum_severity_changed_by_operator"
            )
        ).scalar_one()
        assert entry.details == {
            "adapter_kind": "telegram",
            "from_minimum_severity": "high",
            "to_minimum_severity": "low",
        }


def test_an_invalid_severity_value_is_rejected_without_a_stack_trace(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    admin = register_operator(role=OperatorRole.ADMIN)
    created = _create_enabled_destination()
    with _client(api_app) as client:
        _login(client, admin)
        response = client.post(
            f"/dashboard/notifications/{created.destination_id}/severity",
            data={"_csrf": _csrf(client), "minimum_severity": "not-a-severity"},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    assert response.status_code == 422


def test_disable_without_a_valid_csrf_token_is_rejected(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    admin = register_operator(role=OperatorRole.ADMIN)
    created = _create_enabled_destination()
    with _client(api_app) as client:
        _login(client, admin)
        response = client.post(
            f"/dashboard/notifications/{created.destination_id}/disable",
            data={"_csrf": "synthetic-wrong-token"},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    assert response.status_code == 403
    with get_session_factory()() as session:
        destination = session.get(NotificationDestination, created.destination_id)
        assert destination is not None
        assert destination.enabled is True


def test_mutation_from_a_foreign_origin_is_rejected(
    api_app: object,
    register_operator: OperatorFactory,
) -> None:
    admin = register_operator(role=OperatorRole.ADMIN)
    created = _create_enabled_destination()
    with _client(api_app) as client:
        _login(client, admin)
        response = client.post(
            f"/dashboard/notifications/{created.destination_id}/disable",
            data={"_csrf": _csrf(client)},
            headers={"Origin": "https://attacker.invalid"},
            follow_redirects=False,
        )

    assert response.status_code == 403
    with get_session_factory()() as session:
        destination = session.get(NotificationDestination, created.destination_id)
        assert destination is not None
        assert destination.enabled is True
