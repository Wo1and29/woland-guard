"""PostgreSQL integration tests for stage 6A operator identity and RBAC."""

import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from typing import Annotated
from uuid import UUID

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from woland_guard_control_plane import cli
from woland_guard_control_plane.api.dependencies import (
    get_authenticated_operator,
    require_permission,
)
from woland_guard_control_plane.application.operator_authentication import (
    AuthenticatedOperator,
    InvalidOperatorCredentialsError,
    authenticate_operator,
)
from woland_guard_control_plane.application.operator_keys import generate_operator_api_key
from woland_guard_control_plane.application.operators import (
    IssuedOperatorApiKey,
    OperatorManagementError,
    rotate_operator_api_key,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    OperatorApiKey,
    OperatorRole,
)
from woland_guard_control_plane.main import create_app

pytestmark = pytest.mark.integration

_TEST_IDENTITY_PATH = "/test-only/operator-identity"
_TEST_PERMISSION_PATH = "/test-only/operator-permission"


def _headers(operator: RegisteredOperator, request_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {operator.token}",
        "X-Request-ID": request_id,
    }


def _add_identity_route(application: FastAPI) -> None:
    def identity(
        operator: Annotated[AuthenticatedOperator, Depends(get_authenticated_operator)],
    ) -> dict[str, str]:
        return {
            "operator_id": str(operator.operator_id),
            "username": operator.username,
            "role": operator.role.value,
        }

    application.add_api_route(
        _TEST_IDENTITY_PATH,
        identity,
        methods=["GET"],
        include_in_schema=False,
    )


def _add_permission_route(application: FastAPI, permission: Permission) -> None:
    dependency = require_permission(permission)

    def authorized(
        operator: Annotated[AuthenticatedOperator, Depends(dependency)],
    ) -> dict[str, str]:
        return {"operator_id": str(operator.operator_id)}

    application.add_api_route(
        _TEST_PERMISSION_PATH,
        authorized,
        methods=["GET"],
        include_in_schema=False,
    )


def test_operator_api_dependency_authenticates_and_updates_last_used_at(
    api_app: FastAPI,
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    _add_identity_route(api_app)

    with TestClient(api_app) as client:
        response = client.get(
            _TEST_IDENTITY_PATH,
            headers=_headers(operator, "operator-authentication-success"),
        )

    assert response.status_code == 200
    assert response.json() == {
        "operator_id": str(operator.operator_id),
        "username": operator.username,
        "role": "analyst",
    }
    with get_session_factory()() as session:
        stored_key = session.get(OperatorApiKey, operator.key_id)
        assert stored_key is not None
        assert stored_key.last_used_at is not None


@pytest.mark.parametrize(
    "credential_state",
    ["unknown", "wrong-secret", "revoked", "expired", "inactive"],
)
def test_unusable_operator_credentials_have_one_safe_response_and_no_usage_update(
    api_app: FastAPI,
    register_operator: OperatorFactory,
    credential_state: str,
) -> None:
    now = datetime.now(UTC)
    if credential_state == "unknown":
        operator = register_operator()
        token = generate_operator_api_key().token
    elif credential_state == "wrong-secret":
        operator = register_operator()
        replacement = "A" if operator.token[-1] != "A" else "B"
        token = f"{operator.token[:-1]}{replacement}"
    elif credential_state == "revoked":
        operator = register_operator(revoked_at=now)
        token = operator.token
    elif credential_state == "expired":
        operator = register_operator(expires_at=now - timedelta(seconds=1))
        token = operator.token
    else:
        operator = register_operator(is_active=False)
        token = operator.token
    _add_identity_route(api_app)

    with TestClient(api_app) as client:
        response = client.get(
            _TEST_IDENTITY_PATH,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Request-ID": f"operator-auth-{credential_state}",
            },
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid operator credentials"
    assert response.headers["www-authenticate"] == "Bearer"
    assert token not in response.text
    with get_session_factory()() as session:
        stored_key = session.get(OperatorApiKey, operator.key_id)
        assert stored_key is not None
        assert stored_key.last_used_at is None


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic synthetic", "Bearer", "Bearer too many parts", "Bearer wgak_wrong.kind"],
)
def test_malformed_operator_authorization_header_is_rejected_safely(
    api_app: FastAPI,
    authorization: str | None,
) -> None:
    _add_identity_route(api_app)
    headers = {"X-Request-ID": "operator-malformed-authorization"}
    if authorization is not None:
        headers["Authorization"] = authorization

    with TestClient(api_app) as client:
        response = client.get(_TEST_IDENTITY_PATH, headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid operator credentials"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    ("role", "permission", "expected_status"),
    [
        (OperatorRole.VIEWER, Permission.VIEW_INCIDENTS, 200),
        (OperatorRole.VIEWER, Permission.TRANSITION_INCIDENTS, 403),
        (OperatorRole.ANALYST, Permission.TRANSITION_INCIDENTS, 200),
        (OperatorRole.ANALYST, Permission.VIEW_AUDIT_LOG, 403),
        (OperatorRole.ADMIN, Permission.MANAGE_OPERATORS, 200),
        (OperatorRole.ADMIN, Permission.MANAGE_TELEGRAM_DESTINATIONS, 200),
    ],
)
def test_api_permission_dependency_enforces_central_matrix(
    api_app: FastAPI,
    register_operator: OperatorFactory,
    role: OperatorRole,
    permission: Permission,
    expected_status: int,
) -> None:
    operator = register_operator(role=role)
    _add_permission_route(api_app, permission)

    with TestClient(api_app) as client:
        response = client.get(
            _TEST_PERMISSION_PATH,
            headers=_headers(operator, f"rbac-{role.value}-{permission.value.replace(':', '-')}"),
        )

    assert response.status_code == expected_status
    if expected_status == 403:
        assert response.json()["detail"] == "insufficient operator permission"


def test_invalid_authentication_logs_are_sanitized_and_rate_limited(
    integration_settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = integration_settings.model_copy(
        update={"operator_security_log_events": 2, "operator_security_log_window_seconds": 60}
    )
    application = create_app(settings)
    _add_identity_route(application)
    tokens = [generate_operator_api_key().token for _ in range(5)]

    with (
        caplog.at_level(logging.WARNING, logger="uvicorn.error"),
        TestClient(application) as client,
    ):
        responses = [
            client.get(
                _TEST_IDENTITY_PATH,
                headers={"Authorization": f"Bearer {token}"},
            )
            for token in tokens
        ]

    assert {response.status_code for response in responses} == {401}
    authentication_events = [
        record.message
        for record in caplog.records
        if "security_event=operator_authentication_failed" in record.message
    ]
    assert len(authentication_events) == 2
    combined_logs = " ".join(record.getMessage() for record in caplog.records)
    assert all(token not in combined_logs for token in tokens)


def test_cli_create_issue_rotate_and_revoke_operator_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "create-operator", "--username", "cli-operator", "--role", "admin"],
    )
    cli.main()
    created = _output_map(capsys.readouterr().out)
    operator_id = UUID(created["operator_id"])
    first_expiry = datetime.now(UTC) + timedelta(days=1)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "woland-guard-admin",
            "issue-operator-key",
            "--operator-id",
            str(operator_id),
            "--label",
            "cli-synthetic",
            "--expires-at",
            first_expiry.isoformat(),
        ],
    )
    cli.main()
    issued = _output_map(capsys.readouterr().out)
    first_key_id = UUID(issued["key_id"])
    first_token = issued["token"]
    assert first_token.startswith("wgok_")

    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "rotate-operator-key", "--key-id", str(first_key_id)],
    )
    cli.main()
    rotated = _output_map(capsys.readouterr().out)
    second_key_id = UUID(rotated["key_id"])
    second_token = rotated["token"]
    assert rotated["rotated_from_id"] == str(first_key_id)
    assert second_token != first_token

    now = datetime.now(UTC)
    with get_session_factory()() as session:
        with pytest.raises(InvalidOperatorCredentialsError):
            authenticate_operator(session, first_token, now=now)
        authenticated = authenticate_operator(session, second_token, now=now)
        assert authenticated.operator_id == operator_id
        stored_keys = session.scalars(
            select(OperatorApiKey).order_by(OperatorApiKey.created_at)
        ).all()
        assert len(stored_keys) == 2
        assert stored_keys[0].revoked_at is not None
        assert stored_keys[1].rotated_from_id == stored_keys[0].id
        assert stored_keys[1].expires_at == stored_keys[0].expires_at
        assert "token" not in OperatorApiKey.__table__.columns
        assert "secret" not in OperatorApiKey.__table__.columns

    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "revoke-operator-key", "--key-id", str(second_key_id)],
    )
    cli.main()
    revoked = _output_map(capsys.readouterr().out)
    assert revoked["revoked"] == "true"
    with get_session_factory()() as session:
        with pytest.raises(InvalidOperatorCredentialsError):
            authenticate_operator(session, second_token, now=datetime.now(UTC))


def test_concurrent_rotation_creates_exactly_one_replacement(
    register_operator: OperatorFactory,
) -> None:
    original = register_operator()
    start = Barrier(2)

    def rotate() -> tuple[IssuedOperatorApiKey | None, Exception | None]:
        with get_session_factory()() as session:
            start.wait(timeout=10)
            try:
                with session.begin():
                    replacement = rotate_operator_api_key(session, key_id=original.key_id)
            except Exception as error:  # noqa: BLE001 - assert the exact concurrent outcome
                return None, error
        return replacement, None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [
            future.result(timeout=20) for future in [executor.submit(rotate) for _ in range(2)]
        ]

    replacements = [replacement for replacement, error in outcomes if error is None]
    failures = [error for replacement, error in outcomes if replacement is None]
    assert len(replacements) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], OperatorManagementError)
    assert not isinstance(failures[0], IntegrityError)

    winning_replacement = replacements[0]
    assert winning_replacement is not None
    now = datetime.now(UTC)
    with get_session_factory()() as session:
        original_key = session.get(OperatorApiKey, original.key_id)
        assert original_key is not None
        assert original_key.revoked_at is not None

        stored_replacements = session.scalars(
            select(OperatorApiKey).where(OperatorApiKey.rotated_from_id == original.key_id)
        ).all()
        assert len(stored_replacements) == 1
        assert stored_replacements[0].id == winning_replacement.key_id

        all_operator_keys = session.scalars(
            select(OperatorApiKey).where(OperatorApiKey.operator_id == original.operator_id)
        ).all()
        assert {key.id for key in all_operator_keys} == {
            original.key_id,
            winning_replacement.key_id,
        }

        authenticated = authenticate_operator(session, winning_replacement.token, now=now)
        assert authenticated.key_id == winning_replacement.key_id
        with pytest.raises(InvalidOperatorCredentialsError):
            authenticate_operator(session, original.token, now=now)


@pytest.mark.parametrize("digest_length", [31, 33])
def test_postgresql_rejects_operator_key_digest_with_wrong_length(
    register_operator: OperatorFactory,
    digest_length: int,
) -> None:
    operator = register_operator()
    material = generate_operator_api_key()

    with pytest.raises(IntegrityError), get_session_factory().begin() as session:
        session.add(
            OperatorApiKey(
                operator_id=operator.operator_id,
                public_id=material.public_id,
                secret_hash=b"x" * digest_length,
            )
        )
        session.flush()


def _output_map(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", maxsplit=1)
        values[key] = value
    return values
