"""Fixtures for API tests backed by the real Compose PostgreSQL service."""

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from woland_guard_control_plane.application.operators import (
    create_operator,
    issue_operator_api_key,
)
from woland_guard_control_plane.application.provisioning import provision_test_server
from woland_guard_control_plane.application.rate_limit import (
    AgentRateLimiter,
    FixedWindowRateLimiter,
)
from woland_guard_control_plane.config import Settings, get_settings
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    Operator,
    OperatorApiKey,
    OperatorRole,
    Server,
)
from woland_guard_control_plane.main import create_app


@dataclass(frozen=True, slots=True)
class RegisteredAgent:
    """Synthetic server identity used by integration tests."""

    server_id: UUID
    key_id: UUID
    public_id: str
    token: str = field(repr=False)


class AgentFactory(Protocol):
    """Callable fixture that creates a configured synthetic server and key."""

    def __call__(
        self,
        *,
        is_active: bool = True,
        revoked_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> RegisteredAgent: ...


@dataclass(frozen=True, slots=True)
class RegisteredOperator:
    """Synthetic local operator with one one-time API credential."""

    operator_id: UUID
    key_id: UUID
    username: str
    role: OperatorRole
    public_id: str
    token: str = field(repr=False)


class OperatorFactory(Protocol):
    def __call__(
        self,
        *,
        role: OperatorRole = OperatorRole.VIEWER,
        is_active: bool = True,
        revoked_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> RegisteredOperator: ...


@pytest.fixture(scope="session", autouse=True)
def require_real_postgresql() -> None:
    """Prevent accidental fallback to a local or SQLite integration database."""

    if os.environ.get("WG_RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("integration tests require Docker Compose PostgreSQL")

    _assert_isolated_test_database_settings()
    command.upgrade(Config("alembic.ini"), "head")
    with get_engine().connect() as connection:
        current_database = connection.execute(text("SELECT current_database()"))
        assert current_database.scalar_one() == get_settings().postgres_db
        product = connection.execute(text("SELECT current_setting('server_version')")).scalar_one()
    if not str(product):
        pytest.fail("PostgreSQL did not return its server version")


@pytest.fixture(autouse=True)
def clean_database(require_real_postgresql: None) -> Iterator[None]:
    """Isolate tests without replacing PostgreSQL with an in-memory database."""

    del require_real_postgresql
    _truncate_application_tables()
    yield
    _truncate_application_tables()


@pytest.fixture
def integration_settings() -> Settings:
    """Use Compose database settings with deterministic ingestion limits."""

    return Settings(
        app_env="test",
        ingest_max_body_bytes=1_048_576,
        ingest_rate_limit_requests=60,
        ingest_rate_limit_window_seconds=60,
        ingest_max_clock_skew_seconds=300,
    )


@pytest.fixture
def api_app(integration_settings: Settings) -> FastAPI:
    """Build an app instance configured for real PostgreSQL tests."""

    return create_app(integration_settings)


@pytest.fixture
def client(api_app: FastAPI) -> Iterator[TestClient]:
    """Expose the ASGI application through its real request stack."""

    with TestClient(api_app) as test_client:
        yield test_client


@pytest.fixture
def register_agent() -> AgentFactory:
    """Create synthetic servers and keys through the local provisioning service."""

    def factory(
        *,
        is_active: bool = True,
        revoked_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> RegisteredAgent:
        unique_suffix = uuid4().hex
        with get_session_factory().begin() as session:
            provisioned = provision_test_server(
                session,
                name=f"integration-{unique_suffix}",
                hostname=f"{unique_suffix}.invalid",
                label="integration-test",
            )
            server = session.get(Server, provisioned.server_id)
            api_key = session.get(AgentApiKey, provisioned.key_id)
            assert server is not None
            assert api_key is not None
            server.is_active = is_active
            api_key.revoked_at = revoked_at
            api_key.expires_at = expires_at

        return RegisteredAgent(
            server_id=provisioned.server_id,
            key_id=provisioned.key_id,
            public_id=provisioned.public_id,
            token=provisioned.token,
        )

    return factory


@pytest.fixture
def register_operator() -> OperatorFactory:
    """Create synthetic identities and credentials through the 6A services."""

    def factory(
        *,
        role: OperatorRole = OperatorRole.VIEWER,
        is_active: bool = True,
        revoked_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> RegisteredOperator:
        unique_suffix = uuid4().hex
        with get_session_factory().begin() as session:
            provisioned = create_operator(
                session,
                username=f"operator-{unique_suffix}",
                role=role,
            )
            issued = issue_operator_api_key(
                session,
                operator_id=provisioned.id,
                label="integration-test",
            )
            operator = session.get(Operator, provisioned.id)
            key = session.get(OperatorApiKey, issued.key_id)
            assert operator is not None
            assert key is not None
            operator.is_active = is_active
            if revoked_at is not None and revoked_at <= key.created_at:
                key.created_at = revoked_at - timedelta(seconds=1)
            key.revoked_at = revoked_at
            if expires_at is not None and expires_at <= key.created_at:
                key.created_at = expires_at - timedelta(seconds=1)
            key.expires_at = expires_at

        return RegisteredOperator(
            operator_id=provisioned.id,
            key_id=issued.key_id,
            username=provisioned.username,
            role=role,
            public_id=issued.public_id,
            token=issued.token,
        )

    return factory


@pytest.fixture(autouse=True)
def reset_rate_limiter(api_app: FastAPI) -> None:
    """Ensure request counters never leak between tests."""

    limiter = api_app.state.agent_rate_limiter
    assert isinstance(limiter, AgentRateLimiter)
    limiter.reset()
    security_log_limiter = api_app.state.operator_security_log_limiter
    assert isinstance(security_log_limiter, FixedWindowRateLimiter)
    security_log_limiter.reset()


def _truncate_application_tables() -> None:
    _assert_isolated_test_database_settings()
    immutable_tables = (
        "incident_history",
        "audit_log_entries",
        "operator_idempotency_records",
    )
    with get_engine().connect() as connection:
        transaction = connection.begin()
        try:
            current_database = connection.execute(text("SELECT current_database()"))
            if current_database.scalar_one() != get_settings().postgres_db:
                raise RuntimeError("integration cleanup database identity mismatch")
            for table_name in immutable_tables:
                connection.execute(text(f"ALTER TABLE {table_name} DISABLE TRIGGER USER"))
            connection.execute(
                text(
                    "TRUNCATE TABLE operator_idempotency_records, audit_log_entries, "
                    "incident_history, incident_events, incidents, detection_rule_versions, "
                    "events, outbox_messages, agent_api_keys, servers, operator_api_keys, "
                    "operators CASCADE"
                )
            )
            for table_name in immutable_tables:
                connection.execute(text(f"ALTER TABLE {table_name} ENABLE TRIGGER USER"))
            transaction.commit()
        except Exception:
            transaction.rollback()
            raise
        finally:
            with get_engine().begin() as safety_connection:
                for table_name in immutable_tables:
                    safety_connection.execute(text(f"ALTER TABLE {table_name} ENABLE TRIGGER USER"))


def _assert_isolated_test_database_settings() -> None:
    settings = get_settings()
    if (
        settings.app_env != "test"
        or settings.postgres_host != "postgres"
        or not settings.postgres_db.endswith("_test")
        or os.environ.get("WG_RUN_INTEGRATION_TESTS") != "1"
    ):
        raise RuntimeError("immutable cleanup requires the isolated integration database")
