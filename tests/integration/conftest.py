"""Fixtures for API tests backed by the real Compose PostgreSQL service."""

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from woland_guard_control_plane.application.provisioning import provision_test_server
from woland_guard_control_plane.application.rate_limit import AgentRateLimiter
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import AgentApiKey, Server
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


@pytest.fixture(scope="session", autouse=True)
def require_real_postgresql() -> None:
    """Prevent accidental fallback to a local or SQLite integration database."""

    if os.environ.get("WG_RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("integration tests require Docker Compose PostgreSQL")

    with get_engine().connect() as connection:
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


@pytest.fixture(autouse=True)
def reset_rate_limiter(api_app: FastAPI) -> None:
    """Ensure request counters never leak between tests."""

    limiter = api_app.state.agent_rate_limiter
    assert isinstance(limiter, AgentRateLimiter)
    limiter.reset()


def _truncate_application_tables() -> None:
    with get_engine().begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE incident_events, incidents, detection_rule_versions, "
                "events, agent_api_keys, servers CASCADE"
            )
        )
