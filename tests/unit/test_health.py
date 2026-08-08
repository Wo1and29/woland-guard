"""Tests for application startup and health endpoints."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from woland_guard_control_plane.api.routes import health
from woland_guard_control_plane.database import MigrationDriftError
from woland_guard_control_plane.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Create the application through its public factory."""

    with TestClient(create_app()) as test_client:
        yield test_client


def test_application_starts(client: TestClient) -> None:
    """The application exposes its generated OpenAPI document."""

    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Woland Guard Control Plane"
    assert all(not path.startswith("/dashboard") for path in response.json()["paths"])


def test_liveness_does_not_require_database(client: TestClient) -> None:
    """Liveness remains independent from PostgreSQL availability."""

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_readiness_succeeds_when_database_is_available(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Readiness returns success after the database probe succeeds."""

    monkeypatch.setattr(health, "check_database", lambda: None)

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}


def test_readiness_fails_without_leaking_database_error(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Readiness hides internal database exception details."""

    def raise_database_error() -> None:
        raise SQLAlchemyError("synthetic secret-bearing database error")

    monkeypatch.setattr(health, "check_database", raise_database_error)

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "database": "unavailable"}
    assert "synthetic" not in response.text


def test_readiness_reports_pending_migration_distinctly(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reachable-but-unmigrated database is not the same failure as no database."""

    def raise_drift_error() -> None:
        raise MigrationDriftError("database schema is at revision 'old', code expects 'new'")

    monkeypatch.setattr(health, "check_database", raise_drift_error)

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "database": "not_migrated"}
