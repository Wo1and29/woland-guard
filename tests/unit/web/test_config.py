"""Dashboard configuration and HSTS decision regressions."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.web.app import create_dashboard_app


def test_production_requires_configured_https_origin() -> None:
    with pytest.raises(ValidationError, match="must use HTTPS"):
        Settings(app_env="production", web_public_origin="http://localhost:8000")


@pytest.mark.parametrize(
    "values",
    [
        {"web_session_idle_seconds": 3_600, "web_session_absolute_seconds": 300},
        {"web_session_touch_interval_seconds": 601, "web_session_idle_seconds": 600},
    ],
)
def test_session_timing_invariants_are_validated(values: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        Settings(**values)  # type: ignore[arg-type]


def test_hsts_is_derived_only_from_validated_production_configuration() -> None:
    development = create_dashboard_app(
        Settings(app_env="development", web_public_origin="https://localhost:8000")
    )
    production = create_dashboard_app(
        Settings(app_env="production", web_public_origin="https://dashboard.invalid")
    )

    with TestClient(development, base_url="https://localhost:8000") as client:
        development_response = client.get("/login")
    with TestClient(production, base_url="https://dashboard.invalid") as client:
        production_response = client.get("/login")

    assert "strict-transport-security" not in development_response.headers
    assert production_response.headers["strict-transport-security"] == "max-age=31536000"
