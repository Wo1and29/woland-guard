"""FastAPI application factory."""

from fastapi import FastAPI

from woland_guard_control_plane.api.router import api_router
from woland_guard_control_plane.config import get_settings


def create_app() -> FastAPI:
    """Build the FastAPI application without connecting to PostgreSQL."""

    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Defensive Linux security monitoring control plane.",
    )
    application.include_router(api_router)
    return application


app = create_app()
