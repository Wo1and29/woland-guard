"""FastAPI application factory and safe exception responses."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from woland_guard_control_plane.api.errors import ApiError
from woland_guard_control_plane.api.middleware import (
    IngestionRequestGuardMiddleware,
    RequestIdMiddleware,
)
from woland_guard_control_plane.api.router import api_router
from woland_guard_control_plane.application.rate_limit import (
    AgentRateLimiter,
    FixedWindowRateLimiter,
)
from woland_guard_control_plane.config import Settings, get_settings
from woland_guard_control_plane.web.app import create_dashboard_app


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application without connecting to PostgreSQL."""

    application_settings = settings or get_settings()
    application = FastAPI(
        title=application_settings.app_name,
        version=application_settings.app_version,
        description="Defensive Linux security monitoring control plane.",
    )
    application.state.settings = application_settings
    application.state.agent_rate_limiter = AgentRateLimiter(
        max_requests=application_settings.ingest_rate_limit_requests,
        window_seconds=application_settings.ingest_rate_limit_window_seconds,
    )
    application.state.operator_security_log_limiter = FixedWindowRateLimiter(
        max_requests=application_settings.operator_security_log_events,
        window_seconds=application_settings.operator_security_log_window_seconds,
    )
    application.include_router(api_router)
    application.mount("/dashboard", create_dashboard_app(application_settings))
    application.add_middleware(
        IngestionRequestGuardMiddleware,
        max_body_bytes=application_settings.ingest_max_body_bytes,
    )
    application.add_middleware(RequestIdMiddleware)

    @application.exception_handler(ApiError)
    async def api_error_handler(request: Request, error: ApiError) -> JSONResponse:
        request_id = str(request.state.request_id)
        return JSONResponse(
            status_code=error.status_code,
            content={"detail": error.detail, "request_id": request_id},
            headers=error.headers,
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        _error: RequestValidationError,
    ) -> JSONResponse:
        request_id = str(request.state.request_id)
        return JSONResponse(
            status_code=422,
            content={"detail": "request validation failed", "request_id": request_id},
        )

    return application


app = create_app()
