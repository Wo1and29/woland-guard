"""Mounted Dashboard sub-application factory and HTML exception boundary."""

from pathlib import Path
from typing import cast

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import HTMLResponse

from woland_guard_control_plane.application.login_rate_limit import LoginRateLimiter
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.form_body import BoundedFormBodyMiddleware
from woland_guard_control_plane.web.router import web_router
from woland_guard_control_plane.web.security import (
    DashboardSecurityHeadersMiddleware,
    log_unexpected_dashboard_error,
)

_TEMPLATES = Path(__file__).resolve().parent / "templates"


def create_dashboard_app(settings: Settings) -> DashboardSecurityHeadersMiddleware:
    """Build the isolated cookie-authenticated HTML application."""

    application = FastAPI(
        title="Woland Guard Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = settings
    application.state.templates = Jinja2Templates(directory=str(_TEMPLATES))
    application.state.login_rate_limiter = LoginRateLimiter(
        global_limit=settings.web_login_global_limit,
        global_window_seconds=settings.web_login_global_window_seconds,
        subject_limit=settings.web_login_subject_limit,
        subject_window_seconds=settings.web_login_subject_window_seconds,
        malformed_limit=settings.web_login_malformed_limit,
        malformed_window_seconds=settings.web_login_malformed_window_seconds,
        max_subject_buckets=settings.web_login_max_subject_buckets,
    )
    application.state.security_log_limiter = FixedWindowRateLimiter(
        max_requests=settings.operator_security_log_events,
        window_seconds=settings.operator_security_log_window_seconds,
    )
    application.include_router(web_router)
    application.add_middleware(
        BoundedFormBodyMiddleware,
        max_body_bytes=settings.web_max_form_body_bytes,
    )

    @application.exception_handler(WebError)
    async def web_error_handler(request: Request, error: WebError) -> HTMLResponse:
        return _render_error(request, error.status_code, error.detail)

    @application.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, _error: SQLAlchemyError) -> HTMLResponse:
        return _render_error(request, 503, "Сервис временно недоступен.")

    @application.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, _error: Exception) -> HTMLResponse:
        log_unexpected_dashboard_error(request.scope)
        return _render_error(request, 500, "Внутренняя ошибка.")

    return DashboardSecurityHeadersMiddleware(
        application,
        enable_hsts=(
            settings.app_env == "production"
            and settings.web_public_origin.casefold().startswith("https://")
        ),
    )


def _render_error(request: Request, status_code: int, detail: str) -> HTMLResponse:
    templates = request.app.state.templates
    template_name = f"errors/{status_code}.html"
    if not (_TEMPLATES / template_name).is_file():
        template_name = "errors/500.html"
        status_code = 500
        detail = "Внутренняя ошибка."
    return cast(
        HTMLResponse,
        templates.TemplateResponse(
            request=request,
            name=template_name,
            context={
                "detail": detail,
                "request_id": str(getattr(request.state, "request_id", "unavailable")),
            },
            status_code=status_code,
        ),
    )
