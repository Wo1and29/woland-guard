"""Mounted Dashboard sub-application factory and HTML exception boundary."""

import logging
from pathlib import Path
from typing import cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import HTMLResponse
from starlette.staticfiles import StaticFiles

from woland_guard_control_plane.application.login_rate_limit import LoginRateLimiter
from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.application.rule_queries import (
    ActiveRuleSetLimitError,
    StoredRuleDefinitionError,
)
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.form_body import BoundedFormBodyMiddleware
from woland_guard_control_plane.web.i18n import normalize_language, t
from woland_guard_control_plane.web.presentation import utc_text
from woland_guard_control_plane.web.router import web_router
from woland_guard_control_plane.web.security import (
    LANG_COOKIE_NAME,
    DashboardSecurityHeadersMiddleware,
    log_unexpected_dashboard_error,
)

_TEMPLATES = Path(__file__).resolve().parent / "templates"
_STATIC = Path(__file__).resolve().parent / "static"
logger = logging.getLogger("uvicorn.error")


def create_dashboard_app(settings: Settings) -> DashboardSecurityHeadersMiddleware:
    """Build the isolated cookie-authenticated HTML application."""

    application = FastAPI(
        title="Woland Guard Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = settings
    environment = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=True),
    )
    environment.globals.update(
        t=t,
        utc_text=utc_text,
    )
    application.state.templates = Jinja2Templates(env=environment)
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
    application.mount("/static", StaticFiles(directory=str(_STATIC)), name="dashboard_static")
    application.include_router(web_router)
    application.add_middleware(
        BoundedFormBodyMiddleware,
        max_body_bytes=settings.web_max_form_body_bytes,
    )

    @application.exception_handler(WebError)
    async def web_error_handler(request: Request, error: WebError) -> HTMLResponse:
        return _render_error(request, error.status_code, error.detail)

    @application.exception_handler(RequestValidationError)
    async def request_validation_error_handler(
        request: Request,
        _error: RequestValidationError,
    ) -> HTMLResponse:
        return _render_error(request, 422, t(_lang(request), "err.invalid_request_params"))

    @application.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request,
        error: StarletteHTTPException,
    ) -> HTMLResponse:
        if error.status_code == 404:
            return _render_error(request, 404, t(_lang(request), "err.page_not_found"))
        if error.status_code == 405:
            return _render_error(request, 405, t(_lang(request), "err.method_not_allowed"))
        return _render_error(request, 500, t(_lang(request), "err.internal_error"))

    @application.exception_handler(StoredRuleDefinitionError)
    async def stored_rule_error_handler(
        request: Request,
        error: StoredRuleDefinitionError,
    ) -> HTMLResponse:
        logger.error(
            "request_id=%s event=dashboard_rule_definition_invalid rule_version_id=%s",
            str(getattr(request.state, "request_id", "unavailable")),
            error.rule_version_id,
        )
        return _render_error(request, 503, t(_lang(request), "err.rules_unavailable"))

    @application.exception_handler(ActiveRuleSetLimitError)
    async def active_rule_limit_error_handler(
        request: Request,
        _error: ActiveRuleSetLimitError,
    ) -> HTMLResponse:
        logger.error(
            "request_id=%s event=dashboard_active_rule_validation_limit_exceeded",
            str(getattr(request.state, "request_id", "unavailable")),
        )
        return _render_error(request, 503, t(_lang(request), "err.rules_unavailable"))

    @application.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, _error: SQLAlchemyError) -> HTMLResponse:
        return _render_error(request, 503, t(_lang(request), "err.service_unavailable"))

    @application.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, _error: Exception) -> HTMLResponse:
        log_unexpected_dashboard_error(request.scope)
        return _render_error(request, 500, t(_lang(request), "err.internal_error"))

    return DashboardSecurityHeadersMiddleware(
        application,
        enable_hsts=(
            settings.app_env == "production"
            and settings.web_public_origin.casefold().startswith("https://")
        ),
    )


def _lang(request: Request) -> str:
    return normalize_language(request.cookies.get(LANG_COOKIE_NAME))


def _render_error(request: Request, status_code: int, detail: str) -> HTMLResponse:
    templates = request.app.state.templates
    template_name = f"errors/{status_code}.html"
    lang = _lang(request)
    if not (_TEMPLATES / template_name).is_file():
        template_name = "errors/500.html"
        status_code = 500
        detail = t(lang, "err.internal_error")
    return cast(
        HTMLResponse,
        templates.TemplateResponse(
            request=request,
            name=template_name,
            context={
                "detail": detail,
                "lang": lang,
                "request_id": str(getattr(request.state, "request_id", "unavailable")),
            },
            status_code=status_code,
        ),
    )
