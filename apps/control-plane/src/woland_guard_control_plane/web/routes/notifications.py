"""Telegram destination status and two safe Dashboard mutations (ADR-0024).

Enabling a destination is deliberately absent here: it requires confirming the
token staging file exists, and control-plane has no filesystem access to that
staging directory by design -- only the one-shot `telegram-admin` container and
`outbox-worker` do. That check, and destination creation, chat_id, and token
changes, stay CLI-only.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from woland_guard_control_plane.application.notification_destinations import (
    NotificationDestinationManagementError,
    disable_notification_destination_by_operator,
    list_notification_destinations,
    update_notification_destination_severity_by_operator,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    InvalidWebSessionError,
    WebSessionPermissionError,
    lock_web_session_for_mutation,
)
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.infrastructure.database.models import NotificationSeverity
from woland_guard_control_plane.web.dependencies import (
    require_dashboard_mutation_permission,
    require_dashboard_permission,
)
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.i18n import current_language, t
from woland_guard_control_plane.web.mutations import (
    parse_dashboard_mutation_form,
    require_dashboard_csrf,
)
from woland_guard_control_plane.web.routes.common import (
    dashboard_context,
    external_path,
    render_dashboard,
)
from woland_guard_control_plane.web.security import CSRF_FORM_FIELD, SESSION_COOKIE_NAME

router = APIRouter(prefix="/notifications")


def _unverifiable_from_dashboard(_token_file_name: str) -> bool:
    """Stand in for a real staging check -- see the module docstring.

    Every summary built with this returns staging_file_ready=False, and the
    template never renders that field as a verified answer.
    """

    return False


@router.get("", name="dashboard_notifications")
def notifications_list(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.MANAGE_TELEGRAM_DESTINATIONS)),
    ],
) -> object:
    destinations = list_notification_destinations(
        session,
        staging_readiness=_unverifiable_from_dashboard,
    )
    context = dashboard_context(request, authenticated, active_navigation="notifications")
    context.update(
        {
            "destinations": destinations,
            "severities": tuple(severity.value for severity in NotificationSeverity),
        }
    )
    return render_dashboard(request, template="notifications/list.html", context=context)


@router.post("/{destination_id}/disable", name="dashboard_notification_disable")
def notification_disable(
    destination_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_mutation_permission(Permission.MANAGE_TELEGRAM_DESTINATIONS)),
    ],
) -> RedirectResponse:
    form = parse_dashboard_mutation_form(
        request,
        allowed_fields={CSRF_FORM_FIELD},
        required_fields={CSRF_FORM_FIELD},
    )
    require_dashboard_csrf(request, authenticated=authenticated, form=form)
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    try:
        with session.begin():
            actor = lock_web_session_for_mutation(
                session,
                authenticated=authenticated,
                session_token=token,
                required_permission=Permission.MANAGE_TELEGRAM_DESTINATIONS,
                now=datetime.now(UTC),
            )
            disable_notification_destination_by_operator(
                session,
                actor=actor,
                destination_id=destination_id,
                request_id=_request_id(request),
            )
    except InvalidWebSessionError:
        raise WebError(401, t(current_language(request), "err.login_required")) from None
    except WebSessionPermissionError:
        raise WebError(403, t(current_language(request), "err.insufficient_permissions")) from None
    except NotificationDestinationManagementError:
        raise WebError(404, t(current_language(request), "err.destination_not_found")) from None
    except SQLAlchemyError:
        raise WebError(
            503, t(current_language(request), "err.destination_mutation_unavailable")
        ) from None
    return RedirectResponse(external_path(request, "/notifications"), status_code=303)


@router.post("/{destination_id}/severity", name="dashboard_notification_severity")
def notification_severity(
    destination_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_mutation_permission(Permission.MANAGE_TELEGRAM_DESTINATIONS)),
    ],
) -> RedirectResponse:
    form = parse_dashboard_mutation_form(
        request,
        allowed_fields={CSRF_FORM_FIELD, "minimum_severity"},
        required_fields={CSRF_FORM_FIELD, "minimum_severity"},
    )
    require_dashboard_csrf(request, authenticated=authenticated, form=form)
    try:
        severity = NotificationSeverity(form["minimum_severity"])
    except ValueError:
        raise WebError(422, t(current_language(request), "err.invalid_form")) from None
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    try:
        with session.begin():
            actor = lock_web_session_for_mutation(
                session,
                authenticated=authenticated,
                session_token=token,
                required_permission=Permission.MANAGE_TELEGRAM_DESTINATIONS,
                now=datetime.now(UTC),
            )
            update_notification_destination_severity_by_operator(
                session,
                actor=actor,
                destination_id=destination_id,
                minimum_severity=severity,
                request_id=_request_id(request),
            )
    except InvalidWebSessionError:
        raise WebError(401, t(current_language(request), "err.login_required")) from None
    except WebSessionPermissionError:
        raise WebError(403, t(current_language(request), "err.insufficient_permissions")) from None
    except NotificationDestinationManagementError:
        raise WebError(404, t(current_language(request), "err.destination_not_found")) from None
    except SQLAlchemyError:
        raise WebError(
            503, t(current_language(request), "err.destination_mutation_unavailable")
        ) from None
    return RedirectResponse(external_path(request, "/notifications"), status_code=303)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unavailable"))
