"""Read-only factual Dashboard overview."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.dashboard_overview import get_dashboard_overview
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.web_sessions import AuthenticatedWebSession
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.web.dependencies import require_dashboard_permission
from woland_guard_control_plane.web.routes.common import dashboard_context, render_dashboard

router = APIRouter()


@router.get("/", name="dashboard_overview")
def overview(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.ACCESS_DASHBOARD)),
    ],
) -> object:
    context = dashboard_context(request, authenticated, active_navigation="overview")
    context["overview"] = get_dashboard_overview(session, now=datetime.now(UTC))
    return render_dashboard(request, template="dashboard/overview.html", context=context)
