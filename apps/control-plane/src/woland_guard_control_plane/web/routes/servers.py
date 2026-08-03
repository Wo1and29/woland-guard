"""Read-only server inventory Dashboard routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.dashboard_pagination import (
    DASHBOARD_PAGE_SIZES,
    DashboardCursorValidationError,
)
from woland_guard_control_plane.application.dashboard_search import (
    DashboardQueryValidationError,
    normalize_literal_prefix,
    parse_canonical_uuid,
)
from woland_guard_control_plane.application.incident_queries import (
    IncidentDashboardFilters,
    IncidentDashboardSort,
    list_dashboard_incidents,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.server_queries import (
    ServerFilters,
    ServerSort,
    ServerStateFilter,
    get_server_detail,
    list_servers,
)
from woland_guard_control_plane.application.web_sessions import AuthenticatedWebSession
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.web.dependencies import require_dashboard_permission
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.i18n import current_language, t
from woland_guard_control_plane.web.routes.common import (
    dashboard_context,
    page_url,
    render_dashboard,
)

router = APIRouter(prefix="/servers")


@router.get("", name="dashboard_servers")
def servers_list(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.ACCESS_DASHBOARD)),
    ],
    state: ServerStateFilter = ServerStateFilter.ALL,
    identifier: Annotated[str | None, Query(alias="id", max_length=36)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    sort: ServerSort = ServerSort.NAME_ASC,
    page_size: int = 25,
    cursor: str | None = None,
) -> object:
    try:
        search = normalize_literal_prefix(q)
        server_id = parse_canonical_uuid(identifier)
        _page_size(page_size)
        page = list_servers(
            session,
            filters=ServerFilters(state=state, server_id=server_id, search=search),
            sort=sort,
            page_size=page_size,
            cursor=cursor,
        )
    except DashboardQueryValidationError:
        raise WebError(422, t(current_language(request), "err.invalid_search_params")) from None
    except DashboardCursorValidationError:
        raise WebError(400, t(current_language(request), "err.invalid_cursor")) from None
    context = dashboard_context(request, authenticated, active_navigation="servers")
    parameters = {
        "state": state.value,
        "id": identifier,
        "q": search,
        "sort": sort.value,
        "page_size": page_size,
    }
    context.update(
        {
            "filters": parameters,
            "items": page.items,
            "next_url": None
            if page.next_cursor is None
            else page_url(request, "/servers", {**parameters, "cursor": page.next_cursor}),
            "reset_url": page_url(request, "/servers", parameters),
        }
    )
    return render_dashboard(request, template="servers/list.html", context=context)


@router.get("/{server_id}", name="dashboard_server_detail")
def server_detail(
    server_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.ACCESS_DASHBOARD)),
    ],
) -> object:
    server = get_server_detail(session, server_id)
    if server is None:
        raise WebError(404, t(current_language(request), "err.server_not_found"))
    incidents = list_dashboard_incidents(
        session,
        filters=IncidentDashboardFilters(server_id=server_id),
        sort=IncidentDashboardSort.CREATED_DESC,
        page_size=25,
        cursor=None,
    )
    context = dashboard_context(request, authenticated, active_navigation="servers")
    context.update({"server": server, "incidents": incidents.items[:10]})
    return render_dashboard(request, template="servers/detail.html", context=context)


def _page_size(value: int) -> None:
    if type(value) is not int or value not in DASHBOARD_PAGE_SIZES:
        raise DashboardQueryValidationError("invalid dashboard page size")
