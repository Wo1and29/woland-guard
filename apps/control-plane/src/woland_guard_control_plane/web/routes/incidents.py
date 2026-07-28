"""Read-only incident, history and evidence Dashboard routes."""

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
    parse_canonical_rule_key,
    parse_canonical_uuid,
)
from woland_guard_control_plane.application.incident_queries import (
    IncidentDashboardFilters,
    IncidentDashboardSort,
    get_dashboard_incident_detail,
    list_dashboard_evidence,
    list_dashboard_incidents,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.web_sessions import AuthenticatedWebSession
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
from woland_guard_control_plane.web.dependencies import require_dashboard_permission
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.routes.common import (
    dashboard_context,
    page_url,
    render_dashboard,
)

router = APIRouter(prefix="/incidents")
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@router.get("", name="dashboard_incidents")
def incidents_list(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.VIEW_INCIDENTS)),
    ],
    statuses: Annotated[list[IncidentStatus] | None, Query(alias="status")] = None,
    severities: Annotated[list[str] | None, Query(alias="severity")] = None,
    server_id: Annotated[str | None, Query(max_length=36)] = None,
    rule_key: Annotated[str | None, Query(max_length=100)] = None,
    identifier: Annotated[str | None, Query(alias="id", max_length=36)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    sort: IncidentDashboardSort = IncidentDashboardSort.CREATED_DESC,
    page_size: int = 25,
    cursor: str | None = None,
) -> object:
    try:
        search = normalize_literal_prefix(q)
        parsed_server_id = parse_canonical_uuid(server_id)
        incident_id = parse_canonical_uuid(identifier)
        parsed_rule_key = parse_canonical_rule_key(rule_key)
        normalized_severities = _severities(severities or [])
        _page_size(page_size)
        filters = IncidentDashboardFilters(
            statuses=tuple(status.value for status in statuses or []),
            severities=normalized_severities,
            server_id=parsed_server_id,
            rule_key=parsed_rule_key,
            incident_id=incident_id,
            search=search,
        )
        page = list_dashboard_incidents(
            session,
            filters=filters,
            sort=sort,
            page_size=page_size,
            cursor=cursor,
        )
    except DashboardQueryValidationError:
        raise WebError(422, "Некорректные параметры поиска.") from None
    except DashboardCursorValidationError:
        raise WebError(400, "Некорректный cursor.") from None
    context = dashboard_context(request, authenticated, active_navigation="incidents")
    parameters = {
        "status": [status.value for status in statuses or []],
        "severity": list(normalized_severities),
        "server_id": server_id,
        "rule_key": rule_key,
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
            else page_url(request, "/incidents", {**parameters, "cursor": page.next_cursor}),
            "reset_url": page_url(request, "/incidents", parameters),
        }
    )
    return render_dashboard(request, template="incidents/list.html", context=context)


@router.get("/{incident_id}", name="dashboard_incident_detail")
def incident_detail(
    incident_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.VIEW_INCIDENTS)),
    ],
    evidence_page_size: int = 25,
    evidence_cursor: str | None = None,
) -> object:
    try:
        _page_size(evidence_page_size)
        detail = get_dashboard_incident_detail(session, incident_id)
        evidence = list_dashboard_evidence(
            session,
            incident_id=incident_id,
            page_size=evidence_page_size,
            cursor=evidence_cursor,
        )
    except DashboardQueryValidationError:
        raise WebError(422, "Некорректный размер страницы evidence.") from None
    except DashboardCursorValidationError:
        raise WebError(400, "Некорректный evidence cursor.") from None
    if detail is None:
        raise WebError(404, "Инцидент не найден.")
    context = dashboard_context(request, authenticated, active_navigation="incidents")
    parameters = {"evidence_page_size": evidence_page_size}
    context.update(
        {
            "incident": detail,
            "evidence": evidence.items,
            "evidence_next_url": None
            if evidence.next_cursor is None
            else page_url(
                request,
                f"/incidents/{incident_id}",
                {**parameters, "evidence_cursor": evidence.next_cursor},
            ),
        }
    )
    return render_dashboard(request, template="incidents/detail.html", context=context)


def _severities(values: list[str]) -> tuple[str, ...]:
    if any(value not in _SEVERITIES for value in values):
        raise DashboardQueryValidationError("invalid incident severity")
    return tuple(sorted(set(values)))


def _page_size(value: int) -> None:
    if type(value) is not int or value not in DASHBOARD_PAGE_SIZES:
        raise DashboardQueryValidationError("invalid dashboard page size")
