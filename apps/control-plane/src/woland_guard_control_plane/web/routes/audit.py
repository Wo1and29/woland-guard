"""Admin-only read-only audit log Dashboard route."""

from datetime import UTC, date, datetime, time
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import AUDIT_ACTION_REGISTRY
from woland_guard_control_plane.application.audit_queries import (
    AuditDashboardFilters,
    AuditDashboardSort,
    list_dashboard_audit_entries,
)
from woland_guard_control_plane.application.dashboard_pagination import (
    DASHBOARD_PAGE_SIZES,
    DashboardCursorValidationError,
)
from woland_guard_control_plane.application.dashboard_search import (
    DashboardQueryValidationError,
    parse_canonical_uuid,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.web_sessions import AuthenticatedWebSession
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.web.dependencies import require_dashboard_permission
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.presentation import audit_entry_view
from woland_guard_control_plane.web.routes.common import (
    dashboard_context,
    page_url,
    render_dashboard,
)

router = APIRouter(prefix="/audit")
_ACTOR_TYPES = frozenset({"operator", "local_cli"})
_ACTIONS = frozenset(AUDIT_ACTION_REGISTRY)
_TARGET_TYPES = frozenset(spec.target_type for spec in AUDIT_ACTION_REGISTRY.values())


@router.get("", name="dashboard_audit")
def audit_list(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.VIEW_AUDIT_LOG)),
    ],
    actor_type: Annotated[str | None, Query(max_length=16)] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    target_type: Annotated[str | None, Query(max_length=32)] = None,
    target_id: Annotated[str | None, Query(max_length=36)] = None,
    created_from: Annotated[str | None, Query(max_length=10)] = None,
    created_to: Annotated[str | None, Query(max_length=10)] = None,
    sort: AuditDashboardSort = AuditDashboardSort.CREATED_DESC,
    page_size: int = 25,
    cursor: str | None = None,
) -> object:
    try:
        normalized_actor_type = None if actor_type == "" else actor_type
        normalized_action = None if action == "" else action
        normalized_target_type = None if target_type == "" else target_type
        if normalized_actor_type is not None and normalized_actor_type not in _ACTOR_TYPES:
            raise DashboardQueryValidationError("invalid audit actor type")
        if normalized_action is not None and normalized_action not in _ACTIONS:
            raise DashboardQueryValidationError("invalid audit action")
        if normalized_target_type is not None and normalized_target_type not in _TARGET_TYPES:
            raise DashboardQueryValidationError("invalid audit target type")
        parsed_target_id = parse_canonical_uuid(target_id)
        _page_size(page_size)
        from_date = _parse_date(created_from)
        to_date = _parse_date(created_to)
        from_time = _utc_start(from_date)
        to_time = _utc_start(to_date)
        if from_time is not None and to_time is not None and from_time >= to_time:
            raise DashboardQueryValidationError("invalid audit date range")
        filters = AuditDashboardFilters(
            actor_type=normalized_actor_type,
            action=normalized_action,
            target_type=normalized_target_type,
            target_id=parsed_target_id,
            created_from=from_time,
            created_to=to_time,
        )
        page = list_dashboard_audit_entries(
            session,
            filters=filters,
            sort=sort,
            page_size=page_size,
            cursor=cursor,
        )
    except DashboardQueryValidationError:
        raise WebError(422, "Некорректные audit filters.") from None
    except DashboardCursorValidationError:
        raise WebError(400, "Некорректный cursor.") from None
    context = dashboard_context(request, authenticated, active_navigation="audit")
    parameters = {
        "actor_type": normalized_actor_type,
        "action": normalized_action,
        "target_type": normalized_target_type,
        "target_id": target_id,
        "created_from": None if from_date is None else from_date.isoformat(),
        "created_to": None if to_date is None else to_date.isoformat(),
        "sort": sort.value,
        "page_size": page_size,
    }
    context.update(
        {
            "filters": parameters,
            "items": tuple(audit_entry_view(entry) for entry in page.items),
            "next_url": None
            if page.next_cursor is None
            else page_url(request, "/audit", {**parameters, "cursor": page.next_cursor}),
            "reset_url": page_url(request, "/audit", parameters),
        }
    )
    return render_dashboard(request, template="audit/list.html", context=context)


def _utc_start(value: date | None) -> datetime | None:
    return None if value is None else datetime.combine(value, time.min, tzinfo=UTC)


def _parse_date(value: str | None) -> date | None:
    if value is None or value == "":
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise DashboardQueryValidationError("invalid audit date") from None
    if parsed.isoformat() != value:
        raise DashboardQueryValidationError("invalid audit date")
    return parsed


def _page_size(value: int) -> None:
    if type(value) is not int or value not in DASHBOARD_PAGE_SIZES:
        raise DashboardQueryValidationError("invalid dashboard page size")
