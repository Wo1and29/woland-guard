"""Read-only active detection-rule Dashboard route."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.dashboard_pagination import (
    DASHBOARD_PAGE_SIZES,
    DashboardCursorValidationError,
)
from woland_guard_control_plane.application.dashboard_search import (
    DashboardQueryValidationError,
    normalize_literal_prefix,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.rule_queries import (
    RuleConditionType,
    RuleEnabledFilter,
    RuleFilters,
    RuleSort,
    list_active_rules,
)
from woland_guard_control_plane.application.web_sessions import AuthenticatedWebSession
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.web.dependencies import require_dashboard_permission
from woland_guard_control_plane.web.errors import WebError
from woland_guard_control_plane.web.routes.common import (
    dashboard_context,
    page_url,
    render_dashboard,
)

router = APIRouter(prefix="/rules")
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@router.get("", name="dashboard_rules")
def rules_list(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_permission(Permission.ACCESS_DASHBOARD)),
    ],
    severities: Annotated[list[str] | None, Query(alias="severity")] = None,
    enabled: RuleEnabledFilter = RuleEnabledFilter.ALL,
    condition: Annotated[str | None, Query(max_length=32)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    sort: RuleSort = RuleSort.RULE_KEY_ASC,
    page_size: int = 25,
    cursor: str | None = None,
) -> object:
    try:
        search = normalize_literal_prefix(q)
        normalized_severities = _severities(severities or [])
        condition_type = _condition_type(condition)
        _page_size(page_size)
        page = list_active_rules(
            session,
            filters=RuleFilters(
                severities=normalized_severities,
                enabled=enabled,
                condition_type=condition_type,
                search=search,
            ),
            sort=sort,
            page_size=page_size,
            cursor=cursor,
        )
    except DashboardQueryValidationError:
        raise WebError(422, "Некорректные параметры поиска.") from None
    except DashboardCursorValidationError:
        raise WebError(400, "Некорректный cursor.") from None
    context = dashboard_context(request, authenticated, active_navigation="rules")
    parameters = {
        "severity": list(normalized_severities),
        "enabled": enabled.value,
        "condition": None if condition_type is None else condition_type.value,
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
            else page_url(request, "/rules", {**parameters, "cursor": page.next_cursor}),
            "reset_url": page_url(request, "/rules", parameters),
        }
    )
    return render_dashboard(request, template="rules/list.html", context=context)


def _severities(values: list[str]) -> tuple[str, ...]:
    if any(value not in _SEVERITIES for value in values):
        raise DashboardQueryValidationError("invalid rule severity")
    return tuple(sorted(set(values)))


def _condition_type(value: str | None) -> RuleConditionType | None:
    if value is None or value == "":
        return None
    try:
        return RuleConditionType(value)
    except ValueError:
        raise DashboardQueryValidationError("invalid rule condition type") from None


def _page_size(value: int) -> None:
    if type(value) is not int or value not in DASHBOARD_PAGE_SIZES:
        raise DashboardQueryValidationError("invalid dashboard page size")
