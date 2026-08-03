"""Read-only incident views and safe idempotent Dashboard mutations."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

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
from woland_guard_control_plane.application.incident_comments import (
    CommentValidationError,
    add_incident_comment,
    canonical_comment_hash,
    normalize_comment,
)
from woland_guard_control_plane.application.incident_queries import (
    IncidentDashboardFilters,
    IncidentDashboardSort,
    get_dashboard_incident_detail,
    list_dashboard_evidence,
    list_dashboard_incident_comments,
    list_dashboard_incident_history,
    list_dashboard_incidents,
)
from woland_guard_control_plane.application.incident_workflow import (
    IDEMPOTENCY_REPLAY_HEADER,
    TransitionValidationError,
    allowed_transition_targets,
    canonical_transition_hash,
    normalize_transition,
    transition_incident,
    validate_idempotency_key,
)
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    InvalidWebSessionError,
    WebSessionPermissionError,
    lock_web_session_for_mutation,
)
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
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
    page_url,
    render_dashboard,
)
from woland_guard_control_plane.web.security import CSRF_FORM_FIELD, SESSION_COOKIE_NAME

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
        raise WebError(422, t(current_language(request), "err.invalid_search_params")) from None
    except DashboardCursorValidationError:
        raise WebError(400, t(current_language(request), "err.invalid_cursor")) from None
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
    history_page_size: int = 25,
    history_cursor: str | None = None,
    comment_page_size: int = 25,
    comment_cursor: str | None = None,
) -> object:
    try:
        _page_size(evidence_page_size)
        _page_size(history_page_size)
        _page_size(comment_page_size)
        detail = get_dashboard_incident_detail(session, incident_id)
        if detail is None:
            raise WebError(404, t(current_language(request), "err.incident_not_found"))
        evidence = list_dashboard_evidence(
            session,
            incident_id=incident_id,
            page_size=evidence_page_size,
            cursor=evidence_cursor,
        )
        history = list_dashboard_incident_history(
            session,
            incident_id=incident_id,
            page_size=history_page_size,
            cursor=history_cursor,
        )
        comments = list_dashboard_incident_comments(
            session,
            incident_id=incident_id,
            page_size=comment_page_size,
            cursor=comment_cursor,
        )
    except DashboardQueryValidationError:
        raise WebError(
            422, t(current_language(request), "err.invalid_evidence_page_size")
        ) from None
    except DashboardCursorValidationError:
        raise WebError(400, t(current_language(request), "err.invalid_evidence_cursor")) from None
    context = dashboard_context(request, authenticated, active_navigation="incidents")
    base_parameters = {
        "evidence_page_size": evidence_page_size,
        "history_page_size": history_page_size,
        "comment_page_size": comment_page_size,
    }
    status = IncidentStatus(detail.summary.status)
    context.update(
        {
            "comments": comments.items,
            "comment_idempotency_key": str(uuid4()),
            "incident": detail,
            "evidence": evidence.items,
            "history": history.items,
            "status_targets": allowed_transition_targets(status),
            "status_idempotency_key": str(uuid4()),
            "evidence_next_url": None
            if evidence.next_cursor is None
            else page_url(
                request,
                f"/incidents/{incident_id}",
                {
                    **base_parameters,
                    "evidence_cursor": evidence.next_cursor,
                    "history_cursor": history_cursor,
                    "comment_cursor": comment_cursor,
                },
            ),
            "history_next_url": None
            if history.next_cursor is None
            else page_url(
                request,
                f"/incidents/{incident_id}",
                {
                    **base_parameters,
                    "evidence_cursor": evidence_cursor,
                    "history_cursor": history.next_cursor,
                    "comment_cursor": comment_cursor,
                },
            ),
            "comments_next_url": None
            if comments.next_cursor is None
            else page_url(
                request,
                f"/incidents/{incident_id}",
                {
                    **base_parameters,
                    "evidence_cursor": evidence_cursor,
                    "history_cursor": history_cursor,
                    "comment_cursor": comments.next_cursor,
                },
            ),
        }
    )
    return render_dashboard(request, template="incidents/detail.html", context=context)


@router.post("/{incident_id}/transitions", name="dashboard_incident_transition")
def incident_transition(
    incident_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_mutation_permission(Permission.TRANSITION_INCIDENTS)),
    ],
) -> RedirectResponse:
    """Commit one existing workflow transition, then redirect after success."""

    form = parse_dashboard_mutation_form(
        request,
        allowed_fields={
            CSRF_FORM_FIELD,
            "status",
            "expected_version",
            "reason",
            "idempotency_key",
        },
        required_fields={
            CSRF_FORM_FIELD,
            "status",
            "expected_version",
            "reason",
            "idempotency_key",
        },
    )
    require_dashboard_csrf(request, authenticated=authenticated, form=form)
    try:
        target_status = IncidentStatus(form["status"])
        expected_version = _positive_canonical_integer(form["expected_version"])
        idempotency_key = validate_idempotency_key(form["idempotency_key"])
        normalized = normalize_transition(
            target_status=target_status,
            expected_version=expected_version,
            reason=None if form["reason"] == "" else form["reason"],
        )
    except (TransitionValidationError, ValueError):
        raise WebError(422, t(current_language(request), "err.invalid_transition_data")) from None
    request_hash = canonical_transition_hash(incident_id, normalized)
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    try:
        with session.begin():
            actor = lock_web_session_for_mutation(
                session,
                authenticated=authenticated,
                session_token=token,
                required_permission=Permission.TRANSITION_INCIDENTS,
                now=datetime.now(UTC),
            )
            outcome = transition_incident(
                session,
                actor=actor,
                incident_id=incident_id,
                transition=normalized,
                idempotency_key=idempotency_key,
                canonical_request_hash=request_hash,
                request_id=_request_id(request),
            )
    except InvalidWebSessionError:
        raise WebError(401, t(current_language(request), "err.login_required")) from None
    except WebSessionPermissionError:
        raise WebError(
            403, t(current_language(request), "err.insufficient_permissions")
        ) from None
    except SQLAlchemyError:
        raise WebError(
            503, t(current_language(request), "err.incident_mutation_unavailable")
        ) from None
    return _mutation_outcome_response(request, incident_id, outcome.http_status, outcome.replayed)


@router.post("/{incident_id}/comments", name="dashboard_incident_comment")
def incident_comment(
    incident_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authenticated: Annotated[
        AuthenticatedWebSession,
        Depends(require_dashboard_mutation_permission(Permission.COMMENT_INCIDENTS)),
    ],
) -> RedirectResponse:
    """Create or replay one append-only incident comment, then redirect."""

    form = parse_dashboard_mutation_form(
        request,
        allowed_fields={CSRF_FORM_FIELD, "comment", "idempotency_key"},
        required_fields={CSRF_FORM_FIELD, "comment", "idempotency_key"},
    )
    require_dashboard_csrf(request, authenticated=authenticated, form=form)
    try:
        idempotency_key = validate_idempotency_key(form["idempotency_key"])
        normalized = normalize_comment(form["comment"])
    except (CommentValidationError, TransitionValidationError):
        raise WebError(422, t(current_language(request), "err.invalid_comment")) from None
    request_hash = canonical_comment_hash(incident_id, normalized)
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    try:
        with session.begin():
            actor = lock_web_session_for_mutation(
                session,
                authenticated=authenticated,
                session_token=token,
                required_permission=Permission.COMMENT_INCIDENTS,
                now=datetime.now(UTC),
            )
            outcome = add_incident_comment(
                session,
                actor=actor,
                incident_id=incident_id,
                comment=normalized,
                idempotency_key=idempotency_key,
                canonical_request_hash=request_hash,
                request_id=_request_id(request),
            )
    except InvalidWebSessionError:
        raise WebError(401, t(current_language(request), "err.login_required")) from None
    except WebSessionPermissionError:
        raise WebError(
            403, t(current_language(request), "err.insufficient_permissions")
        ) from None
    except SQLAlchemyError:
        raise WebError(503, t(current_language(request), "err.comment_unavailable")) from None
    return _mutation_outcome_response(request, incident_id, outcome.http_status, outcome.replayed)


def _severities(values: list[str]) -> tuple[str, ...]:
    if any(value not in _SEVERITIES for value in values):
        raise DashboardQueryValidationError("invalid incident severity")
    return tuple(sorted(set(values)))


def _page_size(value: int) -> None:
    if type(value) is not int or value not in DASHBOARD_PAGE_SIZES:
        raise DashboardQueryValidationError("invalid dashboard page size")


def _positive_canonical_integer(value: str) -> int:
    if not value.isdecimal() or value.startswith("0"):
        raise ValueError("invalid positive integer")
    parsed = int(value)
    if not 1 <= parsed <= 2_147_483_647 or str(parsed) != value:
        raise ValueError("invalid positive integer")
    return parsed


def _mutation_outcome_response(
    request: Request,
    incident_id: UUID,
    http_status: int,
    replayed: bool,
) -> RedirectResponse:
    if http_status == 404:
        raise WebError(404, t(current_language(request), "err.incident_not_found"))
    if http_status == 409:
        raise WebError(409, t(current_language(request), "err.incident_conflict"))
    if http_status != 200:
        raise WebError(500, t(current_language(request), "err.internal_error"))
    response = RedirectResponse(
        external_path(request, f"/incidents/{incident_id}"),
        status_code=303,
    )
    if replayed:
        response.headers[IDEMPOTENCY_REPLAY_HEADER] = "true"
    return response


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unavailable"))
