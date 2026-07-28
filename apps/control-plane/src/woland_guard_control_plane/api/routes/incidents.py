"""Authenticated incident read and idempotent workflow APIs."""

import logging
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from woland_guard_control_plane.api.dependencies import require_permission
from woland_guard_control_plane.api.errors import ApiError
from woland_guard_control_plane.application.incident_queries import (
    IncidentFilters,
    get_incident_detail,
    list_incidents,
)
from woland_guard_control_plane.application.incident_workflow import (
    IDEMPOTENCY_REPLAY_HEADER,
    TransitionValidationError,
    canonical_transition_hash,
    normalize_transition,
    transition_incident,
    validate_idempotency_key,
)
from woland_guard_control_plane.application.operator_authentication import (
    AuthenticatedOperatorApiKey,
)
from woland_guard_control_plane.application.pagination import CursorValidationError
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus

logger = logging.getLogger("uvicorn.error")
router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentSummaryResponse(BaseModel):
    id: UUID
    server_id: UUID
    rule_key: str
    rule_version: int
    severity: str
    status: IncidentStatus
    title: str
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    version: int
    created_at: datetime
    updated_at: datetime


class IncidentHistoryResponse(BaseModel):
    id: UUID
    version: int
    entry_type: str
    from_status: IncidentStatus | None
    to_status: IncidentStatus
    reason: str | None
    operator_id: UUID | None
    operator_username: str | None
    created_at: datetime


class IncidentDetailResponse(IncidentSummaryResponse):
    explanation: str
    recommendation: str
    history: list[IncidentHistoryResponse]


class IncidentPageResponse(BaseModel):
    request_id: str
    items: list[IncidentSummaryResponse]
    next_cursor: str | None


class IncidentDetailEnvelope(BaseModel):
    request_id: str
    incident: IncidentDetailResponse


class TransitionIncidentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus
    expected_version: StrictInt = Field(ge=1, le=2_147_483_647)
    reason: str | None = None


@router.get("", response_model=IncidentPageResponse)
def get_incidents(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    _operator: Annotated[
        AuthenticatedOperatorApiKey,
        Depends(require_permission(Permission.VIEW_INCIDENTS)),
    ],
    statuses: Annotated[list[IncidentStatus] | None, Query(alias="status")] = None,
    severities: Annotated[list[str] | None, Query(alias="severity")] = None,
    server_id: UUID | None = None,
    rule_key: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: str | None = None,
) -> IncidentPageResponse:
    """List safe incident summaries using immutable keyset ordering."""

    del _operator
    _validate_date_range(created_from, created_to)
    filters = IncidentFilters(
        statuses=tuple(item.value for item in statuses or []),
        severities=_normalize_severities(severities or []),
        server_id=server_id,
        rule_key=rule_key,
        created_from=created_from,
        created_to=created_to,
    )
    try:
        page = list_incidents(session, filters=filters, limit=limit, cursor=cursor)
    except CursorValidationError:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid cursor") from None
    except SQLAlchemyError:
        logger.error("request_id=%s incident_list_database_error", request.state.request_id)
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "incident query unavailable") from None
    return IncidentPageResponse(
        request_id=str(request.state.request_id),
        items=[IncidentSummaryResponse.model_validate(item) for item in page.items],
        next_cursor=page.next_cursor,
    )


@router.get("/{incident_id}", response_model=IncidentDetailEnvelope)
def get_incident(
    incident_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    _operator: Annotated[
        AuthenticatedOperatorApiKey,
        Depends(require_permission(Permission.VIEW_INCIDENTS)),
    ],
) -> IncidentDetailEnvelope:
    """Return one safe incident snapshot and its bounded workflow history."""

    del _operator
    try:
        detail = get_incident_detail(session, incident_id)
    except SQLAlchemyError:
        logger.error("request_id=%s incident_detail_database_error", request.state.request_id)
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "incident query unavailable") from None
    if detail is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "incident not found")
    return IncidentDetailEnvelope(
        request_id=str(request.state.request_id),
        incident=IncidentDetailResponse.model_validate(detail),
    )


@router.post("/{incident_id}/transitions")
def transition_incident_status(
    incident_id: UUID,
    request: Request,
    transition_request: TransitionIncidentRequest,
    session: Annotated[Session, Depends(get_session)],
    operator: Annotated[
        AuthenticatedOperatorApiKey,
        Depends(require_permission(Permission.TRANSITION_INCIDENTS)),
    ],
    idempotency_key_header: Annotated[
        str | None,
        Header(alias="Idempotency-Key"),
    ] = None,
) -> JSONResponse:
    """Commit or replay one operator-scoped incident status transition."""

    try:
        if idempotency_key_header is None:
            raise TransitionValidationError("missing Idempotency-Key")
        idempotency_key = validate_idempotency_key(idempotency_key_header)
        normalized = normalize_transition(
            target_status=transition_request.status,
            expected_version=transition_request.expected_version,
            reason=transition_request.reason,
        )
    except TransitionValidationError:
        raise ApiError(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid transition request"
        ) from None
    request_hash = canonical_transition_hash(incident_id, normalized)
    try:
        with session.begin():
            outcome = transition_incident(
                session,
                actor=operator.principal,
                incident_id=incident_id,
                transition=normalized,
                idempotency_key=idempotency_key,
                canonical_request_hash=request_hash,
                request_id=str(request.state.request_id),
            )
    except SQLAlchemyError:
        logger.error("request_id=%s incident_transition_database_error", request.state.request_id)
        raise ApiError(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "incident transition unavailable",
        ) from None

    body: dict[str, Any] = {"request_id": str(request.state.request_id), **outcome.response_body}
    headers = {IDEMPOTENCY_REPLAY_HEADER: "true"} if outcome.replayed else None
    return JSONResponse(status_code=outcome.http_status, content=body, headers=headers)


def _normalize_severities(values: list[str]) -> tuple[str, ...]:
    allowed = {"low", "medium", "high", "critical"}
    if any(value not in allowed for value in values):
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid incident filters")
    return tuple(sorted(set(values)))


def _validate_date_range(created_from: datetime | None, created_to: datetime | None) -> None:
    for value in (created_from, created_to):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid incident filters")
    if created_from is not None and created_to is not None and created_from >= created_to:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid incident filters")
