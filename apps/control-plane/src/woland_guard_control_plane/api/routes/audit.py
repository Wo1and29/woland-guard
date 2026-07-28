"""Admin-only safe append-only audit log API."""

import logging
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from woland_guard_control_plane.api.dependencies import require_permission
from woland_guard_control_plane.api.errors import ApiError
from woland_guard_control_plane.application.incident_queries import (
    AuditFilters,
    list_audit_entries,
)
from woland_guard_control_plane.application.operator_authentication import (
    AuthenticatedOperatorApiKey,
)
from woland_guard_control_plane.application.pagination import CursorValidationError
from woland_guard_control_plane.application.rbac import Permission
from woland_guard_control_plane.database import get_session

logger = logging.getLogger("uvicorn.error")
router = APIRouter(prefix="/api/v1/audit-log", tags=["audit"])


class AuditEntryResponse(BaseModel):
    id: UUID
    actor_type: str
    operator_id: UUID | None
    actor_username: str | None
    action: str
    target_type: str
    target_id: UUID
    request_id: str | None
    details: dict[str, Any]
    created_at: datetime


class AuditPageResponse(BaseModel):
    request_id: str
    items: list[AuditEntryResponse]
    next_cursor: str | None


@router.get("", response_model=AuditPageResponse)
def get_audit_log(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    _operator: Annotated[
        AuthenticatedOperatorApiKey,
        Depends(require_permission(Permission.VIEW_AUDIT_LOG)),
    ],
    operator_id: UUID | None = None,
    action: Annotated[str | None, Query(min_length=3, max_length=64)] = None,
    target_type: Annotated[str | None, Query(min_length=3, max_length=32)] = None,
    target_id: UUID | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: str | None = None,
) -> AuditPageResponse:
    """List allowlisted audit entries with strict keyset pagination."""

    del _operator
    _validate_date_range(created_from, created_to)
    filters = AuditFilters(
        operator_id=operator_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        created_from=created_from,
        created_to=created_to,
    )
    try:
        page = list_audit_entries(session, filters=filters, limit=limit, cursor=cursor)
    except CursorValidationError:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid cursor") from None
    except SQLAlchemyError:
        logger.error("request_id=%s audit_list_database_error", request.state.request_id)
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "audit query unavailable") from None
    return AuditPageResponse(
        request_id=str(request.state.request_id),
        items=[AuditEntryResponse.model_validate(item) for item in page.items],
        next_cursor=page.next_cursor,
    )


def _validate_date_range(created_from: datetime | None, created_to: datetime | None) -> None:
    for value in (created_from, created_to):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid audit filters")
    if created_from is not None and created_to is not None and created_from >= created_to:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid audit filters")
