"""Liveness and readiness endpoints."""

from typing import Literal

from fastapi import APIRouter, Response, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from woland_guard_control_plane.database import check_database

router = APIRouter(prefix="/health", tags=["health"])


class LivenessResponse(BaseModel):
    """Response returned when the process is running."""

    status: Literal["alive"]


class ReadinessResponse(BaseModel):
    """Response describing dependency readiness."""

    status: Literal["ready", "not_ready"]
    database: Literal["ok", "unavailable"]


@router.get("/live", response_model=LivenessResponse)
def liveness() -> LivenessResponse:
    """Report process liveness without contacting external dependencies."""

    return LivenessResponse(status="alive")


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
def readiness(response: Response) -> ReadinessResponse:
    """Report readiness only after PostgreSQL accepts a simple query."""

    try:
        check_database()
    except SQLAlchemyError:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(status="not_ready", database="unavailable")

    return ReadinessResponse(status="ready", database="ok")
