"""Version 1 ingestion endpoint for authenticated normalized event batches."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from woland_guard_contracts import EventBatchV1
from woland_guard_control_plane.api.errors import ApiError
from woland_guard_control_plane.application.authentication import (
    InactiveServerError,
    InvalidAgentCredentialsError,
    authenticate_agent,
)
from woland_guard_control_plane.application.detection import run_detection
from woland_guard_control_plane.application.detection.engine import DetectionEngineError
from woland_guard_control_plane.application.rate_limit import AgentRateLimiter
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.database import get_session
from woland_guard_control_plane.infrastructure.database.event_repository import insert_event_batch

logger = logging.getLogger("uvicorn.error")

router = APIRouter(prefix="/api/v1", tags=["events"])


class IngestEventsResponse(BaseModel):
    """Idempotent result of one committed event batch."""

    request_id: str
    batch_id: UUID
    accepted: int
    existing: int


@router.post(
    "/events",
    response_model=IngestEventsResponse,
    status_code=status.HTTP_200_OK,
)
def ingest_events(
    request: Request,
    batch: EventBatchV1,
    session: Annotated[Session, Depends(get_session)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> IngestEventsResponse:
    """Authenticate an agent and atomically persist its normalized event batch."""

    request_id = str(request.state.request_id)
    settings = cast(Settings, request.app.state.settings)
    rate_limiter = cast(AgentRateLimiter, request.app.state.agent_rate_limiter)
    token = _bearer_token(authorization)
    now = datetime.now(UTC)

    try:
        with session.begin():
            agent = authenticate_agent(session, token, now=now)
            retry_after = rate_limiter.consume(agent.public_id)
            if retry_after is not None:
                raise ApiError(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "agent request rate exceeded",
                    headers={"Retry-After": str(retry_after)},
                )

            _validate_timestamps(batch, now=now, settings=settings)
            agent.key.last_used_at = now
            new_events = insert_event_batch(
                session,
                server_id=agent.server_id,
                events=batch.events,
                persisted_at=now,
            )
            try:
                detection_result = run_detection(
                    session,
                    new_events=new_events,
                    outbox_max_attempts=settings.outbox_default_max_attempts,
                )
            except (DetectionEngineError, SQLAlchemyError):
                raise
            except Exception as error:
                raise DetectionEngineError("unexpected detection failure") from error
    except InvalidAgentCredentialsError:
        raise ApiError(
            status.HTTP_401_UNAUTHORIZED,
            "invalid agent credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except InactiveServerError:
        raise ApiError(status.HTTP_403_FORBIDDEN, "server is inactive") from None
    except ApiError:
        raise
    except (DetectionEngineError, SQLAlchemyError):
        logger.error("request_id=%s ingestion_database_error", request_id)
        raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "event ingestion unavailable") from None

    accepted = len(new_events)
    existing = len(batch.events) - accepted
    logger.info(
        "request_id=%s server_id=%s event_batch_committed accepted=%d existing=%d "
        "matched_rules=%d created_incidents=%d linked_evidence=%d",
        request_id,
        agent.server_id,
        accepted,
        existing,
        detection_result.matched_rules,
        detection_result.created_incidents,
        detection_result.linked_evidence,
    )
    return IngestEventsResponse(
        request_id=request_id,
        batch_id=batch.batch_id,
        accepted=accepted,
        existing=existing,
    )


def _bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise ApiError(
            status.HTTP_401_UNAUTHORIZED,
            "invalid agent credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or separator != " " or not token or " " in token:
        raise ApiError(
            status.HTTP_401_UNAUTHORIZED,
            "invalid agent credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def _validate_timestamps(batch: EventBatchV1, *, now: datetime, settings: Settings) -> None:
    sent_at = batch.sent_at.astimezone(UTC)
    maximum_skew = timedelta(seconds=settings.ingest_max_clock_skew_seconds)
    if abs(now - sent_at) > maximum_skew:
        raise ApiError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "sent_at is outside allowed clock skew",
        )

    latest_allowed_event_time = now + maximum_skew
    if any(
        event.collected_at.astimezone(UTC) > latest_allowed_event_time for event in batch.events
    ):
        raise ApiError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "event collected_at is outside allowed clock skew",
        )
