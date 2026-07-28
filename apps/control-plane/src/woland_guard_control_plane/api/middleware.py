"""Request ID and pre-JSON ingestion request guards."""

import logging
import re
from typing import cast
from uuid import uuid4

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("uvicorn.error")

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_INGESTION_PATH = "/api/v1/events"


def request_id_from_scope(scope: Scope) -> str:
    """Return the request ID previously assigned to this ASGI scope."""

    state = scope.get("state", {})
    request_id = state.get("request_id")
    return str(request_id) if request_id is not None else uuid4().hex


class RequestIdMiddleware:
    """Assign, log, and return a safe request identifier for every HTTP request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        supplied_request_id = _header_value(scope, REQUEST_ID_HEADER.lower().encode("ascii"))
        request_id = (
            supplied_request_id
            if supplied_request_id is not None
            and _REQUEST_ID_PATTERN.fullmatch(supplied_request_id)
            else uuid4().hex
        )
        scope.setdefault("state", {})["request_id"] = request_id
        status_code = 500

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = list(message.get("headers", []))
                headers.append(
                    (REQUEST_ID_HEADER.lower().encode("ascii"), request_id.encode("ascii"))
                )
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        except Exception:
            state = scope.setdefault("state", {})
            if not state.get("wg_unexpected_error_logged", False):
                logger.error("request_id=%s event=request_unexpected_error", request_id)
                state["wg_unexpected_error_logged"] = True
            raise

        logger.info(
            "request_id=%s method=%s path=%s status=%d",
            request_id,
            scope.get("method", ""),
            scope.get("path", ""),
            status_code,
        )


class IngestionRequestGuardMiddleware:
    """Validate media type and bound request bytes before FastAPI parses JSON."""

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not _is_ingestion_request(scope):
            await self.app(scope, receive, send)
            return

        content_type = _header_value(scope, b"content-type")
        media_type = content_type.split(";", maxsplit=1)[0].strip().lower() if content_type else ""
        if media_type != "application/json":
            await _send_error(scope, receive, send, 415, "Content-Type must be application/json")
            return

        content_length = _header_value(scope, b"content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                await _send_error(scope, receive, send, 400, "invalid Content-Length")
                return
            if declared_length < 0:
                await _send_error(scope, receive, send, 400, "invalid Content-Length")
                return
            if declared_length > self.max_body_bytes:
                await _send_error(scope, receive, send, 413, "request body is too large")
                return

        body = await _read_bounded_body(receive, self.max_body_bytes)
        if body is None:
            await _send_error(scope, receive, send, 413, "request body is too large")
            return

        replay_receive = _build_replay_receive(body)
        await self.app(scope, replay_receive, send)


def _header_value(scope: Scope, name: bytes) -> str | None:
    for header_name, header_value in scope.get("headers", []):
        if header_name.lower() == name:
            return cast(bytes, header_value).decode("latin-1")
    return None


def _is_ingestion_request(scope: Scope) -> bool:
    return (
        scope["type"] == "http"
        and scope.get("method") == "POST"
        and scope.get("path") == _INGESTION_PATH
    )


async def _read_bounded_body(receive: Receive, max_body_bytes: int) -> bytes | None:
    chunks: list[bytes] = []
    received_bytes = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return b""
        body = message.get("body", b"")
        received_bytes += len(body)
        if received_bytes > max_body_bytes:
            return None
        chunks.append(body)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _build_replay_receive(body: bytes) -> Receive:
    delivered = False

    async def replay_receive() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return replay_receive


async def _send_error(
    scope: Scope,
    receive: Receive,
    send: Send,
    status_code: int,
    detail: str,
) -> None:
    request_id = request_id_from_scope(scope)
    response = JSONResponse(
        status_code=status_code,
        content={"detail": detail, "request_id": request_id},
    )
    await response(scope, receive, send)
