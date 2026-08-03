"""Strict bounded ASGI form-body collection and URL-encoded parsing."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Collection
from email.message import Message
from urllib.parse import parse_qsl

from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.types import Message as AsgiMessage
from starlette.types import Receive, Scope, Send

from woland_guard_control_plane.web.i18n import current_language, t

_HEX_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class BoundedFormError(ValueError):
    """A safe form transport/parsing error without body reflection."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class BoundedFormBodyMiddleware:
    """Buffer unsafe form bodies up to a hard byte limit before any parsing."""

    def __init__(self, app: Callable[..., Awaitable[None]], *, max_body_bytes: int) -> None:
        if type(max_body_bytes) is not int or max_body_bytes <= 0:
            raise ValueError("form body limit must be a positive integer")
        self._app = app
        self._max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self._app(scope, receive, send)
            return
        try:
            _validate_form_headers(scope, max_body_bytes=self._max_body_bytes)
            body = await _read_bounded_body(receive, max_body_bytes=self._max_body_bytes)
        except BoundedFormError as error:
            lang = current_language(Request(scope))
            response = HTMLResponse(
                _safe_error_document(error.status_code, lang),
                status_code=error.status_code,
            )
            await response(scope, receive, send)
            return
        scope.setdefault("state", {})["bounded_form_body"] = body
        replayed = False

        async def replay() -> AsgiMessage:
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self._app(scope, replay, send)


def parse_bounded_form(
    body: bytes,
    *,
    allowed_fields: Collection[str],
    required_fields: Collection[str],
    max_fields: int,
) -> dict[str, str]:
    """Parse a previously bounded UTF-8 form with an exact field allowlist."""

    if type(body) is not bytes or type(max_fields) is not int or max_fields <= 0:
        raise BoundedFormError(422, "invalid form")
    try:
        encoded = body.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise BoundedFormError(422, "invalid form") from error
    if _HEX_ESCAPE.search(encoded) is not None:
        raise BoundedFormError(422, "invalid form")
    try:
        pairs = parse_qsl(
            encoded,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=max_fields,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise BoundedFormError(422, "invalid form") from error
    allowed = set(allowed_fields)
    required = set(required_fields)
    result: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in result:
            raise BoundedFormError(422, "invalid form")
        result[key] = value
    if not required.issubset(result):
        raise BoundedFormError(422, "invalid form")
    return result


def content_type_is_allowed(value: str) -> bool:
    """Accept browser URL-encoded forms with zero or one UTF-8 charset."""

    if not value or any(character in value for character in "\r\n"):
        return False
    message = Message()
    message["content-type"] = value
    if message.get_content_type().casefold() != "application/x-www-form-urlencoded":
        return False
    params = message.get_params(header="content-type", failobj=[])
    if not params:
        return False
    extra = params[1:]
    if not extra:
        return True
    if len(extra) != 1:
        return False
    name, parameter_value = extra[0]
    return name.casefold() == "charset" and parameter_value.casefold() == "utf-8"


def _validate_form_headers(scope: Scope, *, max_body_bytes: int) -> None:
    grouped: dict[bytes, list[bytes]] = {}
    for name, value in scope.get("headers", []):
        grouped.setdefault(name.lower(), []).append(value)
    content_types = grouped.get(b"content-type", [])
    if len(content_types) != 1:
        raise BoundedFormError(415, "unsupported form content type")
    try:
        content_type = content_types[0].decode("latin-1")
    except UnicodeDecodeError as error:
        raise BoundedFormError(415, "unsupported form content type") from error
    if not content_type_is_allowed(content_type):
        raise BoundedFormError(415, "unsupported form content type")
    if b"content-encoding" in grouped:
        raise BoundedFormError(415, "encoded form bodies are not supported")
    lengths = grouped.get(b"content-length", [])
    if len(lengths) > 1:
        raise BoundedFormError(400, "invalid content length")
    if lengths:
        try:
            raw_length = lengths[0].decode("ascii")
        except UnicodeDecodeError as error:
            raise BoundedFormError(400, "invalid content length") from error
        if not raw_length.isdecimal():
            raise BoundedFormError(400, "invalid content length")
        if int(raw_length) > max_body_bytes:
            raise BoundedFormError(413, "form body is too large")


async def _read_bounded_body(receive: Receive, *, max_body_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise BoundedFormError(400, "request body was interrupted")
        if message["type"] != "http.request":
            raise BoundedFormError(400, "invalid request body")
        chunk = message.get("body", b"")
        if type(chunk) is not bytes:
            raise BoundedFormError(400, "invalid request body")
        total += len(chunk)
        if total > max_body_bytes:
            raise BoundedFormError(413, "form body is too large")
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _safe_error_document(status_code: int, lang: str) -> str:
    error_word = t(lang, "errors.error_word")
    return (
        f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
        f"<title>{error_word} {status_code}</title></head>"
        f"<body><main><h1>{error_word} {status_code}</h1>"
        f"<p>{t(lang, 'errors.request_cannot_be_processed')}</p></main></body></html>"
    )
