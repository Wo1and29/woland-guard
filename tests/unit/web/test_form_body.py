"""Strict media-type and bounded ASGI form-body regressions."""

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from starlette.types import Message

from woland_guard_control_plane.web.form_body import (
    BoundedFormBodyMiddleware,
    content_type_is_allowed,
    parse_bounded_form,
)


@pytest.mark.parametrize(
    "value",
    [
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=UTF-8",
        "APPLICATION/X-WWW-FORM-URLENCODED; CHARSET=utf-8",
    ],
)
def test_browser_compatible_content_types_are_accepted(value: str) -> None:
    assert content_type_is_allowed(value)


@pytest.mark.parametrize(
    "value",
    [
        "application/json",
        "multipart/form-data; boundary=x",
        "application/x-www-form-urlencoded; charset=iso-8859-1",
        "application/x-www-form-urlencoded; charset=utf-8; charset=utf-8",
        "application/x-www-form-urlencoded; charset=utf-8; version=1",
        "application/x-www-form-urlencoded; =utf-8",
        "application/x-www-form-urlencoded; charset",
        "application/x-www-form-urlencoded\r\nX-Test: value",
    ],
)
def test_unsupported_or_malformed_content_types_are_rejected(value: str) -> None:
    assert not content_type_is_allowed(value)


def test_form_parser_uses_strict_utf8_and_exact_fields() -> None:
    assert parse_bounded_form(
        b"credential=value&_csrf=%D1%82%D0%B5%D1%81%D1%82",
        allowed_fields={"credential", "_csrf"},
        required_fields={"credential", "_csrf"},
        max_fields=2,
    ) == {"credential": "value", "_csrf": "тест"}


def test_chunked_body_is_rejected_before_downstream_after_hard_limit() -> None:
    asyncio.run(_assert_chunked_body_is_rejected())


async def _assert_chunked_body_is_rejected() -> None:
    downstream_called = False
    sent: list[dict[str, Any]] = []
    messages: AsyncIterator[dict[str, Any]] = _messages()

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal downstream_called
        downstream_called = True

    async def receive() -> dict[str, Any]:
        return await anext(messages)

    async def send(message: Message) -> None:
        sent.append(dict(message))

    middleware = BoundedFormBodyMiddleware(app, max_body_bytes=4)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        },
        receive,
        send,
    )

    assert not downstream_called
    assert sent[0]["status"] == 413


async def _messages() -> AsyncIterator[dict[str, Any]]:
    yield {"type": "http.request", "body": b"abc", "more_body": True}
    yield {"type": "http.request", "body": b"de", "more_body": False}
