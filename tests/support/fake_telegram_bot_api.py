"""In-process fake Bot API transport with strict canonical request checks."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx2

_REQUIRED_BODY_KEYS = {
    "sendMessage": {"chat_id", "text"},
    "getUpdates": {"offset", "limit", "timeout", "allowed_updates"},
    "answerCallbackQuery": {"callback_query_id", "text", "show_alert"},
}
_OPTIONAL_BODY_KEYS = {
    "sendMessage": {"reply_markup"},
    "getUpdates": frozenset(),
    "answerCallbackQuery": frozenset(),
}


class ChunkedBody(httpx2.SyncByteStream):
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = tuple(chunks)

    def __iter__(self) -> Iterator[bytes]:
        return iter(self._chunks)


@dataclass(slots=True)
class FakeTelegramBotApiTransport(httpx2.BaseTransport):
    """A dependency-injected fake unavailable through Settings, CLI, or PostgreSQL."""

    status_code: int = 200
    response_chunks: tuple[bytes, ...] = (b'{"ok":true,"result":{}}',)
    requests: list[dict[str, Any]] = field(default_factory=list, repr=False)
    expected_tokens: list[str] = field(default_factory=list, repr=False)
    allowed_methods: tuple[str, ...] = ("sendMessage",)
    methods: list[str] = field(default_factory=list, repr=False)

    def handle_request(self, request: httpx2.Request) -> httpx2.Response:
        assert request.method == "POST"
        assert request.url.scheme == "https"
        assert request.url.host == "api.telegram.org"
        assert request.url.port is None
        assert request.url.query == b""
        raw_path = request.url.raw_path
        assert raw_path.startswith(b"/bot")
        assert raw_path.count(b"/") == 2
        method = raw_path.rsplit(b"/", 1)[1].decode("ascii")
        assert method in self.allowed_methods
        if self.expected_tokens:
            expected = quote(self.expected_tokens.pop(0), safe="").encode("ascii")
            assert raw_path == b"/bot" + expected + b"/" + method.encode("ascii")
        body = json.loads(request.read())
        required = _REQUIRED_BODY_KEYS[method]
        allowed = required | _OPTIONAL_BODY_KEYS[method]
        assert required <= set(body) <= allowed
        if method == "sendMessage":
            assert type(body["chat_id"]) is int
            assert type(body["text"]) is str
            if "reply_markup" in body:
                assert isinstance(body["reply_markup"], dict)
        elif method == "getUpdates":
            assert type(body["offset"]) is int
            assert type(body["limit"]) is int
            assert type(body["timeout"]) is int
            assert type(body["allowed_updates"]) is list
        else:
            assert type(body["callback_query_id"]) is str
            assert type(body["text"]) is str
            assert type(body["show_alert"]) is bool
        self.methods.append(method)
        self.requests.append(body)
        return httpx2.Response(
            self.status_code,
            stream=ChunkedBody(self.response_chunks),
            request=request,
        )
