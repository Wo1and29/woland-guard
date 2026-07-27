"""In-process fake Bot API transport with strict canonical request checks."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx2


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

    def handle_request(self, request: httpx2.Request) -> httpx2.Response:
        assert request.method == "POST"
        assert request.url.scheme == "https"
        assert request.url.host == "api.telegram.org"
        assert request.url.port is None
        assert request.url.query == b""
        raw_path = request.url.raw_path
        assert raw_path.startswith(b"/bot")
        assert raw_path.endswith(b"/sendMessage")
        assert raw_path.count(b"/") == 2
        if self.expected_tokens:
            expected = quote(self.expected_tokens.pop(0), safe="").encode("ascii")
            assert raw_path == b"/bot" + expected + b"/sendMessage"
        body = json.loads(request.read())
        assert set(body) == {"chat_id", "text"}
        assert type(body["chat_id"]) is int
        assert type(body["text"]) is str
        self.requests.append(body)
        return httpx2.Response(
            self.status_code,
            stream=ChunkedBody(self.response_chunks),
            request=request,
        )
