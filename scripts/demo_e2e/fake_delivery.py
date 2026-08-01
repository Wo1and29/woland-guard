"""Explicit demo-only Telegram boundary for a real outbox worker without network."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote_to_bytes

import httpx2
from sqlalchemy.orm import Session, sessionmaker

from scripts.demo_e2e.contracts import DemoE2EError, SecretValue
from woland_guard_control_plane.application.outbox_worker import (
    DeliveryAdapter,
    EqualJitterBackoff,
    OutboxWorker,
)
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.infrastructure.database.models import NotificationAdapterKind
from woland_guard_control_plane.infrastructure.telegram.adapter import (
    TelegramDeliveryAdapter,
    load_telegram_delivery_configuration,
)
from woland_guard_control_plane.infrastructure.telegram.client import (
    TELEGRAM_API_ORIGIN,
    TelegramBotApiClient,
    TelegramHttpTimeouts,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramToken,
    TelegramTokenSynchronizer,
    validate_token_file_name,
)

DEMO_TOKEN_FILE_NAME: Final = "synthetic-demo.token"  # noqa: S105 - a filename, not a secret
MAX_FAKE_REQUEST_BYTES: Final = 16_384
ENCODED_TOKEN_SEGMENT: Final = re.compile(rb"(?:[A-Za-z0-9._~:!-]|%[0-9A-Fa-f]{2})+")


class DemoFakeDeliveryError(DemoE2EError):
    """The explicit in-process fake received an unexpected request."""


class _ChunkedResponse(httpx2.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        yield b'{"ok":true,'
        yield b'"result":{}}'


@dataclass(frozen=True, slots=True)
class DemoDeliveryEvidence:
    request_count: int


class DemoTelegramTransport(httpx2.BaseTransport):
    """Validate and discard a Telegram request without retaining sensitive fields."""

    __slots__ = ("_request_count", "_token_digest")

    def __init__(self, token: SecretValue) -> None:
        self._request_count = 0
        self._token_digest = hashlib.sha256(token.reveal().encode("utf-8")).digest()

    @property
    def evidence(self) -> DemoDeliveryEvidence:
        return DemoDeliveryEvidence(request_count=self._request_count)

    def __repr__(self) -> str:
        return f"DemoTelegramTransport(request_count={self._request_count}, body=<discarded>)"

    def handle_request(self, request: httpx2.Request) -> httpx2.Response:
        if (
            request.method != "POST"
            or request.url.scheme != "https"
            or request.url.host != "api.telegram.org"
            or request.url.port is not None
            or request.url.query
            or not _token_path_matches(request.url.raw_path, self._token_digest)
        ):
            raise DemoFakeDeliveryError("demo fake delivery rejected a request")
        raw = request.read()
        if not 1 <= len(raw) <= MAX_FAKE_REQUEST_BYTES:
            raise DemoFakeDeliveryError("demo fake delivery rejected a request")
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise DemoFakeDeliveryError("demo fake delivery rejected a request") from None
        if (
            not isinstance(body, dict)
            or set(body) != {"chat_id", "text"}
            or type(body["chat_id"]) is not int
            or type(body["text"]) is not str
            or not body["text"]
        ):
            raise DemoFakeDeliveryError("demo fake delivery rejected a request")
        self._request_count += 1
        del raw, body
        return httpx2.Response(
            200,
            stream=_ChunkedResponse(),
            request=request,
        )


class InMemoryDemoTokenSynchronizer(TelegramTokenSynchronizer):
    """Demo-only token source unavailable through production Settings or registry."""

    __slots__ = ("_credential", "_file_name")

    def __init__(self, credential: SecretValue, *, file_name: str = DEMO_TOKEN_FILE_NAME) -> None:
        self._credential = credential
        self._file_name = validate_token_file_name(file_name)

    def staging_file_ready(self, token_file_name: str) -> bool:
        return token_file_name == self._file_name

    def token_for_delivery(self, token_file_name: str) -> TelegramToken:
        if token_file_name != self._file_name:
            raise DemoFakeDeliveryError("demo token binding is invalid")
        return TelegramToken(self._credential.reveal())


def build_demo_worker(
    *,
    session_factory: sessionmaker[Session],
    settings: Settings,
    token: SecretValue,
) -> tuple[OutboxWorker, DemoTelegramTransport]:
    transport = DemoTelegramTransport(token)
    telegram_kind = NotificationAdapterKind.TELEGRAM.value
    adapters: dict[str, DeliveryAdapter] = {
        telegram_kind: TelegramDeliveryAdapter(
            client=TelegramBotApiClient._for_test(
                timeouts=TelegramHttpTimeouts(
                    connect=settings.telegram_connect_timeout_seconds,
                    read=settings.telegram_read_timeout_seconds,
                    write=settings.telegram_write_timeout_seconds,
                    pool=settings.telegram_pool_timeout_seconds,
                ),
                transport=transport,
            ),
            synchronizer=InMemoryDemoTokenSynchronizer(token),
        )
    }
    worker = OutboxWorker(
        session_factory=session_factory,
        adapters=adapters,
        configuration_loaders={telegram_kind: load_telegram_delivery_configuration},
        backoff=EqualJitterBackoff(
            base_seconds=settings.outbox_backoff_base_seconds,
            maximum_seconds=settings.outbox_backoff_max_seconds,
            retry_after_cap_seconds=settings.outbox_retry_after_cap_seconds,
        ),
        lease_seconds=settings.outbox_lease_seconds,
        adapter_timeout_seconds=settings.outbox_adapter_timeout_seconds,
        poll_seconds=settings.outbox_poll_seconds,
        recovery_interval_seconds=settings.outbox_recovery_interval_seconds,
    )
    return worker, transport


def assert_production_origin_unchanged() -> None:
    if TELEGRAM_API_ORIGIN != "https://api.telegram.org":
        raise DemoFakeDeliveryError("production Telegram origin invariant changed")


def _token_path_matches(raw_path: bytes, expected_digest: bytes) -> bool:
    prefix = b"/bot"
    suffix = b"/sendMessage"
    if (
        not raw_path.startswith(prefix)
        or not raw_path.endswith(suffix)
        or raw_path.count(b"/") != 2
    ):
        return False
    encoded = raw_path[len(prefix) : -len(suffix)]
    if not 1 <= len(encoded) <= 512 or ENCODED_TOKEN_SEGMENT.fullmatch(encoded) is None:
        return False
    try:
        token = unquote_to_bytes(encoded)
    except ValueError:
        return False
    if (
        not 1 <= len(token) <= 256
        or b"/" in token
        or any(value < 33 or value > 126 for value in token)
    ):
        return False
    actual_digest = hashlib.sha256(token).digest()
    return hmac.compare_digest(actual_digest, expected_digest)
