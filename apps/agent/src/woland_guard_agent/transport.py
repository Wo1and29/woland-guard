"""HTTPS-only ingestion transport with safe response classification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from uuid import uuid4

import httpx2 as httpx

from woland_guard_agent.config import SecretToken
from woland_guard_contracts import EventBatchV1, NormalizedEventV1


class DeliveryClass(StrEnum):
    SUCCESS = "success"
    AUTHENTICATION = "authentication"
    FORBIDDEN = "forbidden"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNPROCESSABLE = "unprocessable"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    NETWORK_ERROR = "network_error"
    PROTOCOL_ERROR = "protocol_error"


@dataclass(frozen=True, slots=True)
class TransportResult:
    classification: DeliveryClass
    request_id: str
    accepted: int = 0
    existing: int = 0
    retry_after_seconds: float | None = None


class IngestionTransport:
    """Send batches without exposing the token or response body to callers."""

    def __init__(
        self,
        *,
        base_url: str,
        token: SecretToken,
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
        allow_insecure_http_for_tests: bool = False,
        client: httpx.Client | None = None,
    ) -> None:
        if not base_url.startswith("https://") and not allow_insecure_http_for_tests:
            raise ValueError("agent transport requires HTTPS")
        self._endpoint = f"{base_url.rstrip('/')}/api/v1/events"
        self._token = token
        timeout = httpx.Timeout(
            connect=connect_timeout_seconds,
            read=read_timeout_seconds,
            write=read_timeout_seconds,
            pool=connect_timeout_seconds,
        )
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    def send(self, events: list[NormalizedEventV1]) -> TransportResult:
        if not 1 <= len(events) <= 100:
            raise ValueError("transport batch must contain between 1 and 100 events")

        request_id = uuid4().hex
        batch = EventBatchV1(sent_at=datetime.now(UTC), events=tuple(events))
        try:
            response = self._client.post(
                self._endpoint,
                headers={
                    "Authorization": self._token.authorization_header(),
                    "Content-Type": "application/json",
                    "X-Request-ID": request_id,
                },
                json=batch.model_dump(mode="json"),
            )
        except httpx.HTTPError:
            return TransportResult(DeliveryClass.NETWORK_ERROR, request_id=request_id)

        if response.status_code == 200:
            return _successful_result(response, request_id=request_id, expected=len(events))
        if response.status_code == 401:
            return TransportResult(DeliveryClass.AUTHENTICATION, request_id=request_id)
        if response.status_code == 403:
            return TransportResult(DeliveryClass.FORBIDDEN, request_id=request_id)
        if response.status_code == 413:
            return TransportResult(DeliveryClass.PAYLOAD_TOO_LARGE, request_id=request_id)
        if response.status_code == 422:
            return TransportResult(DeliveryClass.UNPROCESSABLE, request_id=request_id)
        if response.status_code == 429:
            return TransportResult(
                DeliveryClass.RATE_LIMITED,
                request_id=request_id,
                retry_after_seconds=_retry_after_seconds(response.headers.get("Retry-After")),
            )
        if 500 <= response.status_code <= 599:
            return TransportResult(DeliveryClass.SERVER_ERROR, request_id=request_id)
        return TransportResult(DeliveryClass.PROTOCOL_ERROR, request_id=request_id)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> IngestionTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _successful_result(
    response: httpx.Response,
    *,
    request_id: str,
    expected: int,
) -> TransportResult:
    try:
        body = response.json()
        accepted = body["accepted"]
        existing = body["existing"]
    except (ValueError, KeyError, TypeError):
        return TransportResult(DeliveryClass.PROTOCOL_ERROR, request_id=request_id)

    if (
        not isinstance(accepted, int)
        or isinstance(accepted, bool)
        or not isinstance(existing, int)
        or isinstance(existing, bool)
        or accepted < 0
        or existing < 0
        or accepted + existing != expected
    ):
        return TransportResult(DeliveryClass.PROTOCOL_ERROR, request_id=request_id)
    return TransportResult(
        DeliveryClass.SUCCESS,
        request_id=request_id,
        accepted=accepted,
        existing=existing,
    )


def _retry_after_seconds(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            target = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if target.tzinfo is None:
            target = target.replace(tzinfo=UTC)
        seconds = (target - datetime.now(UTC)).total_seconds()
    return max(0.0, min(seconds, 3_600.0))
