"""HTTP request construction, response validation and safe error classification."""

from collections.abc import Callable
from datetime import UTC, datetime

import httpx2 as httpx
import pytest

from woland_guard_agent.config import SecretToken
from woland_guard_agent.transport import DeliveryClass, IngestionTransport
from woland_guard_contracts import NormalizedEventV1

SYNTHETIC_TOKEN = "wgak_transport.synthetic-secret"  # noqa: S105


def test_sends_batch_with_request_id_and_handles_accepted_plus_existing() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"accepted": 1, "existing": 1})

    transport = make_transport(handler)
    result = transport.send([make_event("one"), make_event("two")])
    second_result = transport.send([make_event("three"), make_event("four")])

    assert result.classification is DeliveryClass.SUCCESS
    assert result.accepted == 1
    assert result.existing == 1
    assert captured[0].headers["Authorization"] == f"Bearer {SYNTHETIC_TOKEN}"
    assert captured[0].headers["X-Request-ID"] == result.request_id
    assert captured[1].headers["X-Request-ID"] == second_result.request_id
    assert result.request_id != second_result.request_id
    assert captured[0].url.path == "/api/v1/events"


@pytest.mark.parametrize(
    ("status_code", "classification"),
    [
        (401, DeliveryClass.AUTHENTICATION),
        (403, DeliveryClass.FORBIDDEN),
        (413, DeliveryClass.PAYLOAD_TOO_LARGE),
        (422, DeliveryClass.UNPROCESSABLE),
        (500, DeliveryClass.SERVER_ERROR),
        (503, DeliveryClass.SERVER_ERROR),
    ],
)
def test_classifies_required_http_statuses(
    status_code: int,
    classification: DeliveryClass,
) -> None:
    transport = make_transport(lambda _request: httpx.Response(status_code))

    result = transport.send([make_event("status")])

    assert result.classification is classification


def test_retry_after_is_parsed_for_rate_limit() -> None:
    transport = make_transport(lambda _request: httpx.Response(429, headers={"Retry-After": "17"}))

    result = transport.send([make_event("rate")])

    assert result.classification is DeliveryClass.RATE_LIMITED
    assert result.retry_after_seconds == 17


def test_invalid_success_counts_are_protocol_error() -> None:
    transport = make_transport(
        lambda _request: httpx.Response(200, json={"accepted": 0, "existing": 0})
    )

    result = transport.send([make_event("invalid-count")])

    assert result.classification is DeliveryClass.PROTOCOL_ERROR


def test_network_exception_does_not_expose_token() -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic unavailable", request=request)

    transport = make_transport(unavailable)

    result = transport.send([make_event("network")])

    assert result.classification is DeliveryClass.NETWORK_ERROR
    assert SYNTHETIC_TOKEN not in repr(result)


def test_production_transport_rejects_plain_http() -> None:
    with pytest.raises(ValueError, match="requires HTTPS"):
        IngestionTransport(
            base_url="http://control-plane.invalid",
            token=SecretToken(SYNTHETIC_TOKEN),
            connect_timeout_seconds=1,
            read_timeout_seconds=1,
        )


def make_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> IngestionTransport:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return IngestionTransport(
        base_url="https://control-plane.invalid",
        token=SecretToken(SYNTHETIC_TOKEN),
        connect_timeout_seconds=1,
        read_timeout_seconds=1,
        client=client,
    )


def make_event(summary: str) -> NormalizedEventV1:
    return NormalizedEventV1(
        occurred_at=datetime(2024, 1, 1, tzinfo=UTC),
        collected_at=datetime(2024, 1, 1, tzinfo=UTC),
        event_type="linux.journald",
        summary=summary,
    )
