from __future__ import annotations

import httpx2
import pytest
from scripts.demo_e2e.contracts import SecretValue
from scripts.demo_e2e.fake_delivery import DemoFakeDeliveryError, DemoTelegramTransport


def test_fake_delivery_validates_and_discards_sensitive_request_fields() -> None:
    token = SecretValue("123:SyntheticCredential")
    transport = DemoTelegramTransport(token)
    request = httpx2.Request(
        "POST",
        "https://api.telegram.org/bot123:SyntheticCredential/sendMessage",
        json={"chat_id": -1001234567890, "text": "Synthetic notification"},
    )

    response = transport.handle_request(request)

    assert response.status_code == 200
    assert transport.evidence.request_count == 1
    representation = repr(transport)
    assert "SyntheticCredential" not in representation
    assert "Synthetic notification" not in representation
    assert "-1001234567890" not in representation


def test_fake_delivery_rejects_noncanonical_or_oversized_requests() -> None:
    transport = DemoTelegramTransport(SecretValue("123:SyntheticCredential"))

    with pytest.raises(DemoFakeDeliveryError):
        transport.handle_request(
            httpx2.Request(
                "POST",
                "https://example.invalid/botSyntheticCredential/sendMessage",
                json={"chat_id": 1, "text": "synthetic"},
            )
        )

    assert transport.evidence.request_count == 0


def test_fake_delivery_binds_expected_token_digest_without_disclosure() -> None:
    expected = "123:SyntheticExpectedCanary"
    wrong = "123:SyntheticWrongCanary"
    transport = DemoTelegramTransport(SecretValue(expected))

    accepted = transport.handle_request(
        httpx2.Request(
            "POST",
            "https://api.telegram.org/bot123%3ASyntheticExpectedCanary/sendMessage",
            json={"chat_id": 1, "text": "synthetic"},
        )
    )
    assert accepted.status_code == 200

    with pytest.raises(DemoFakeDeliveryError) as captured:
        transport.handle_request(
            httpx2.Request(
                "POST",
                f"https://api.telegram.org/bot{wrong}/sendMessage",
                json={"chat_id": 1, "text": "synthetic"},
            )
        )
    assert expected not in repr(transport)
    assert expected not in str(captured.value)
    assert wrong not in str(captured.value)


@pytest.mark.parametrize("segment", ["", "x" * 513, "%00", "%ZZ", "bad%2Ftoken"])
def test_fake_delivery_rejects_malformed_or_oversized_token(segment: str) -> None:
    transport = DemoTelegramTransport(SecretValue("123:SyntheticCredential"))
    with pytest.raises(DemoFakeDeliveryError):
        transport.handle_request(
            httpx2.Request(
                "POST",
                f"https://api.telegram.org/bot{segment}/sendMessage",
                json={"chat_id": 1, "text": "synthetic"},
            )
        )
