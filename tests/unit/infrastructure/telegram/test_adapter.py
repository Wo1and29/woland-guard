"""Redacted provider DTO and Telegram response classification."""

import dataclasses
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from tests.support.fake_telegram_bot_api import FakeTelegramBotApiTransport

from woland_guard_control_plane.application.outbox import IncidentCreatedNotificationV1
from woland_guard_control_plane.application.outbox_worker import (
    DeliveryDisposition,
    DeliveryRequest,
)
from woland_guard_control_plane.infrastructure.database.models import OutboxErrorCode
from woland_guard_control_plane.infrastructure.telegram.adapter import (
    TelegramDeliveryAdapter,
    TelegramDeliveryConfiguration,
    _classify_response,
    safe_asdict,
)
from woland_guard_control_plane.infrastructure.telegram.client import (
    TelegramBotApiClient,
    TelegramHttpTimeouts,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramTokenSynchronizer,
)

CANARY_CHAT_ID = 4_001_002_003
CANARY_FILE_NAME = "canary-token-file.secret"


def test_provider_configuration_is_redacted_in_nested_representations(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configuration = TelegramDeliveryConfiguration.create(
        destination_id=UUID("10000000-0000-4000-8000-000000000001"),
        chat_id=CANARY_CHAT_ID,
        token_file_name=CANARY_FILE_NAME,
    )
    logger = logging.getLogger("test.telegram.dto")
    with caplog.at_level(logging.WARNING, logger="test.telegram.dto"):
        logger.warning("repr=%r str=%s", configuration, configuration)
    rendered = " ".join(
        (
            repr(configuration),
            str(configuration),
            repr([configuration]),
            repr({"configuration": configuration}),
            repr(dataclasses.asdict(configuration)),
            repr(safe_asdict(configuration)),
            repr(RuntimeError(configuration)),
        )
    )
    assert str(CANARY_CHAT_ID) not in rendered
    assert CANARY_FILE_NAME not in rendered
    assert str(CANARY_CHAT_ID) not in caplog.text
    assert CANARY_FILE_NAME not in caplog.text
    assert not hasattr(configuration, "claim_token")
    assert not hasattr(configuration, "token")


@pytest.mark.parametrize(
    ("status_code", "body", "disposition", "error_code", "retry_after"),
    [
        (
            503,
            b'{"ok":false,"error_code":400}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            None,
        ),
        (
            408,
            b'{"ok":false,"error_code":400}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            None,
        ),
        (
            429,
            b'{"ok":false,"error_code":400,"parameters":{"retry_after":12}}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            12.0,
        ),
        (
            302,
            b'{"ok":false,"error_code":503}',
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
            None,
        ),
        (
            401,
            b"not-json",
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
            None,
        ),
        (
            400,
            b'{"ok":false,"error_code":503}',
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
            None,
        ),
        (
            200,
            b'{"ok":false,"error_code":408}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            None,
        ),
        (
            200,
            b'{"ok":false,"error_code":429,"parameters":{"retry_after":12}}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            12.0,
        ),
        (
            200,
            b'{"ok":false,"error_code":503}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            None,
        ),
        (
            200,
            b'{"ok":false,"error_code":400}',
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
            None,
        ),
        (
            200,
            b'{"ok":false}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            None,
        ),
        (
            200,
            b'{"ok":false,"error_code":"429"}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            None,
        ),
        (
            200,
            b'{"ok":false,"error_code":399}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            None,
        ),
        (
            200,
            b'{"ok":"true"}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            None,
        ),
        (
            200,
            b'{"error_code":400}',
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            None,
        ),
        (
            200,
            b"[]",
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            None,
        ),
        (
            200,
            b"not-json",
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            None,
        ),
        (200, b'{"ok":true,"result":{}}', DeliveryDisposition.DELIVERED, None, None),
    ],
)
def test_telegram_api_response_classification_is_closed(
    status_code: int,
    body: bytes,
    disposition: DeliveryDisposition,
    error_code: OutboxErrorCode | None,
    retry_after: float | None,
) -> None:
    result = _classify_response(status_code, body)
    assert result.disposition is disposition
    assert result.error_code is error_code
    assert result.retry_after_seconds == retry_after


def test_next_delivery_uses_atomically_rotated_staging_token(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    token_file_name = "rotation.token"  # noqa: S105
    first_token = "synthetic-first-adapter-token"  # noqa: S105
    second_token = "synthetic-second-adapter-token"  # noqa: S105
    token_path = staging / token_file_name
    token_path.write_text(first_token, encoding="ascii")
    fake_api = FakeTelegramBotApiTransport(expected_tokens=[first_token, second_token])
    adapter = TelegramDeliveryAdapter(
        client=TelegramBotApiClient._for_test(
            timeouts=TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1),
            transport=fake_api,
        ),
        synchronizer=TelegramTokenSynchronizer(
            staging_directory=staging,
            runtime_directory=runtime,
            enforce_posix_metadata=False,
        ),
        dashboard_origin="https://localhost:8443",
    )
    configuration = TelegramDeliveryConfiguration.create(
        destination_id=UUID("10000000-0000-4000-8000-000000000001"),
        chat_id=CANARY_CHAT_ID,
        token_file_name=token_file_name,
    )
    request = DeliveryRequest(
        outbox_id=UUID("20000000-0000-4000-8000-000000000001"),
        incident_id=UUID("30000000-0000-4000-8000-000000000001"),
        destination_id=configuration.destination_id,
        adapter_kind="telegram",
        notification_type="incident.created",
        payload=IncidentCreatedNotificationV1(
            incident_id=UUID("30000000-0000-4000-8000-000000000001"),
            server_id=UUID("40000000-0000-4000-8000-000000000001"),
            rule_key="synthetic_rule",
            rule_version=1,
            severity="high",
            title="Synthetic incident",
            created_at=datetime.now(UTC),
        ),
        attempt_count=1,
        provider_configuration=configuration,
    )

    assert adapter.deliver(request, timeout_seconds=4).disposition is DeliveryDisposition.DELIVERED
    replacement = staging / "replacement"
    replacement.write_text(second_token, encoding="ascii")
    os.replace(replacement, token_path)
    assert adapter.deliver(request, timeout_seconds=4).disposition is DeliveryDisposition.DELIVERED
    assert fake_api.expected_tokens == []
