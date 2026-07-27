"""Telegram provider binding for the generic outbox worker."""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.outbox_worker import (
    DeliveryDisposition,
    DeliveryRequest,
    DeliveryResult,
)
from woland_guard_control_plane.infrastructure.database.models import (
    NotificationAdapterKind,
    OutboxErrorCode,
    TelegramDestinationConfig,
)
from woland_guard_control_plane.infrastructure.telegram.client import (
    TelegramBotApiClient,
    TelegramResponseTooLargeError,
    TelegramTransportError,
)
from woland_guard_control_plane.infrastructure.telegram.message import (
    TelegramMessageError,
    format_incident_created_message,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramTokenFileError,
    TelegramTokenSynchronizer,
)


class _RedactedScalar[T]:
    __slots__ = ("__value",)

    def __init__(self, value: T) -> None:
        self.__value = value

    def reveal(self) -> T:
        return self.__value

    def __repr__(self) -> str:
        return "<redacted>"

    def __str__(self) -> str:
        return "<redacted>"

    def __deepcopy__(self, _memo: dict[int, object]) -> _RedactedScalar[T]:
        return self


@dataclass(frozen=True, slots=True)
class TelegramDeliveryConfiguration:
    """Detached provider data with safe nested and direct representations."""

    destination_id: UUID
    chat_id: _RedactedScalar[int] = field(repr=False)
    token_file_name: _RedactedScalar[str] = field(repr=False)

    @classmethod
    def create(
        cls,
        *,
        destination_id: UUID,
        chat_id: int,
        token_file_name: str,
    ) -> TelegramDeliveryConfiguration:
        return cls(
            destination_id=destination_id,
            chat_id=_RedactedScalar(chat_id),
            token_file_name=_RedactedScalar(token_file_name),
        )

    def __repr__(self) -> str:
        return f"TelegramDeliveryConfiguration(destination_id={self.destination_id}, <redacted>)"

    def __str__(self) -> str:
        return self.__repr__()


def load_telegram_delivery_configuration(
    session: Session,
    destination_id: UUID,
) -> TelegramDeliveryConfiguration | None:
    config = session.scalar(
        select(TelegramDestinationConfig).where(
            TelegramDestinationConfig.destination_id == destination_id
        )
    )
    if config is None:
        return None
    return TelegramDeliveryConfiguration.create(
        destination_id=config.destination_id,
        chat_id=config.chat_id,
        token_file_name=config.token_file_name,
    )


class TelegramDeliveryAdapter:
    """Render and send one safe Telegram notification without database access."""

    def __init__(
        self,
        *,
        client: TelegramBotApiClient,
        synchronizer: TelegramTokenSynchronizer,
    ) -> None:
        self._client = client
        self._synchronizer = synchronizer

    def deliver(
        self,
        request: DeliveryRequest,
        *,
        timeout_seconds: float,
    ) -> DeliveryResult:
        configuration = request.provider_configuration
        if not isinstance(configuration, TelegramDeliveryConfiguration):
            return DeliveryResult(
                DeliveryDisposition.PERMANENT,
                OutboxErrorCode.DESTINATION_UNCONFIGURED,
            )
        try:
            token = self._synchronizer.token_for_delivery(configuration.token_file_name.reveal())
        except TelegramTokenFileError as error:
            return DeliveryResult(DeliveryDisposition.RETRYABLE, error.error_code)
        try:
            text = format_incident_created_message(request.payload)
        except TelegramMessageError:
            return DeliveryResult(
                DeliveryDisposition.PERMANENT,
                OutboxErrorCode.PAYLOAD_INVALID,
            )
        try:
            response = self._client.send_message(
                token=token,
                chat_id=configuration.chat_id.reveal(),
                text=text,
                timeout_seconds=timeout_seconds,
            )
        except TelegramResponseTooLargeError:
            return DeliveryResult(
                DeliveryDisposition.RETRYABLE,
                OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
            )
        except TelegramTransportError:
            return DeliveryResult(
                DeliveryDisposition.RETRYABLE,
                OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            )
        return _classify_response(response.status_code, response.body)


def _classify_response(status_code: int, body: bytes) -> DeliveryResult:
    if 300 <= status_code < 400:
        return DeliveryResult(
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
        )
    if status_code == 408:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
        )
    if status_code == 429:
        parsed = _parse_response(body)
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            retry_after_seconds=_retry_after(parsed),
        )
    if 500 <= status_code < 600:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
        )
    if 400 <= status_code < 500:
        return DeliveryResult(
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
        )
    if not 200 <= status_code < 300:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
        )

    parsed = _parse_response(body)
    if parsed is None:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
        )
    if parsed["ok"] is True:
        return DeliveryResult(DeliveryDisposition.DELIVERED)
    api_code = parsed.get("error_code")
    if type(api_code) is not int:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
        )
    if api_code == 408:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
        )
    if api_code == 429:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
            retry_after_seconds=_retry_after(parsed),
        )
    if 500 <= api_code < 600:
        return DeliveryResult(
            DeliveryDisposition.RETRYABLE,
            OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
        )
    if 400 <= api_code < 500:
        return DeliveryResult(
            DeliveryDisposition.PERMANENT,
            OutboxErrorCode.PERMANENT_DELIVERY_ERROR,
        )
    return DeliveryResult(
        DeliveryDisposition.RETRYABLE,
        OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
    )


def _parse_response(body: bytes) -> dict[str, object] | None:
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict) or type(parsed.get("ok")) is not bool:
        return None
    return parsed


def _retry_after(parsed: dict[str, object] | None) -> float | None:
    if parsed is None:
        return None
    parameters = parsed.get("parameters")
    if not isinstance(parameters, dict):
        return None
    value = parameters.get("retry_after")
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        return None
    return float(value)


def safe_asdict(configuration: TelegramDeliveryConfiguration) -> dict[str, object]:
    """Testable safe conversion; raw dataclasses.asdict retains redacted wrappers too."""

    return {
        "destination_id": str(configuration.destination_id),
        "chat_id": copy.deepcopy(configuration.chat_id),
        "token_file_name": copy.deepcopy(configuration.token_file_name),
    }


TELEGRAM_ADAPTER_KIND = NotificationAdapterKind.TELEGRAM.value
