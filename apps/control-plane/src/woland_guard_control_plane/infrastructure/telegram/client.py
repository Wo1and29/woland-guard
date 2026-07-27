"""Synchronous fixed-origin Telegram Bot API client with bounded streaming reads."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import quote

import httpx2

from woland_guard_control_plane.infrastructure.telegram.logging_guard import (
    suppress_sensitive_http_logging,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import TelegramToken

TELEGRAM_API_ORIGIN: Final = "https://api.telegram.org"
TELEGRAM_RESPONSE_LIMIT_BYTES: Final = 65_536


class TelegramTransportError(RuntimeError):
    """Safe transport failure without URL, request, response, or exception details."""


class TelegramResponseTooLargeError(TelegramTransportError):
    """The provider response exceeded the bounded protocol buffer."""


@dataclass(frozen=True, slots=True)
class TelegramHttpResponse:
    status_code: int
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class TelegramHttpTimeouts:
    connect: float = 5.0
    read: float = 10.0
    write: float = 5.0
    pool: float = 1.0

    def validate_for(self, overall_budget: float) -> None:
        values = (self.connect, self.read, self.write, self.pool, overall_budget)
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
            for value in values
        ):
            raise ValueError("Telegram HTTP timeout configuration is invalid.")
        if sum(values[:-1]) > overall_budget:
            raise ValueError("Telegram HTTP timeout configuration is invalid.")


class TelegramBotApiClient:
    """A production client whose origin cannot be selected through runtime configuration."""

    __slots__ = ("_timeouts", "_transport")

    def __init__(
        self,
        *,
        timeouts: TelegramHttpTimeouts,
        _test_transport: httpx2.BaseTransport | None = None,
    ) -> None:
        self._timeouts = timeouts
        self._transport = _test_transport

    @classmethod
    def production(cls, *, timeouts: TelegramHttpTimeouts) -> TelegramBotApiClient:
        """Build the only client used by the production adapter registry."""

        return cls(timeouts=timeouts)

    @classmethod
    def _for_test(
        cls,
        *,
        timeouts: TelegramHttpTimeouts,
        transport: httpx2.BaseTransport,
    ) -> TelegramBotApiClient:
        return cls(timeouts=timeouts, _test_transport=transport)

    def send_message(
        self,
        *,
        token: TelegramToken,
        chat_id: int,
        text: str,
        timeout_seconds: float,
    ) -> TelegramHttpResponse:
        self._timeouts.validate_for(timeout_seconds)
        suppress_sensitive_http_logging()
        timeout = httpx2.Timeout(
            connect=self._timeouts.connect,
            read=self._timeouts.read,
            write=self._timeouts.write,
            pool=self._timeouts.pool,
        )
        transport = self._transport or httpx2.HTTPTransport(retries=0, verify=True)
        encoded_token = quote(token.reveal_for_http(), safe="")
        url = f"{TELEGRAM_API_ORIGIN}/bot{encoded_token}/sendMessage"
        try:
            with httpx2.Client(
                timeout=timeout,
                transport=transport,
                trust_env=False,
                verify=True,
                follow_redirects=False,
            ) as client:
                with client.stream(
                    "POST",
                    url,
                    json={"chat_id": chat_id, "text": text},
                ) as response:
                    buffer = bytearray()
                    for chunk in response.iter_bytes():
                        if len(buffer) + len(chunk) > TELEGRAM_RESPONSE_LIMIT_BYTES:
                            raise TelegramResponseTooLargeError(
                                "Telegram response exceeded the safe size limit."
                            )
                        buffer.extend(chunk)
                    return TelegramHttpResponse(
                        status_code=response.status_code,
                        body=bytes(buffer),
                    )
        except TelegramTransportError:
            raise
        except httpx2.HTTPError:
            raise TelegramTransportError("Telegram transport failed safely.") from None
