"""Synchronous fixed-origin Telegram Bot API client with bounded streaming reads."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import quote

import httpx2

from woland_guard_control_plane.infrastructure.telegram.logging_guard import (
    suppress_sensitive_http_logging,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import TelegramToken

TELEGRAM_API_ORIGIN: Final = "https://api.telegram.org"
TELEGRAM_RESPONSE_LIMIT_BYTES: Final = 65_536
CALLBACK_QUERY_ANSWER_TEXT_MAX_CHARS: Final = 200


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
        reply_markup: dict[str, Any] | None = None,
    ) -> TelegramHttpResponse:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        return self._call(
            token=token,
            method="sendMessage",
            payload=payload,
            timeout_seconds=timeout_seconds,
        )

    def answer_callback_query(
        self,
        *,
        token: TelegramToken,
        callback_query_id: str,
        text: str,
        show_alert: bool,
        timeout_seconds: float,
    ) -> TelegramHttpResponse:
        """Answer one callback_query; the reply is visible only to the presser."""

        if not 1 <= len(callback_query_id) <= 128 or not callback_query_id.isascii():
            raise ValueError("Telegram callback_query_id is invalid.")
        if len(text) > CALLBACK_QUERY_ANSWER_TEXT_MAX_CHARS:
            raise ValueError("Telegram callback answer text is too long.")
        return self._call(
            token=token,
            method="answerCallbackQuery",
            payload={
                "callback_query_id": callback_query_id,
                "text": text,
                "show_alert": show_alert,
            },
            timeout_seconds=timeout_seconds,
        )

    def get_updates(
        self,
        *,
        token: TelegramToken,
        offset: int,
        limit: int,
        long_poll_seconds: int,
        allowed_updates: tuple[str, ...],
        timeout_seconds: float,
    ) -> TelegramHttpResponse:
        """Long-poll the confirmed offset for the single allowed inbound consumer."""

        if offset < 0 or not 1 <= limit <= 100 or long_poll_seconds < 0:
            raise ValueError("Telegram update request parameters are invalid.")
        if not allowed_updates or any(
            not value or len(value) > 32 or not value.isascii() for value in allowed_updates
        ):
            raise ValueError("Telegram update request parameters are invalid.")
        return self._call(
            token=token,
            method="getUpdates",
            payload={
                "offset": offset,
                "limit": limit,
                "timeout": long_poll_seconds,
                "allowed_updates": list(allowed_updates),
            },
            timeout_seconds=timeout_seconds,
        )

    def _call(
        self,
        *,
        token: TelegramToken,
        method: str,
        payload: dict[str, object],
        timeout_seconds: float,
    ) -> TelegramHttpResponse:
        """Issue one bounded fixed-origin Bot API call without leaking the token."""

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
        url = f"{TELEGRAM_API_ORIGIN}/bot{encoded_token}/{method}"
        try:
            with httpx2.Client(
                timeout=timeout,
                transport=transport,
                trust_env=False,
                verify=True,
                follow_redirects=False,
            ) as client:
                with client.stream("POST", url, json=payload) as response:
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
