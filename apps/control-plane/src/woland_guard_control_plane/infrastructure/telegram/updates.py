"""Strict bounded contracts for the inbound Telegram update subset used by 9A.

Unlike the project's own event contracts, these models use ``extra="ignore"`` rather
than ``extra="forbid"``: the Bot API is an external contract that gains fields over
time, and forbidding unknown keys would fail closed on every upstream addition. The
safety property here is that only allowlisted fields are ever read; anything else is
dropped before the value reaches application code.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

TELEGRAM_MESSAGE_TEXT_MAX_CHARS: Final = 4_096
TELEGRAM_UPDATE_BATCH_MAX: Final = 100
TELEGRAM_USER_ID_MAX: Final = 2**53 - 1
TELEGRAM_CALLBACK_QUERY_ID_MAX_CHARS: Final = 128
TELEGRAM_CALLBACK_DATA_MAX_CHARS: Final = 256
PRIVATE_CHAT_TYPE: Final = "private"


class TelegramUpdateError(ValueError):
    """A safe rejection of one malformed or oversized Bot API response."""


class _InboundModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class TelegramSender(_InboundModel):
    """The account that produced one update."""

    id: int = Field(gt=0, le=TELEGRAM_USER_ID_MAX)
    is_bot: bool = False


class TelegramChat(_InboundModel):
    """The conversation one message belongs to."""

    id: int
    type: str = Field(max_length=32)


class TelegramMessage(_InboundModel):
    """One inbound message; non-text messages arrive without ``text``."""

    message_id: int
    sender: TelegramSender | None = Field(default=None, alias="from")
    chat: TelegramChat
    text: str | None = Field(default=None, max_length=TELEGRAM_MESSAGE_TEXT_MAX_CHARS)

    @property
    def is_private(self) -> bool:
        """Return whether this message came from a one-to-one conversation."""

        return self.chat.type == PRIVATE_CHAT_TYPE


class TelegramCallbackQuery(_InboundModel):
    """One inline-button press; ``data`` is untrusted input, not our own value."""

    id: str = Field(min_length=1, max_length=TELEGRAM_CALLBACK_QUERY_ID_MAX_CHARS)
    sender: TelegramSender | None = Field(default=None, alias="from")
    message: TelegramMessage | None = None
    data: str | None = Field(default=None, max_length=TELEGRAM_CALLBACK_DATA_MAX_CHARS)


class TelegramUpdate(_InboundModel):
    """One update envelope limited to the message and callback_query kinds."""

    update_id: int = Field(ge=0)
    message: TelegramMessage | None = None
    callback_query: TelegramCallbackQuery | None = None


class TelegramUpdateResponse(_InboundModel):
    """The bounded ``getUpdates`` envelope."""

    ok: bool
    result: tuple[TelegramUpdate, ...] = Field(
        default_factory=tuple,
        max_length=TELEGRAM_UPDATE_BATCH_MAX,
    )


def parse_update_response(body: bytes) -> tuple[TelegramUpdate, ...]:
    """Return the ordered updates from one bounded ``getUpdates`` response body.

    The raw body is never echoed into the error, so a malformed provider response
    cannot inject provider-controlled text into logs or operator-visible output.
    """

    try:
        response = TelegramUpdateResponse.model_validate_json(body)
    except ValidationError:
        raise TelegramUpdateError("Telegram update response was rejected safely.") from None
    if not response.ok:
        raise TelegramUpdateError("Telegram update response was not successful.")
    return tuple(sorted(response.result, key=lambda update: update.update_id))
