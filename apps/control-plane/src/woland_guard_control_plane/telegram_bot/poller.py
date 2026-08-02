"""Single-consumer long-poll loop with an offset confirmed only after handling."""

from __future__ import annotations

import logging
import signal
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event
from types import FrameType
from typing import Final

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from woland_guard_control_plane.infrastructure.telegram.client import (
    TelegramBotApiClient,
    TelegramTransportError,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramToken,
    TelegramTokenSynchronizer,
)
from woland_guard_control_plane.infrastructure.telegram.updates import (
    TelegramUpdate,
    TelegramUpdateError,
    parse_update_response,
)
from woland_guard_control_plane.telegram_bot.offsets import (
    confirm_next_update_id,
    load_next_update_id,
)
from woland_guard_control_plane.telegram_bot.router import TelegramCommandRouter

logger = logging.getLogger(__name__)

ALLOWED_UPDATE_KINDS: Final = ("message",)
_HTTP_OK: Final = 200


@dataclass(frozen=True, slots=True)
class PollerSettings:
    """Bounded runtime configuration for the inbound consumer."""

    token_file_name: str
    request_timeout_seconds: float
    long_poll_seconds: int
    idle_poll_seconds: float
    batch_limit: int


@dataclass(frozen=True, slots=True)
class PollCycleResult:
    """Counters for one completed cycle; no update content is retained."""

    received: int = 0
    replied: int = 0
    ignored: int = 0


class TelegramBotPoller:
    """Consume inbound updates for exactly one process and reply in the same chat.

    Telegram rejects a second concurrent ``getUpdates`` consumer for the same bot
    token with HTTP 409, so this service must run as a single replica and must not
    be combined with a configured webhook.
    """

    __slots__ = (
        "_client",
        "_clock",
        "_router",
        "_session_factory",
        "_settings",
        "_stop",
        "_synchronizer",
    )

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        client: TelegramBotApiClient,
        synchronizer: TelegramTokenSynchronizer,
        router: TelegramCommandRouter,
        settings: PollerSettings,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._client = client
        self._synchronizer = synchronizer
        self._router = router
        self._settings = settings
        self._clock = clock or (lambda: datetime.now(UTC))
        self._stop = Event()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def request_stop(self) -> None:
        self._stop.set()

    def install_signal_handlers(self) -> None:
        def handle_signal(_signum: int, _frame: FrameType | None) -> None:
            logger.info("telegram_bot_shutdown_requested")
            self.request_stop()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

    def run(self) -> None:
        """Poll until SIGTERM or SIGINT, tolerating transient provider failures."""

        self.install_signal_handlers()
        logger.info("telegram_bot_started")
        try:
            while not self._stop.is_set():
                try:
                    result = self.run_once()
                except (TelegramTransportError, TelegramUpdateError):
                    logger.warning("telegram_bot_poll_failed")
                    self._stop.wait(self._settings.idle_poll_seconds)
                    continue
                except SQLAlchemyError:
                    logger.warning("telegram_bot_database_unavailable")
                    self._stop.wait(self._settings.idle_poll_seconds)
                    continue
                if result.received == 0 and not self._stop.is_set():
                    self._stop.wait(self._settings.idle_poll_seconds)
        finally:
            logger.info("telegram_bot_stopped")

    def run_once(self) -> PollCycleResult:
        """Fetch one bounded batch, handle every update, then confirm the offset."""

        token = self._synchronizer.token_for_delivery(self._settings.token_file_name)
        with self._session_factory() as session:
            offset = load_next_update_id(session)
        response = self._client.get_updates(
            token=token,
            offset=offset,
            limit=self._settings.batch_limit,
            long_poll_seconds=self._settings.long_poll_seconds,
            allowed_updates=ALLOWED_UPDATE_KINDS,
            timeout_seconds=self._settings.request_timeout_seconds,
        )
        if response.status_code != _HTTP_OK:
            raise TelegramTransportError("Telegram update request was rejected safely.")
        updates = parse_update_response(response.body)
        if not updates:
            return PollCycleResult()

        replied = ignored = 0
        for update in updates:
            if self._handle_update(update, token=token):
                replied += 1
            else:
                ignored += 1
        with self._session_factory.begin() as session:
            confirm_next_update_id(session, next_update_id=updates[-1].update_id + 1)
        logger.info(
            "telegram_bot_batch_handled",
            extra={"received": len(updates), "replied": replied},
        )
        return PollCycleResult(received=len(updates), replied=replied, ignored=ignored)

    def _handle_update(self, update: TelegramUpdate, *, token: TelegramToken) -> bool:
        message = update.message
        if message is None:
            return False
        reply = self._router.handle(message, now=self._clock())
        if reply is None:
            return False
        try:
            self._client.send_message(
                token=token,
                chat_id=message.chat.id,
                text=reply,
                timeout_seconds=self._settings.request_timeout_seconds,
            )
        except TelegramTransportError:
            logger.warning("telegram_bot_reply_failed")
            return False
        return True
