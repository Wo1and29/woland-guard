"""The deny guards that must reject an update before any database work happens."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.infrastructure.telegram.updates import TelegramMessage
from woland_guard_control_plane.telegram_bot.router import TelegramCommandRouter, _parse_command

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)


class _ExplodingSessionFactory:
    """Fails the test if a denied update ever reaches PostgreSQL."""

    def begin(self) -> Any:
        raise AssertionError("denied update must not open a database session")

    def __call__(self) -> Any:
        raise AssertionError("denied update must not open a database session")


def _router(*, max_requests: int = 100) -> TelegramCommandRouter:
    return TelegramCommandRouter(
        _ExplodingSessionFactory(),  # type: ignore[arg-type]
        rate_limiter=FixedWindowRateLimiter(max_requests=max_requests, window_seconds=60),
        result_limit=10,
    )


def _message(**overrides: object) -> TelegramMessage:
    payload: dict[str, object] = {
        "message_id": 1,
        "from": {"id": 4242, "is_bot": False},
        "chat": {"id": 4242, "type": "private"},
        "text": "/status",
    }
    payload.update(overrides)
    return TelegramMessage.model_validate(payload)


@pytest.mark.parametrize(
    "overrides",
    [
        {"chat": {"id": -100, "type": "group"}},
        {"chat": {"id": -100, "type": "supergroup"}},
        {"from": {"id": 4242, "is_bot": True}},
        {"text": None},
        {"text": "just a plain sentence"},
        {"text": "/unknown-command-with-dashes"},
        {"text": "/"},
    ],
)
def test_denied_updates_never_reach_the_database(overrides: dict[str, object]) -> None:
    assert _router().handle(_message(**overrides), now=NOW) is None


def test_message_without_sender_is_ignored() -> None:
    payload = {
        "message_id": 1,
        "chat": {"id": 4242, "type": "private"},
        "text": "/status",
    }
    assert _router().handle(TelegramMessage.model_validate(payload), now=NOW) is None


def test_rate_limited_sender_is_ignored_without_a_reply() -> None:
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60)
    router = TelegramCommandRouter(
        _ExplodingSessionFactory(),  # type: ignore[arg-type]
        rate_limiter=limiter,
        result_limit=10,
    )
    assert limiter.consume("4242") is None

    assert router.handle(_message(text="/status"), now=NOW) is None


def test_result_limit_must_fit_one_query_page() -> None:
    limiter = FixedWindowRateLimiter(max_requests=10, window_seconds=60)
    with pytest.raises(ValueError, match="result limit"):
        TelegramCommandRouter(
            _ExplodingSessionFactory(),  # type: ignore[arg-type]
            rate_limiter=limiter,
            result_limit=26,
        )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("/status", "/status"),
        ("  /Status  ", "/status"),
        ("/status@woland_guard_bot", "/status"),
        ("/incidents extra ignored arguments", "/incidents"),
        ("/HELP", "/help"),
    ],
)
def test_command_parsing_is_canonical(text: str, expected: str) -> None:
    assert _parse_command(text) == expected


@pytest.mark.parametrize(
    "text",
    ["", "   ", "status", "/", "/12345", "/with_underscore", "/" + "a" * 40],
)
def test_non_commands_are_rejected(text: str) -> None:
    assert _parse_command(text) is None
