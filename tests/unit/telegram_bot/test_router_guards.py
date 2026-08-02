"""The deny guards that must reject an update before any database work happens.

9B widens the boundary compared to 9A: any private, non-bot, non-empty-text
message now opens a database session (to check a pending reason prompt), not
only recognized commands. Only the structural guards below (bot sender,
non-private chat, missing text, missing sender, rate limit) still short-circuit
before the database -- see ADR-0014.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.infrastructure.telegram.updates import (
    TelegramCallbackQuery,
    TelegramMessage,
)
from woland_guard_control_plane.telegram_bot.router import (
    IpBlockRuntimeSettings,
    TelegramCommandRouter,
    _parse_command,
)

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
_PENDING_ACTION_TTL_SECONDS = 300
_IP_BLOCK_SETTINGS = IpBlockRuntimeSettings(
    enabled=False,
    require_second_operator=True,
    plan_ttl_seconds=3_600,
    nft_table="woland_guard",
    nft_set_v4="blocked_v4",
    nft_set_v6="blocked_v6",
)


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
        pending_action_ttl_seconds=_PENDING_ACTION_TTL_SECONDS,
        ip_block_settings=_IP_BLOCK_SETTINGS,
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


def _callback_query(**overrides: object) -> TelegramCallbackQuery:
    payload: dict[str, object] = {
        "id": "callback-1",
        "from": {"id": 4242, "is_bot": False},
        "data": "1:iv:11111111-1111-4111-8111-111111111111:1",
    }
    payload.update(overrides)
    return TelegramCallbackQuery.model_validate(payload)


@pytest.mark.parametrize(
    "overrides",
    [
        {"chat": {"id": -100, "type": "group"}},
        {"chat": {"id": -100, "type": "supergroup"}},
        {"from": {"id": 4242, "is_bot": True}},
        {"text": None},
    ],
)
def test_structurally_rejected_messages_never_reach_the_database(
    overrides: dict[str, object],
) -> None:
    assert _router().handle(_message(**overrides), now=NOW, update_id=1) is None


def test_message_without_sender_is_ignored() -> None:
    payload = {
        "message_id": 1,
        "chat": {"id": 4242, "type": "private"},
        "text": "/status",
    }
    assert _router().handle(TelegramMessage.model_validate(payload), now=NOW, update_id=1) is None


def test_rate_limited_sender_is_ignored_without_a_reply() -> None:
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60)
    router = TelegramCommandRouter(
        _ExplodingSessionFactory(),  # type: ignore[arg-type]
        rate_limiter=limiter,
        result_limit=10,
        pending_action_ttl_seconds=_PENDING_ACTION_TTL_SECONDS,
        ip_block_settings=_IP_BLOCK_SETTINGS,
    )
    assert limiter.consume("4242") is None

    assert router.handle(_message(text="/status"), now=NOW, update_id=1) is None


def test_result_limit_must_fit_one_query_page() -> None:
    limiter = FixedWindowRateLimiter(max_requests=10, window_seconds=60)
    with pytest.raises(ValueError, match="result limit"):
        TelegramCommandRouter(
            _ExplodingSessionFactory(),  # type: ignore[arg-type]
            rate_limiter=limiter,
            result_limit=26,
            pending_action_ttl_seconds=_PENDING_ACTION_TTL_SECONDS,
            ip_block_settings=_IP_BLOCK_SETTINGS,
        )


def test_pending_action_ttl_must_be_positive() -> None:
    limiter = FixedWindowRateLimiter(max_requests=10, window_seconds=60)
    with pytest.raises(ValueError, match="TTL"):
        TelegramCommandRouter(
            _ExplodingSessionFactory(),  # type: ignore[arg-type]
            rate_limiter=limiter,
            result_limit=10,
            pending_action_ttl_seconds=0,
            ip_block_settings=_IP_BLOCK_SETTINGS,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"from": {"id": 4242, "is_bot": True}},
        {"data": None},
    ],
)
def test_structurally_rejected_callback_queries_never_reach_the_database(
    overrides: dict[str, object],
) -> None:
    answer = _router().handle_callback_query(_callback_query(**overrides), now=NOW)
    assert answer.show_alert is True


@pytest.mark.parametrize(
    "data",
    [
        "not-the-right-shape",
        "2:iv:11111111-1111-4111-8111-111111111111:1",  # unknown schema version
        "1:xx:11111111-1111-4111-8111-111111111111:1",  # unknown action code
        "1:iv:not-a-uuid:1",
        "1:iv:11111111-1111-4111-8111-111111111111:0",  # zero version
        "1:iv:11111111-1111-4111-8111-111111111111:abc",
    ],
)
def test_malformed_callback_data_never_reaches_the_database(data: str) -> None:
    answer = _router().handle_callback_query(_callback_query(data=data), now=NOW)
    assert answer.show_alert is True


def test_callback_query_without_sender_is_rejected_before_the_database() -> None:
    payload = {
        "id": "callback-1",
        "data": "1:iv:11111111-1111-4111-8111-111111111111:1",
    }
    answer = _router().handle_callback_query(TelegramCallbackQuery.model_validate(payload), now=NOW)
    assert answer.show_alert is True


def test_rate_limited_callback_sender_still_gets_an_answer() -> None:
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60)
    router = TelegramCommandRouter(
        _ExplodingSessionFactory(),  # type: ignore[arg-type]
        rate_limiter=limiter,
        result_limit=10,
        pending_action_ttl_seconds=_PENDING_ACTION_TTL_SECONDS,
        ip_block_settings=_IP_BLOCK_SETTINGS,
    )
    assert limiter.consume("4242") is None

    answer = router.handle_callback_query(_callback_query(), now=NOW)
    assert answer.show_alert is True


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
