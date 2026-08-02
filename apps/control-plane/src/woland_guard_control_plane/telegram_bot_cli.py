"""Safe local entrypoint for the single inbound Telegram consumer."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from sqlalchemy.exc import SQLAlchemyError

from woland_guard_control_plane.application.rate_limit import FixedWindowRateLimiter
from woland_guard_control_plane.config import Settings, get_settings
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.telegram.client import (
    TelegramBotApiClient,
    TelegramHttpTimeouts,
    TelegramTransportError,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramTokenFileError,
    TelegramTokenSynchronizer,
)
from woland_guard_control_plane.infrastructure.telegram.updates import TelegramUpdateError
from woland_guard_control_plane.telegram_bot.poller import PollerSettings, TelegramBotPoller
from woland_guard_control_plane.telegram_bot.router import (
    IpBlockRuntimeSettings,
    TelegramCommandRouter,
)

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="woland-guard-telegram-bot")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("run", "consume inbound updates until SIGTERM or SIGINT"),
        ("run-once", "consume exactly one bounded batch and exit"),
    ):
        subparser = commands.add_parser(name, help=help_text)
        subparser.add_argument("--token-file-name", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Execute one command with safe, non-reflective error output."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    arguments = build_parser().parse_args(argv)
    settings = get_settings()
    try:
        poller = _build_poller(settings, token_file_name=arguments.token_file_name)
        if arguments.command == "run-once":
            result = poller.run_once()
            print(f"received={result.received} replied={result.replied} ignored={result.ignored}")
            return
        poller.run()
    except (TelegramTokenFileError, TelegramUpdateError, ValueError):
        print("Telegram bot input was rejected by the safe policy.", file=sys.stderr)
        raise SystemExit(2) from None
    except TelegramTransportError:
        print("Telegram bot could not reach the provider safely.", file=sys.stderr)
        raise SystemExit(1) from None
    except SQLAlchemyError:
        print("Telegram bot failed because PostgreSQL is unavailable.", file=sys.stderr)
        raise SystemExit(1) from None


def _build_poller(settings: Settings, *, token_file_name: str) -> TelegramBotPoller:
    session_factory = get_session_factory()
    router = TelegramCommandRouter(
        session_factory,
        rate_limiter=FixedWindowRateLimiter(
            max_requests=settings.telegram_bot_rate_limit_requests,
            window_seconds=settings.telegram_bot_rate_limit_window_seconds,
        ),
        result_limit=settings.telegram_bot_result_limit,
        pending_action_ttl_seconds=settings.telegram_bot_pending_action_ttl_seconds,
        ip_block_settings=IpBlockRuntimeSettings(
            enabled=settings.ip_block_enabled,
            require_second_operator=settings.ip_block_require_second_operator,
            plan_ttl_seconds=settings.ip_block_plan_ttl_seconds,
            nft_table=settings.ip_block_nft_table,
            nft_set_v4=settings.ip_block_nft_set_v4,
            nft_set_v6=settings.ip_block_nft_set_v6,
        ),
    )
    return TelegramBotPoller(
        session_factory=session_factory,
        client=TelegramBotApiClient.production(
            timeouts=TelegramHttpTimeouts(
                connect=settings.telegram_bot_connect_timeout_seconds,
                read=settings.telegram_bot_read_timeout_seconds,
                write=settings.telegram_bot_write_timeout_seconds,
                pool=settings.telegram_bot_pool_timeout_seconds,
            )
        ),
        synchronizer=TelegramTokenSynchronizer(),
        router=router,
        settings=PollerSettings(
            token_file_name=token_file_name,
            request_timeout_seconds=settings.telegram_bot_request_timeout_seconds,
            long_poll_seconds=settings.telegram_bot_long_poll_seconds,
            idle_poll_seconds=settings.telegram_bot_idle_poll_seconds,
            batch_limit=settings.telegram_bot_batch_limit,
        ),
    )
