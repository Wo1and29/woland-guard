"""Safe local lifecycle and operations CLI for the transactional outbox worker."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from woland_guard_control_plane.application.outbox_worker import (
    DeliveryAdapter,
    EqualJitterBackoff,
    OutboxOperationError,
    OutboxWorker,
    queue_statistics,
    recover_expired_claims,
    requeue_failed_message,
)
from woland_guard_control_plane.config import Settings, get_settings
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import NotificationAdapterKind
from woland_guard_control_plane.infrastructure.telegram.adapter import (
    TelegramDeliveryAdapter,
    load_telegram_delivery_configuration,
)
from woland_guard_control_plane.infrastructure.telegram.client import (
    TelegramBotApiClient,
    TelegramHttpTimeouts,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramTokenSynchronizer,
)

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="woland-guard-outbox")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="run the worker until SIGTERM or SIGINT")
    run_once = commands.add_parser("run-once", help="process a bounded number of due rows")
    run_once.add_argument("--limit", type=int, choices=range(1, 101), default=1)
    commands.add_parser("status", help="show safe aggregate queue statistics")
    commands.add_parser("recover-expired", help="recover expired processing leases")
    requeue = commands.add_parser("requeue-failed", help="requeue one confirmed failed row")
    requeue.add_argument("outbox_id", type=UUID)
    requeue.add_argument("--confirm", type=UUID, required=True)
    requeue.add_argument("--additional-attempts", type=int, choices=range(1, 6), default=1)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Execute one command with safe, non-reflective error output."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    arguments = build_parser().parse_args(argv)
    settings = get_settings()
    try:
        if arguments.command == "status":
            with get_session_factory()() as session:
                stats = queue_statistics(session, now=datetime.now(UTC))
            print(
                " ".join(
                    (
                        f"pending={stats.pending}",
                        f"processing={stats.processing}",
                        f"delivered={stats.delivered}",
                        f"failed={stats.failed}",
                        f"ready={stats.ready}",
                        f"expired={stats.expired}",
                        "oldest_pending_age_seconds="
                        + (
                            "null"
                            if stats.oldest_pending_age_seconds is None
                            else str(stats.oldest_pending_age_seconds)
                        ),
                    )
                )
            )
            return
        if arguments.command == "recover-expired":
            with get_session_factory().begin() as session:
                recovered, failed = recover_expired_claims(session, now=datetime.now(UTC))
            print(f"recovered={recovered} failed={failed}")
            return
        if arguments.command == "requeue-failed":
            with get_session_factory().begin() as session:
                message = requeue_failed_message(
                    session,
                    outbox_id=arguments.outbox_id,
                    confirmation=arguments.confirm,
                    additional_attempts=arguments.additional_attempts,
                    now=datetime.now(UTC),
                )
            print(
                f"outbox_id={message.id} status={message.status} "
                f"attempt_count={message.attempt_count} max_attempts={message.max_attempts}"
            )
            return

        worker = _build_worker(settings)
        if arguments.command == "run-once":
            result = worker.run_once(limit=arguments.limit)
            print(
                f"processed={result.processed} delivered={result.delivered} "
                f"deferred={result.deferred} failed={result.failed} "
                f"lease_lost={result.lease_lost}"
            )
            return
        worker.run()
    except (OutboxOperationError, ValueError):
        print("Outbox operation was rejected by the safe application policy.", file=sys.stderr)
        raise SystemExit(2) from None
    except SQLAlchemyError:
        print("Outbox operation failed because PostgreSQL is unavailable.", file=sys.stderr)
        raise SystemExit(1) from None


def _build_worker(settings: Settings) -> OutboxWorker:
    telegram_kind = NotificationAdapterKind.TELEGRAM.value
    adapters: dict[str, DeliveryAdapter] = {
        telegram_kind: TelegramDeliveryAdapter(
            client=TelegramBotApiClient.production(
                timeouts=TelegramHttpTimeouts(
                    connect=settings.telegram_connect_timeout_seconds,
                    read=settings.telegram_read_timeout_seconds,
                    write=settings.telegram_write_timeout_seconds,
                    pool=settings.telegram_pool_timeout_seconds,
                )
            ),
            synchronizer=TelegramTokenSynchronizer(),
            dashboard_origin=settings.web_public_origin,
            language=settings.telegram_notification_language,
        )
    }
    return OutboxWorker(
        session_factory=get_session_factory(),
        adapters=adapters,
        configuration_loaders={telegram_kind: load_telegram_delivery_configuration},
        backoff=EqualJitterBackoff(
            base_seconds=settings.outbox_backoff_base_seconds,
            maximum_seconds=settings.outbox_backoff_max_seconds,
            retry_after_cap_seconds=settings.outbox_retry_after_cap_seconds,
        ),
        lease_seconds=settings.outbox_lease_seconds,
        adapter_timeout_seconds=settings.outbox_adapter_timeout_seconds,
        poll_seconds=settings.outbox_poll_seconds,
        recovery_interval_seconds=settings.outbox_recovery_interval_seconds,
    )
