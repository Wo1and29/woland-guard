"""Command-line interface for service, configuration checks and one-shot diagnostics."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

from woland_guard_agent.config import (
    AgentConfigurationError,
    AgentSettings,
    SecretToken,
    load_agent_settings,
    load_secret_token,
)
from woland_guard_agent.delivery import BackoffPolicy, DeliveryManager
from woland_guard_agent.logging import configure_logging
from woland_guard_agent.platform_support import UnsupportedPlatformError, require_ubuntu_2404
from woland_guard_agent.service import AgentRuntimeError, AgentService
from woland_guard_agent.sources import JournaldSource, JournalSource, SyslogFileSource
from woland_guard_agent.spool import SpoolSecurityError, SQLiteSpool
from woland_guard_agent.transport import IngestionTransport

logger = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    configure_logging("INFO")
    try:
        settings = load_agent_settings(arguments.config)
        configure_logging(settings.log_level)
        if arguments.command.startswith("spool-"):
            return _run_spool_command(arguments, settings=settings)

        token = load_secret_token(settings.http.token_file)
        if arguments.command == "check-config":
            logger.info("configuration_valid")
            return 0

        require_ubuntu_2404()
        service = _build_service(settings, token=token)
        if arguments.command == "run-once":
            try:
                result = service.run_once(source_limit=arguments.source_limit)
                statistics = service.statistics()
                logger.info(
                    "diagnostic_complete collected=%d duplicates=%d skipped=%d pending=%d "
                    "quarantined=%d oversized=%d",
                    result.collected,
                    result.duplicates,
                    result.skipped,
                    statistics.pending,
                    statistics.quarantined,
                    statistics.oversized,
                )
            finally:
                service.close()
            return 0
        service.run()
        return 0
    except (AgentConfigurationError, SpoolSecurityError, UnsupportedPlatformError) as error:
        logger.error("startup_rejected reason=%s", error)
        return 2
    except AgentRuntimeError:
        logger.error("agent_runtime_failed")
        return 1


def _build_service(settings: AgentSettings, *, token: SecretToken) -> AgentService:
    spool = SQLiteSpool(settings.spool.path, max_events=settings.spool.max_events)
    transport = IngestionTransport(
        base_url=str(settings.http.base_url),
        token=token,
        connect_timeout_seconds=settings.http.connect_timeout_seconds,
        read_timeout_seconds=settings.http.read_timeout_seconds,
    )
    delivery = DeliveryManager(
        spool=spool,
        transport=transport,
        configured_batch_size=settings.http.batch_size,
        backoff=BackoffPolicy(
            base_seconds=settings.retry.base_seconds,
            maximum_seconds=settings.retry.maximum_seconds,
        ),
        authentication_retry_seconds=settings.retry.authentication_seconds,
    )
    return AgentService(
        source=_build_source(settings),
        spool=spool,
        delivery=delivery,
        delivery_poll_seconds=settings.delivery_poll_seconds,
    )


def _build_source(settings: AgentSettings) -> JournalSource:
    """Construct the one source the validated configuration selected."""

    if settings.source == "syslog_file":
        if settings.syslog_file is None:  # pragma: no cover - the validator forbids this
            raise AgentConfigurationError("syslog_file settings are missing")
        return SyslogFileSource(settings.syslog_file.path)
    return JournaldSource()


def _run_spool_command(arguments: argparse.Namespace, *, settings: AgentSettings) -> int:
    spool = SQLiteSpool(settings.spool.path, max_events=settings.spool.max_events)
    spool.initialize()
    if arguments.command == "spool-status":
        statistics = spool.statistics()
        logger.info(
            "spool_status pending=%d quarantined=%d oversized=%d diagnostics=%d",
            statistics.pending,
            statistics.quarantined,
            statistics.oversized,
            statistics.diagnostics,
        )
        for diagnostic in spool.diagnostics():
            logger.warning(
                "spool_diagnostic code=%s occurrences=%d",
                diagnostic.code,
                diagnostic.occurrences,
            )
        return 0

    if arguments.command == "spool-list":
        for event in spool.list_events(status=arguments.status, limit=arguments.limit):
            logger.info(
                "spool_event event_id=%s status=%s attempts=%d last_error=%s",
                event.event_id,
                event.status,
                event.attempts,
                event.last_error or "none",
            )
        return 0

    if arguments.command == "spool-requeue":
        changed = spool.requeue(arguments.event_id)
        logger.info("spool_requeue event_id=%s changed=%s", arguments.event_id, changed)
        return 0 if changed else 3

    if arguments.confirm != str(arguments.event_id):
        logger.error("spool_delete_rejected confirmation_mismatch=true")
        return 4
    changed = spool.delete(arguments.event_id)
    logger.info("spool_delete event_id=%s changed=%s", arguments.event_id, changed)
    return 0 if changed else 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="woland-guard-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("check-config", "run"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--config", type=Path, required=True)
    run_once = subparsers.add_parser("run-once")
    run_once.add_argument("--config", type=Path, required=True)
    run_once.add_argument("--source-limit", type=int, default=100, choices=range(1, 1_001))
    spool_status = subparsers.add_parser("spool-status")
    spool_status.add_argument("--config", type=Path, required=True)
    spool_list = subparsers.add_parser("spool-list")
    spool_list.add_argument("--config", type=Path, required=True)
    spool_list.add_argument(
        "--status",
        choices=("pending", "quarantined", "oversized"),
        required=True,
    )
    spool_list.add_argument("--limit", type=int, default=100, choices=range(1, 1_001))
    spool_requeue = subparsers.add_parser("spool-requeue")
    spool_requeue.add_argument("--config", type=Path, required=True)
    spool_requeue.add_argument("event_id", type=UUID)
    spool_delete = subparsers.add_parser("spool-delete")
    spool_delete.add_argument("--config", type=Path, required=True)
    spool_delete.add_argument("event_id", type=UUID)
    spool_delete.add_argument("--confirm", required=True)
    return parser
