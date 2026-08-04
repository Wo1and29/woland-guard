"""Agent lifecycle coordinating source collection and durable delivery."""

from __future__ import annotations

import logging
import signal
from collections.abc import Iterator
from dataclasses import dataclass
from threading import Event, Thread
from types import FrameType

from woland_guard_agent.delivery import DeliveryManager, DeliveryOutcome, close_transport
from woland_guard_agent.normalization import normalize_record
from woland_guard_agent.sources import (
    JournalRecord,
    JournalSource,
    SourceCursorUnavailableError,
    SourceUnavailableError,
)
from woland_guard_agent.spool import (
    EnqueueResult,
    SpoolFullError,
    SpoolStatistics,
    SQLiteSpool,
)

logger = logging.getLogger(__name__)


class AgentRuntimeError(RuntimeError):
    """A safe fatal runtime error suitable for systemd restart handling."""


@dataclass(frozen=True, slots=True)
class RunOnceResult:
    collected: int
    duplicates: int
    skipped: int
    delivery: DeliveryOutcome


class AgentService:
    """Run collection and delivery concurrently with a shared stop signal."""

    def __init__(
        self,
        *,
        source: JournalSource,
        spool: SQLiteSpool,
        delivery: DeliveryManager,
        delivery_poll_seconds: float,
    ) -> None:
        self._source = source
        self._spool = spool
        self._delivery = delivery
        self._delivery_poll_seconds = delivery_poll_seconds
        self._stop = Event()
        self._collector: Thread | None = None
        self._collector_failed = False

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def request_stop(self) -> None:
        self._stop.set()

    def statistics(self) -> SpoolStatistics:
        return self._spool.statistics()

    def close(self) -> None:
        self.request_stop()
        close_transport(self._delivery.transport)

    def install_signal_handlers(self) -> None:
        """Translate SIGTERM/SIGINT into cooperative shutdown without queue deletion."""

        def handle_signal(_signum: int, _frame: FrameType | None) -> None:
            logger.info("shutdown_requested")
            self.request_stop()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

    def run(self) -> None:
        self._spool.initialize()
        self.install_signal_handlers()
        self._collector = Thread(target=self._collector_entrypoint, name="source-reader")
        self._collector.start()
        logger.info("agent_started source=%s", self._source.name)
        try:
            while not self._stop.is_set():
                outcome = self._delivery.deliver_once()
                self._log_delivery(outcome)
                self._stop.wait(self._delivery_poll_seconds)
        finally:
            self._stop.set()
            if self._collector is not None:
                self._collector.join(timeout=5)
            self.close()
            logger.info("agent_stopped")
        if self._collector_failed:
            raise AgentRuntimeError("source collector failed")

    def run_once(self, *, source_limit: int = 100) -> RunOnceResult:
        """Collect a bounded snapshot and make one delivery attempt for diagnostics."""

        self._spool.initialize()
        collected = 0
        duplicates = 0
        skipped = 0
        cursor = self._spool.cursor(self._source.name)
        try:
            for record in self._source.backlog(
                after_cursor=cursor,
                stop_event=self._stop,
                initial_limit=source_limit,
            ):
                result = self._persist_record(record)
                if result is None:
                    skipped += 1
                elif result is EnqueueResult.INSERTED:
                    collected += 1
                else:
                    duplicates += 1
        except SourceCursorUnavailableError:
            self._record_journal_gap()
        delivery = self._delivery.deliver_once()
        self._log_delivery(delivery)
        return RunOnceResult(
            collected=collected,
            duplicates=duplicates,
            skipped=skipped,
            delivery=delivery,
        )

    def _collect_forever(self) -> None:
        while not self._stop.is_set():
            if self._spool.statistics().total >= self._spool_capacity():
                logger.warning("spool_full collection_paused=true")
                self._stop.wait(self._delivery_poll_seconds)
                continue

            try:
                self._collect_cycle()
            except SourceCursorUnavailableError:
                self._record_journal_gap()
            except SourceUnavailableError:
                logger.error("source_unavailable source=%s", self._source.name)
                self._stop.wait(self._delivery_poll_seconds)

    def _collect_cycle(self) -> None:
        cursor = self._spool.cursor(self._source.name)
        self._drain(
            self._source.backlog(
                after_cursor=cursor,
                stop_event=self._stop,
                initial_limit=None,
            )
        )
        cursor = self._spool.cursor(self._source.name)
        self._drain(
            self._source.follow(
                after_cursor=cursor,
                stop_event=self._stop,
            )
        )

    def _drain(self, records: Iterator[JournalRecord]) -> None:
        for record in records:
            if self._stop.is_set():
                break
            try:
                result = self._persist_record(record)
            except SpoolFullError:
                logger.warning("spool_full cursor_advanced=false")
                break
            if result is None:
                logger.info("journal_record_skipped cursor_advanced=true")
            else:
                logger.info("journal_record_stored result=%s", result.value)

    def _persist_record(self, record: JournalRecord) -> EnqueueResult | None:
        event = normalize_record(record, source=self._source.event_source)
        if event is None:
            self._spool.advance_cursor(
                source_name=self._source.name,
                cursor=record.cursor,
            )
            return None
        return self._spool.enqueue_with_cursor(
            source_name=self._source.name,
            cursor=record.cursor,
            event=event,
        )

    def _record_journal_gap(self) -> None:
        self._spool.record_diagnostic("journal_gap")
        self._spool.clear_cursor(self._source.name)
        logger.error(
            "source_cursor_gap source=%s diagnostic=journal_gap rebase=explicit",
            self._source.name,
        )

    def _collector_entrypoint(self) -> None:
        try:
            self._collect_forever()
        except Exception:
            self._collector_failed = True
            logger.error("source_collector_failed source=%s", self._source.name)
            self._stop.set()

    def _log_delivery(self, outcome: DeliveryOutcome) -> None:
        if outcome.action.value == "idle":
            return
        logger.info(
            "delivery action=%s request_id=%s events=%d accepted=%d existing=%d",
            outcome.action.value,
            outcome.request_id,
            outcome.event_count,
            outcome.accepted,
            outcome.existing,
        )

    def _spool_capacity(self) -> int:
        return self._spool.max_events
