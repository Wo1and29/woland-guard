"""PostgreSQL-backed Telegram adapter and provider error regressions."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

import pytest

from tests.integration.test_outbox_worker import FixedRandom, MutableClock, _seed_outbox
from tests.support.fake_telegram_bot_api import FakeTelegramBotApiTransport
from woland_guard_control_plane.application.outbox_worker import (
    DeliveryAdapter,
    DeliveryDisposition,
    DeliveryRequest,
    DeliveryResult,
    EqualJitterBackoff,
    OutboxWorker,
)
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    OutboxErrorCode,
    OutboxMessage,
    OutboxStatus,
)
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

pytestmark = pytest.mark.integration


@dataclass(slots=True)
class FixedResultAdapter:
    result: DeliveryResult

    def deliver(
        self,
        _request: DeliveryRequest,
        *,
        timeout_seconds: float,
    ) -> DeliveryResult:
        assert timeout_seconds == 5
        return self.result


def _worker(
    now: datetime,
    adapter: DeliveryAdapter,
    *,
    load_provider_config: bool = False,
) -> OutboxWorker:
    return OutboxWorker(
        session_factory=get_session_factory(),
        adapters={"telegram": adapter},
        configuration_loaders=(
            {"telegram": load_telegram_delivery_configuration} if load_provider_config else None
        ),
        clock=MutableClock(now),
        backoff=EqualJitterBackoff(
            base_seconds=4,
            maximum_seconds=10,
            retry_after_cap_seconds=30,
            random_source=FixedRandom(),
        ),
        lease_seconds=10,
        adapter_timeout_seconds=5,
        poll_seconds=0.01,
        recovery_interval_seconds=5,
    )


@pytest.mark.parametrize(
    "error_code",
    [
        OutboxErrorCode.RETRYABLE_DELIVERY_ERROR,
        OutboxErrorCode.TELEGRAM_STAGING_FILE_MISSING,
        OutboxErrorCode.TELEGRAM_STAGING_FILE_INVALID,
        OutboxErrorCode.TELEGRAM_RUNTIME_COPY_UNAVAILABLE,
        OutboxErrorCode.TELEGRAM_RUNTIME_COPY_INVALID,
        OutboxErrorCode.TELEGRAM_PROTOCOL_ERROR,
    ],
)
def test_worker_persists_exact_retryable_provider_error_code(
    error_code: OutboxErrorCode,
) -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    result = _worker(
        now,
        FixedResultAdapter(DeliveryResult(DeliveryDisposition.RETRYABLE, error_code)),
    ).run_once()

    assert result.deferred == 1
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        assert message.status == OutboxStatus.PENDING.value
        assert message.last_error_code == error_code.value


def test_real_worker_routes_detached_provider_config_to_fake_bot_api(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    with get_session_factory()() as session:
        configuration = load_telegram_delivery_configuration(session, seeded.destination_id)
    assert configuration is not None
    token_file_name = configuration.token_file_name.reveal()
    (staging / token_file_name).write_text("synthetic-integration-token", encoding="ascii")
    fake_api = FakeTelegramBotApiTransport()
    telegram_adapter = TelegramDeliveryAdapter(
        client=TelegramBotApiClient._for_test(
            timeouts=TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1),
            transport=fake_api,
        ),
        synchronizer=TelegramTokenSynchronizer(
            staging_directory=staging,
            runtime_directory=runtime,
            enforce_posix_metadata=False,
        ),
        dashboard_origin="https://localhost:8443",
    )
    worker = _worker(now, telegram_adapter, load_provider_config=True)

    result = worker.run_once()

    assert result.delivered == 1
    assert len(fake_api.requests) == 1
    assert {"chat_id", "text"} <= set(fake_api.requests[0])
    message = fake_api.requests[0]["text"]
    assert isinstance(message, str)
    for forbidden in ("actor", "source_ip", "attributes", "correlation", "payload"):
        assert forbidden not in message.casefold()


def test_staging_canary_is_absent_from_database_and_application_logs(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "synthetic-telegram-token-never-persist"  # noqa: S105
    now = datetime.now(UTC)
    seeded = _seed_outbox(now=now)
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    with get_session_factory()() as session:
        configuration = load_telegram_delivery_configuration(session, seeded.destination_id)
    assert configuration is not None
    (staging / configuration.token_file_name.reveal()).write_text(canary, encoding="ascii")
    adapter = TelegramDeliveryAdapter(
        client=TelegramBotApiClient._for_test(
            timeouts=TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1),
            transport=FakeTelegramBotApiTransport(),
        ),
        synchronizer=TelegramTokenSynchronizer(
            staging_directory=staging,
            runtime_directory=runtime,
            enforce_posix_metadata=False,
        ),
        dashboard_origin="https://localhost:8443",
    )
    worker = _worker(now, adapter, load_provider_config=True)

    with caplog.at_level("DEBUG"):
        assert worker.run_once().delivered == 1

    assert canary not in caplog.text
    with get_session_factory()() as session:
        message = session.get(OutboxMessage, seeded.outbox_id)
        assert message is not None
        database_projection = " ".join(
            (
                str(message.payload),
                str(message.last_error),
                str(message.last_error_code),
                message.idempotency_key,
            )
        )
    assert canary not in database_projection


def test_running_worker_discovers_destination_and_token_without_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    staging = tmp_path / "staging"
    runtime = tmp_path / "runtime"
    staging.mkdir()
    runtime.mkdir()
    token_file_name = "added-after-worker-start.token"  # noqa: S105
    fake_api = FakeTelegramBotApiTransport()
    adapter = TelegramDeliveryAdapter(
        client=TelegramBotApiClient._for_test(
            timeouts=TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1),
            transport=fake_api,
        ),
        synchronizer=TelegramTokenSynchronizer(
            staging_directory=staging,
            runtime_directory=runtime,
            enforce_posix_metadata=False,
        ),
        dashboard_origin="https://localhost:8443",
    )
    worker = _worker(now, adapter, load_provider_config=True)
    startup_recovery_finished = Event()
    original_recover = worker._recover

    def observed_recover(*, now: datetime | None = None) -> tuple[int, int]:
        result = original_recover(now=now)
        startup_recovery_finished.set()
        return result

    monkeypatch.setattr(worker, "install_signal_handlers", lambda: None)
    monkeypatch.setattr(worker, "_recover", observed_recover)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(worker.run)
        assert startup_recovery_finished.wait(timeout=10)
        (staging / token_file_name).write_text(
            "synthetic-added-after-start-token",
            encoding="ascii",
        )
        seeded = _seed_outbox(now=now, token_file_name=token_file_name)
        deadline = datetime.now(UTC).timestamp() + 10
        while datetime.now(UTC).timestamp() < deadline:
            with get_session_factory()() as session:
                message = session.get(OutboxMessage, seeded.outbox_id)
                if message is not None and message.status == OutboxStatus.DELIVERED.value:
                    break
            Event().wait(0.01)
        else:
            raise AssertionError("running worker did not discover the new destination")
        worker.request_stop()
        future.result(timeout=10)

    assert len(fake_api.requests) == 1
