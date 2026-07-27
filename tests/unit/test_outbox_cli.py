"""Unit tests for non-reflective outbox CLI failures."""

from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from woland_guard_control_plane import outbox_cli
from woland_guard_control_plane.application.outbox_worker import (
    OutboxOperationError,
    QueueStatistics,
)
from woland_guard_control_plane.config import Settings


class FakeSessionFactory:
    @contextmanager
    def __call__(self) -> Iterator[Session]:
        yield Mock(spec=Session)

    @contextmanager
    def begin(self) -> Iterator[Session]:
        yield Mock(spec=Session)


def test_cli_does_not_reflect_application_error_or_canary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "synthetic-cli-secret-canary"
    monkeypatch.setattr(outbox_cli, "get_settings", Settings)
    monkeypatch.setattr(outbox_cli, "get_session_factory", FakeSessionFactory)

    def reject(*_args: object, **_kwargs: object) -> None:
        raise OutboxOperationError(canary)

    monkeypatch.setattr(outbox_cli, "requeue_failed_message", reject)
    identifier = "11111111-2222-4333-8444-555555555555"

    with pytest.raises(SystemExit) as captured:
        outbox_cli.main(
            [
                "requeue-failed",
                identifier,
                "--confirm",
                identifier,
            ]
        )

    output = capsys.readouterr()
    assert captured.value.code == 2
    assert canary not in output.out
    assert canary not in output.err
    assert "payload" not in output.err.casefold()


@pytest.mark.parametrize(
    "oldest_age",
    [None, 12.5],
)
def test_status_prints_safe_oldest_pending_age(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    oldest_age: float | None,
) -> None:
    monkeypatch.setattr(outbox_cli, "get_settings", Settings)
    monkeypatch.setattr(outbox_cli, "get_session_factory", FakeSessionFactory)
    monkeypatch.setattr(
        outbox_cli,
        "queue_statistics",
        lambda _session, *, now: QueueStatistics(1, 0, 0, 0, 1, 0, oldest_age),
    )

    outbox_cli.main(["status"])

    output = capsys.readouterr().out
    expected = "null" if oldest_age is None else str(oldest_age)
    assert f"oldest_pending_age_seconds={expected}" in output
    assert "payload" not in output.casefold()
    assert "last_error" not in output.casefold()
    assert "destination" not in output.casefold()


def test_settings_validate_recovery_interval_bounds_and_relationship() -> None:
    assert Settings().outbox_recovery_interval_seconds == 30
    with pytest.raises(ValidationError):
        Settings(outbox_recovery_interval_seconds=0)
    with pytest.raises(ValidationError):
        Settings(outbox_lease_seconds=60, outbox_recovery_interval_seconds=61)


def test_settings_require_telegram_phase_timeouts_to_fit_adapter_budget() -> None:
    settings = Settings(
        outbox_adapter_timeout_seconds=10,
        outbox_lease_seconds=11,
        outbox_recovery_interval_seconds=5,
        telegram_connect_timeout_seconds=2,
        telegram_read_timeout_seconds=3,
        telegram_write_timeout_seconds=2,
        telegram_pool_timeout_seconds=1,
    )
    assert settings.telegram_read_timeout_seconds == 3
    with pytest.raises(ValidationError):
        Settings(
            outbox_adapter_timeout_seconds=10,
            outbox_lease_seconds=11,
            outbox_recovery_interval_seconds=5,
            telegram_connect_timeout_seconds=3,
            telegram_read_timeout_seconds=3,
            telegram_write_timeout_seconds=3,
            telegram_pool_timeout_seconds=2,
        )
