from __future__ import annotations

import signal
from pathlib import Path

import pytest
from scripts.demo_e2e.commands import (
    DemoCommandError,
    cooperative_signal_handlers,
    raise_if_shutdown_requested,
    shutdown_requested,
)
from scripts.demo_e2e.contracts import DemoRunIdentity, RecoveryPhase
from scripts.demo_e2e.recovery import RecoveryLedgerStore


@pytest.mark.skipif(not hasattr(signal, "SIGTERM"), reason="SIGTERM is unavailable")
@pytest.mark.parametrize("phase", tuple(RecoveryPhase))
def test_sigterm_only_requests_shutdown_and_preserves_recovery_ledger(
    tmp_path: Path,
    phase: RecoveryPhase,
) -> None:
    identity = DemoRunIdentity.from_run_id("0123456789abcdef")
    directory = tmp_path / phase.value
    directory.mkdir(mode=0o700)
    store = RecoveryLedgerStore.create(directory / "recovery.json", identity)
    store.set_phase(phase)

    with cooperative_signal_handlers():
        signal.raise_signal(signal.SIGTERM)
        signal.raise_signal(signal.SIGTERM)
        assert shutdown_requested()
        with pytest.raises(DemoCommandError, match="shutdown was requested"):
            raise_if_shutdown_requested()
        reopened = RecoveryLedgerStore.open(store.path)
        assert reopened.ledger.phase is phase

    assert not shutdown_requested()
    assert store.path.is_file()
