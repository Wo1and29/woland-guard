from __future__ import annotations

import os
from pathlib import Path

import pytest
from scripts.demo_e2e.commands import CommandRunner
from scripts.demo_e2e.orchestrator import run_automated_verification

pytestmark = [pytest.mark.e2e, pytest.mark.docker, pytest.mark.browser]


@pytest.mark.skipif(
    os.environ.get("WG_RUN_DEMO_E2E") != "1",
    reason="set WG_RUN_DEMO_E2E=1 for the isolated 8B release gate",
)
def test_full_demo_browser_backup_and_restore() -> None:
    project_root = Path(__file__).resolve().parents[2]
    source_head = (
        CommandRunner()
        .run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            timeout_seconds=15,
        )
        .text()
        .strip()
    )
    result = run_automated_verification(
        project_root,
        source_head=source_head,
    )

    assert result.source_head == source_head
    assert result.scenario_count == 32
    assert result.accepted_events == result.replayed_events
    assert result.delivered_notifications == result.final_snapshot.outbox
    assert result.final_snapshot.delivered == result.final_snapshot.outbox
    assert result.final_snapshot.failed == 0
    assert result.final_snapshot.pending == 0
    assert result.final_snapshot.processing == 0
    assert result.final_snapshot.comments == 1
    assert result.final_snapshot.active_sessions == 0
