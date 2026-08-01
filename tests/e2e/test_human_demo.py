from __future__ import annotations

import os
from pathlib import Path

import pytest
from scripts.demo_e2e.human import run_human_demo

pytestmark = [pytest.mark.e2e, pytest.mark.docker, pytest.mark.browser]


@pytest.mark.skipif(
    os.environ.get("WG_RUN_DEMO_E2E") != "1",
    reason="set WG_RUN_DEMO_E2E=1 for the isolated 8B human-demo smoke",
)
def test_human_demo_ready_state_and_noninteractive_cleanup(tmp_path: Path) -> None:
    credential_output = (tmp_path / "operators.json").resolve()

    run_human_demo(
        Path(__file__).resolve().parents[2],
        credential_output=credential_output,
        wait_for_shutdown=lambda _prompt: "",
    )

    assert not credential_output.exists()
