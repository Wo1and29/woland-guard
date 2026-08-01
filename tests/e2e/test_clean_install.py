from __future__ import annotations

import os
from pathlib import Path

import pytest
from scripts.demo_e2e.clean_install import verify_clean_install

pytestmark = [pytest.mark.e2e, pytest.mark.docker, pytest.mark.browser]


@pytest.mark.skipif(
    os.environ.get("WG_RUN_CLEAN_INSTALL") != "1",
    reason="set WG_RUN_CLEAN_INSTALL=1 after the candidate commit exists in git archive HEAD",
)
def test_tracked_only_clean_install_release_gate() -> None:
    project_root = Path(__file__).resolve().parents[2]
    summary = verify_clean_install(project_root)

    assert summary.startswith("8B verification passed:")
    assert "scenarios=32" in summary
