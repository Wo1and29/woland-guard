from __future__ import annotations

from pathlib import Path

import pytest
from scripts.demo_e2e import orchestrator as orchestrator_module
from scripts.demo_e2e.contracts import DemoE2EError


class _FoundationFailureEnvironment:
    def __init__(self, *, stop_fails: bool = False) -> None:
        self.stop_fails = stop_fails
        self.stop_calls = 0

    def start_foundation(self) -> None:
        raise DemoE2EError("static foundation failure")

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_fails:
            raise DemoE2EError("static cleanup failure")


def test_orchestrator_always_attempts_exact_cleanup_after_foundation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = _FoundationFailureEnvironment()
    monkeypatch.setattr(
        orchestrator_module,
        "ComposeDemoEnvironment",
        lambda **_kwargs: environment,
    )

    with pytest.raises(DemoE2EError, match="compose_foundation"):
        orchestrator_module.run_automated_verification(tmp_path, source_head="a" * 40)

    assert environment.stop_calls == 1


def test_cleanup_failure_remains_authoritative_and_does_not_reflect_nested_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "synthetic-orchestration-credential-canary"
    environment = _FoundationFailureEnvironment(stop_fails=True)
    monkeypatch.setattr(
        orchestrator_module,
        "ComposeDemoEnvironment",
        lambda **_kwargs: environment,
    )

    with pytest.raises(DemoE2EError, match="cleanup failed") as captured:
        orchestrator_module.run_automated_verification(tmp_path, source_head="a" * 40)

    assert environment.stop_calls == 1
    assert canary not in str(captured.value)
