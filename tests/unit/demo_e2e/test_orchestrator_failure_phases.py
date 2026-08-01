from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import pytest
from scripts.demo_e2e import orchestrator as orchestrator_module
from scripts.demo_e2e.browser import BrowserWorkflowEvidence
from scripts.demo_e2e.contracts import DemoDatabaseConfiguration, DemoE2EError, SecretValue
from scripts.demo_e2e.fake_delivery import DemoDeliveryEvidence
from scripts.demo_e2e.pipeline import PipelineSnapshot

ZERO_SNAPSHOT = PipelineSnapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


@dataclass
class _Engine:
    dispose_calls: int = 0

    def dispose(self) -> None:
        self.dispose_calls += 1


@dataclass
class _Environment:
    stop_calls: int = 0

    def start_foundation(self) -> None:
        return None

    def verify_schema(self) -> None:
        return None

    def database_configuration(self) -> DemoDatabaseConfiguration:
        return DemoDatabaseConfiguration(
            host="127.0.0.1",
            port=54321,
            database="wg_demo",
            username="wg_demo",
            password=SecretValue("synthetic-database-credential"),
        )

    def start_control_plane(self) -> str:
        return "http://127.0.0.1:54322"

    def stop_control_plane(self) -> None:
        return None

    def stop(self) -> None:
        self.stop_calls += 1


@dataclass
class _Provisioning:
    agent_token: SecretValue = field(
        default_factory=lambda: SecretValue("synthetic-agent-credential"),
        repr=False,
    )
    secrets: tuple[str, ...] = ()


@dataclass
class _Backup:
    path: Path
    cleanup_calls: int = 0

    def cleanup(self) -> None:
        self.cleanup_calls += 1


@pytest.mark.parametrize(
    ("failure_phase", "expected_phase"),
    [
        ("initial_ingestion", "initial_ingestion"),
        ("outbox_delivery", "outbox_delivery"),
        ("browser_workflow", "browser_workflow"),
        ("backup", "backup"),
        ("restore_verification", "restore_verification"),
    ],
)
def test_phase_failure_disposes_resources_and_runs_exact_compose_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
    expected_phase: str,
) -> None:
    environment = _Environment()
    engine = _Engine()
    provisioning = _Provisioning()
    backup = _Backup(path=tmp_path / "wg8b-backup-static" / "synthetic.dump")
    monkeypatch.setattr(
        orchestrator_module,
        "ComposeDemoEnvironment",
        lambda **_kwargs: environment,
    )
    monkeypatch.setattr(
        orchestrator_module,
        "create_session_factory",
        lambda _database: (object(), engine),
    )
    monkeypatch.setattr(orchestrator_module, "verify_exact_rules", lambda *_args: None)
    monkeypatch.setattr(orchestrator_module, "provision_demo", lambda *_args: provisioning)
    monkeypatch.setattr(orchestrator_module, "build_all_manifests", tuple)
    monkeypatch.setattr(
        orchestrator_module, "_materialize_manifests", lambda value, **_kwargs: value
    )
    monkeypatch.setattr(orchestrator_module, "verify_ingestion", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orchestrator_module, "database_snapshot", lambda *_args: ZERO_SNAPSHOT)
    monkeypatch.setattr(
        orchestrator_module,
        "database_schema_fingerprint",
        lambda *_args: object(),
    )
    monkeypatch.setattr(
        orchestrator_module, "verify_replay", lambda *_args, **_kwargs: ZERO_SNAPSHOT
    )
    monkeypatch.setattr(
        orchestrator_module,
        "send_manifests",
        lambda **_kwargs: _raise_if(failure_phase, "initial_ingestion", ()),
    )
    monkeypatch.setattr(
        orchestrator_module,
        "deliver_outbox",
        lambda *_args, **_kwargs: _raise_if(
            failure_phase,
            "outbox_delivery",
            DemoDeliveryEvidence(request_count=0),
        ),
    )
    monkeypatch.setattr(
        orchestrator_module,
        "run_browser_workflow",
        lambda **_kwargs: _raise_if(
            failure_phase,
            "browser_workflow",
            BrowserWorkflowEvidence(UUID(int=1), 1, 1, 1, 1),
        ),
    )
    monkeypatch.setattr(
        orchestrator_module,
        "create_backup",
        lambda *_args, **_kwargs: _raise_if(failure_phase, "backup", backup),
    )

    def restore(**_kwargs: object) -> None:
        _raise_if(failure_phase, "restore_verification", None)

    monkeypatch.setattr(orchestrator_module, "restore_and_verify", restore)

    with pytest.raises(DemoE2EError, match=expected_phase):
        orchestrator_module.run_automated_verification(tmp_path, source_head="a" * 40)

    assert environment.stop_calls == 1
    assert engine.dispose_calls == 1
    assert backup.cleanup_calls == (1 if failure_phase == "restore_verification" else 0)


def _raise_if[T](selected: str, current: str, result: T) -> T:
    if selected == current:
        raise DemoE2EError("static injected phase failure")
    return result
