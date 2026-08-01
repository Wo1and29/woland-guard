from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from scripts.demo_e2e.contracts import DemoRunIdentity, SecretValue
from scripts.demo_e2e.human import HumanDemoError, write_human_credentials
from scripts.demo_e2e.pipeline import (
    HUMAN_DEMO_SCENARIO_IDS,
    DemoOperatorCredential,
    DemoProvisioning,
    PipelineExpectations,
    build_human_manifests,
)

from woland_guard_control_plane.infrastructure.database.models import OperatorRole


def _provisioning() -> DemoProvisioning:
    identity = DemoRunIdentity.from_run_id("0123456789abcdef")

    def operator(role: OperatorRole) -> DemoOperatorCredential:
        return DemoOperatorCredential(
            operator_id=uuid4(),
            username=f"demo-{role.value}-{identity.run_id[:8]}",
            role=role,
            token=SecretValue(f"synthetic-{role.value}-credential"),
        )

    return DemoProvisioning(
        server_id=uuid4(),
        agent_token=SecretValue("synthetic-agent-credential"),
        analyst=operator(OperatorRole.ANALYST),
        admin=operator(OperatorRole.ADMIN),
        viewer=operator(OperatorRole.VIEWER),
        destination_id=uuid4(),
        telegram_token=SecretValue("synthetic-telegram-credential"),
    )


def test_human_profile_is_catalog_bound_and_compact() -> None:
    manifests = build_human_manifests()
    expectations = PipelineExpectations.from_manifests(manifests)

    assert tuple(manifest.scenario_id for manifest in manifests) == HUMAN_DEMO_SCENARIO_IDS
    assert len(manifests) == 1
    assert expectations.event_count > 0
    assert expectations.outbox_count > 0


def test_human_credentials_use_explicit_new_file_and_are_removed(tmp_path: Path) -> None:
    output = (tmp_path / "operators.json").resolve()
    provisioning = _provisioning()

    credential_file = write_human_credentials(
        output,
        origin="https://127.0.0.1:8443",
        provisioning=provisioning,
    )
    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["dashboard_origin"] == "https://127.0.0.1:8443"
    assert data["analyst"]["operator_api_key"] == provisioning.analyst.token.reveal()
    assert "credential" not in repr(credential_file)
    if os.name == "posix":
        assert output.stat().st_mode & 0o077 == 0
    credential_file.cleanup()
    assert not output.exists()


def test_human_credentials_refuse_overwrite_and_relative_output(tmp_path: Path) -> None:
    existing = tmp_path / "operators.json"
    existing.write_text("preserve", encoding="utf-8")
    provisioning = _provisioning()

    with pytest.raises(HumanDemoError):
        write_human_credentials(
            existing.resolve(),
            origin="https://127.0.0.1:8443",
            provisioning=provisioning,
        )
    with pytest.raises(HumanDemoError):
        write_human_credentials(
            Path("relative.json"),
            origin="https://127.0.0.1:8443",
            provisioning=provisioning,
        )

    assert existing.read_text(encoding="utf-8") == "preserve"


def test_human_credentials_do_not_delete_file_created_during_open_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = (tmp_path / "operators.json").resolve()
    provisioning = _provisioning()
    real_open = os.open

    def raced_open(path: object, flags: int, mode: int = 0o777) -> int:
        assert isinstance(path, str | bytes | os.PathLike)
        descriptor = real_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        os.write(descriptor, b"foreign")
        os.close(descriptor)
        raise FileExistsError

    monkeypatch.setattr(os, "open", raced_open)

    with pytest.raises(HumanDemoError):
        write_human_credentials(
            output,
            origin="https://127.0.0.1:8443",
            provisioning=provisioning,
        )

    assert output.read_bytes() == b"foreign"
