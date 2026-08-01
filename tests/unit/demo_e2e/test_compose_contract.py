from __future__ import annotations

from pathlib import Path

import yaml


def test_demo_compose_is_closed_and_uses_loopback_random_ports() -> None:
    project_root = Path(__file__).resolve().parents[3]
    topology = yaml.safe_load((project_root / "compose.demo.yaml").read_text(encoding="utf-8"))
    services = topology["services"]

    assert set(services) == {
        "demo-postgres",
        "demo-migrate",
        "demo-rule-sync",
        "demo-control-plane",
    }
    assert services["demo-postgres"]["ports"] == ["127.0.0.1::5432"]
    assert services["demo-control-plane"]["ports"] == ["127.0.0.1::8000"]
    assert set(topology["networks"]) == {"demo-backend"}
    assert set(topology["volumes"]) == {"demo-postgres-data"}
    serialized = (project_root / "compose.demo.yaml").read_text(encoding="utf-8")
    assert "docker.sock" not in serialized
    assert "/var/log/journal" not in serialized
    assert "privileged:" not in serialized
    assert "network_mode: host" not in serialized
    for name in ("demo-migrate", "demo-rule-sync", "demo-control-plane"):
        service = services[name]
        assert "com.woland_guard.demo_owner" in service["build"]["labels"]
        assert service["user"] == "10001:10001"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["restart"] == "no"
