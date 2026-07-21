"""Static checks for least-privilege systemd and secret-free sample configuration."""

from pathlib import Path


def test_systemd_unit_uses_unprivileged_user_journal_group_and_hardening() -> None:
    unit = Path("deploy/systemd/woland-guard-agent.service").read_text(encoding="utf-8")

    assert "User=woland-guard" in unit
    assert "Group=woland-guard" in unit
    assert "SupplementaryGroups=systemd-journal" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/var/lib/woland-guard" in unit
    assert "StateDirectoryMode=0700" in unit
    assert "KillSignal=SIGTERM" in unit
    assert "TimeoutStopSec=30s" in unit
    assert "check-config" in unit


def test_example_yaml_contains_token_path_but_no_plaintext_token() -> None:
    config = Path("deploy/config/agent.example.yaml").read_text(encoding="utf-8")

    assert "token_file: /etc/woland-guard/agent.token" in config
    assert "wgak_" not in config
    assert "source: journald" in config
