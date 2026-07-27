"""Static Compose isolation regressions for outbound Telegram secrets."""

from pathlib import Path
from typing import Any, cast

import yaml

COMPOSE_PATH = Path(__file__).parents[2] / "compose.yaml"
STAGING_TARGET = "/run/woland-guard-staging/telegram"
RUNTIME_TARGET = "/run/secrets/woland-guard/telegram"


def _services() -> dict[str, dict[str, Any]]:
    document = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    return cast(dict[str, dict[str, Any]], document["services"])


def _volume_targets(service: dict[str, Any]) -> set[str]:
    targets: set[str] = set()
    for volume in service.get("volumes", []):
        if isinstance(volume, dict):
            targets.add(str(volume["target"]))
        elif isinstance(volume, str):
            targets.add(volume.split(":", maxsplit=1)[0])
    for mount in service.get("tmpfs", []):
        targets.add(str(mount).split(":", maxsplit=1)[0])
    return targets


def _assert_hardened(service: dict[str, Any]) -> None:
    assert service["user"] == "10001:10001"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]


def test_control_plane_has_no_telegram_secret_mounts() -> None:
    service = _services()["control-plane"]
    targets = _volume_targets(service)
    assert STAGING_TARGET not in targets
    assert RUNTIME_TARGET not in targets
    serialized = str(service.get("environment", {})).casefold()
    assert "telegram_bot_token" not in serialized
    assert "telegram_chat" not in serialized


def test_telegram_admin_has_only_read_only_staging_and_is_one_shot() -> None:
    service = _services()["telegram-admin"]
    _assert_hardened(service)
    targets = _volume_targets(service)
    assert STAGING_TARGET in targets
    assert RUNTIME_TARGET not in targets
    staging = next(volume for volume in service["volumes"] if volume["target"] == STAGING_TARGET)
    assert staging["read_only"] is True
    assert service["profiles"] == ["telegram-notifications"]
    assert service["restart"] == "no"
    assert "ports" not in service


def test_outbox_worker_has_read_only_staging_and_private_runtime_tmpfs() -> None:
    service = _services()["outbox-worker"]
    _assert_hardened(service)
    targets = _volume_targets(service)
    assert STAGING_TARGET in targets
    assert RUNTIME_TARGET in targets
    staging = next(volume for volume in service["volumes"] if volume["target"] == STAGING_TARGET)
    assert staging["read_only"] is True
    runtime_mount = next(
        mount for mount in service["tmpfs"] if str(mount).startswith(RUNTIME_TARGET)
    )
    assert "uid=10001" in runtime_mount
    assert "gid=10001" in runtime_mount
    assert "mode=0700" in runtime_mount
    assert service["profiles"] == ["telegram-notifications"]


def test_no_service_receives_telegram_token_or_chat_id_through_environment() -> None:
    for service in _services().values():
        environment = str(service.get("environment", {})).casefold()
        assert "bot_token" not in environment
        assert "chat_id" not in environment
