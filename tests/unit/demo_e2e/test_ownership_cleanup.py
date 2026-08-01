from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from scripts.demo_e2e import ownership as ownership_module
from scripts.demo_e2e.commands import CommandResult, CommandRunner, DemoCommandError
from scripts.demo_e2e.contracts import (
    COMPOSE_PROJECT_LABEL_KEY,
    OWNERSHIP_LABEL_KEY,
    DemoRunIdentity,
    RecoveryResource,
    RecoveryResourceKind,
)
from scripts.demo_e2e.ownership import (
    ComposeDemoEnvironment,
    DemoOwnershipError,
    recover_from_ledger,
)
from scripts.demo_e2e.recovery import RecoveryLedgerStore


def _store(tmp_path: Path) -> RecoveryLedgerStore:
    identity = DemoRunIdentity.from_run_id("0123456789abcdef")
    directory = tmp_path / "ledger"
    directory.mkdir(mode=0o700)
    return RecoveryLedgerStore.create(directory / "recovery.json", identity)


def _environment(
    tmp_path: Path,
    *,
    attempts: int = 3,
) -> ComposeDemoEnvironment:
    (tmp_path / "compose.demo.yaml").write_text("services: {}\n", encoding="utf-8")
    store = _store(tmp_path)
    return ComposeDemoEnvironment(
        project_root=tmp_path,
        identity=store.identity,
        ledger=store,
        runner=_FakeDockerRunner(store),
        recovery_poll_attempts=attempts,
        recovery_poll_seconds=0,
    )


@pytest.mark.parametrize("available_attempt", [2, 3])
def test_failed_start_polling_finds_late_resource_and_enters_exact_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    available_attempt: int,
) -> None:
    environment = _environment(tmp_path, attempts=3)
    resource = _resource(environment.ledger, RecoveryResourceKind.CONTAINER)
    calls = 0
    cleaned: list[bool] = []

    def discover(**_kwargs: object) -> tuple[RecoveryResource, ...]:
        nonlocal calls
        calls += 1
        return (resource,) if calls >= available_attempt else ()

    monkeypatch.setattr(ownership_module, "_discover_exact_project", discover)
    monkeypatch.setattr(
        ownership_module,
        "_cleanup_project",
        lambda **_kwargs: cleaned.append(True),
    )

    environment._recover_after_failed_start()

    assert calls == available_attempt
    assert cleaned == [True]
    assert resource in environment.ledger.ledger.resources


def test_failed_start_without_visible_resource_keeps_ledger_for_later_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = _environment(tmp_path, attempts=2)
    monkeypatch.setattr(ownership_module, "_discover_exact_project", lambda **_kwargs: ())

    with pytest.raises(DemoOwnershipError, match="could not prove"):
        environment._recover_after_failed_start()

    assert environment.ledger.path.exists()


@pytest.mark.parametrize(
    "kind",
    [
        RecoveryResourceKind.CONTAINER,
        RecoveryResourceKind.NETWORK,
        RecoveryResourceKind.VOLUME,
        RecoveryResourceKind.IMAGE,
    ],
)
def test_new_process_recovers_each_exact_resource_kind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: RecoveryResourceKind,
) -> None:
    store = _store(tmp_path)
    resource = _resource(store, kind)
    store.replace_project_resources(store.ledger.main_project_name, (resource,))
    fake = _FakeDockerRunner(store, resources=(resource,))
    monkeypatch.setattr(ownership_module, "CommandRunner", lambda: fake)

    recover_from_ledger(RecoveryLedgerStore.open(store.path))

    assert fake.deleted == [resource]
    assert not store.path.exists()


def test_resource_set_change_and_replaced_exact_id_fail_without_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    recorded = _resource(store, RecoveryResourceKind.CONTAINER, value="a" * 64)
    replacement = _resource(store, RecoveryResourceKind.CONTAINER, value="b" * 64)
    store.replace_project_resources(store.ledger.main_project_name, (recorded,))
    fake = _FakeDockerRunner(store, resources=(replacement,))
    monkeypatch.setattr(ownership_module, "CommandRunner", lambda: fake)

    with pytest.raises(DemoOwnershipError, match="changed"):
        recover_from_ledger(RecoveryLedgerStore.open(store.path))

    assert fake.deleted == []
    assert store.path.exists()


@pytest.mark.parametrize(
    ("project", "owner"),
    [
        ("wg8b-0123456789abcdef", "wg8b-fedcba9876543210"),
        ("wg8b-fedcba9876543210", "wg8b-0123456789abcdef"),
    ],
)
def test_mismatched_project_or_label_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project: str,
    owner: str,
) -> None:
    store = _store(tmp_path)
    resource = _resource(store, RecoveryResourceKind.CONTAINER)
    fake = _FakeDockerRunner(
        store,
        resources=(resource,),
        label_overrides={
            resource.resource_id: {
                COMPOSE_PROJECT_LABEL_KEY: project,
                OWNERSHIP_LABEL_KEY: owner,
            }
        },
    )
    monkeypatch.setattr(ownership_module, "CommandRunner", lambda: fake)

    with pytest.raises(DemoOwnershipError):
        recover_from_ledger(RecoveryLedgerStore.open(store.path))

    assert fake.deleted == []
    assert store.path.exists()


def test_multiple_networks_and_malformed_identity_fail_without_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    first = _resource(store, RecoveryResourceKind.NETWORK, value="a" * 64)
    second = _resource(store, RecoveryResourceKind.NETWORK, value="b" * 64)
    fake = _FakeDockerRunner(store, resources=(first, second))
    monkeypatch.setattr(ownership_module, "CommandRunner", lambda: fake)
    with pytest.raises(DemoOwnershipError, match="ambiguous"):
        recover_from_ledger(RecoveryLedgerStore.open(store.path))
    assert fake.deleted == []

    malformed = _FakeDockerRunner(store, malformed_list=True)
    monkeypatch.setattr(ownership_module, "CommandRunner", lambda: malformed)
    with pytest.raises(DemoOwnershipError, match="malformed"):
        recover_from_ledger(RecoveryLedgerStore.open(store.path))
    assert malformed.deleted == []


def test_deletion_failure_keeps_exact_identity_in_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    resource = _resource(store, RecoveryResourceKind.CONTAINER)
    store.replace_project_resources(store.ledger.main_project_name, (resource,))
    fake = _FakeDockerRunner(store, resources=(resource,), deletion_fails=True)
    monkeypatch.setattr(ownership_module, "CommandRunner", lambda: fake)

    with pytest.raises(DemoOwnershipError, match="deletion failed"):
        recover_from_ledger(RecoveryLedgerStore.open(store.path))

    reopened = RecoveryLedgerStore.open(store.path)
    assert reopened.ledger.resources == (resource,)


def _resource(
    store: RecoveryLedgerStore,
    kind: RecoveryResourceKind,
    *,
    value: str | None = None,
) -> RecoveryResource:
    default = {
        RecoveryResourceKind.CONTAINER: "a" * 64,
        RecoveryResourceKind.NETWORK: "b" * 64,
        RecoveryResourceKind.VOLUME: "wg8b-0123456789abcdef_demo-postgres-data",
        RecoveryResourceKind.IMAGE: "sha256:" + "c" * 64,
    }[kind]
    return RecoveryResource(
        project_name=store.ledger.main_project_name,
        kind=kind,
        resource_id=value or default,
    )


class _FakeDockerRunner(CommandRunner):
    def __init__(
        self,
        store: RecoveryLedgerStore,
        *,
        resources: tuple[RecoveryResource, ...] = (),
        label_overrides: dict[str, dict[str, str]] | None = None,
        malformed_list: bool = False,
        deletion_fails: bool = False,
    ) -> None:
        self.store = store
        self.resources = {resource.resource_id: resource for resource in resources}
        self.label_overrides = label_overrides or {}
        self.malformed_list = malformed_list
        self.deletion_fails = deletion_fails
        self.deleted: list[RecoveryResource] = []

    def run(
        self,
        arguments: Sequence[str],
        **_kwargs: object,
    ) -> CommandResult:
        arguments = list(arguments)
        if self.malformed_list and "--filter" in arguments:
            return CommandResult(returncode=0, stdout=b"../malformed\n")
        if self._is_list(arguments):
            kind = self._list_kind(arguments)
            labels = self._requested_labels(arguments)
            values = [
                resource.resource_id
                for resource in self.resources.values()
                if resource.kind == kind
                and all(self._labels(resource).get(key) == value for key, value in labels.items())
            ]
            return CommandResult(returncode=0, stdout=("\n".join(values)).encode())
        resource_id = arguments[-1]
        resource = self.resources.get(resource_id)
        if self._is_delete(arguments):
            if self.deletion_fails:
                raise DemoCommandError("demo command failed safely")
            if resource is None:
                return CommandResult(returncode=1, stdout=b"")
            self.deleted.append(resource)
            del self.resources[resource_id]
            return CommandResult(returncode=0, stdout=b"")
        if resource is None:
            return CommandResult(returncode=1, stdout=b"")
        labels = self._labels(resource)
        if "{{json .}}" in arguments:
            service = "demo-migrate"
            metadata: dict[str, Any] = {
                "Config": {"Labels": {**labels, "com.docker.compose.service": service}},
                "RepoTags": [f"{resource.project_name}-{service}:latest"],
            }
            return CommandResult(returncode=0, stdout=json.dumps(metadata).encode())
        return CommandResult(returncode=0, stdout=json.dumps(labels).encode())

    def _labels(self, resource: RecoveryResource) -> dict[str, str]:
        labels = self.label_overrides.get(
            resource.resource_id,
            {
                COMPOSE_PROJECT_LABEL_KEY: resource.project_name,
                OWNERSHIP_LABEL_KEY: self.store.ledger.ownership_label,
            },
        )
        if resource.kind == RecoveryResourceKind.IMAGE:
            return {**labels, "com.docker.compose.service": "demo-migrate"}
        return labels

    @staticmethod
    def _is_list(arguments: list[str]) -> bool:
        return "--filter" in arguments and ("ls" in arguments or "ps" in arguments)

    @staticmethod
    def _list_kind(arguments: list[str]) -> RecoveryResourceKind:
        if "image" in arguments:
            return RecoveryResourceKind.IMAGE
        if "network" in arguments:
            return RecoveryResourceKind.NETWORK
        if "volume" in arguments:
            return RecoveryResourceKind.VOLUME
        return RecoveryResourceKind.CONTAINER

    @staticmethod
    def _requested_labels(arguments: list[str]) -> dict[str, str]:
        values: dict[str, str] = {}
        for index, argument in enumerate(arguments):
            if argument != "--filter":
                continue
            _, key, value = arguments[index + 1].split("=", 2)
            values[key] = value
        return values

    @staticmethod
    def _is_delete(arguments: list[str]) -> bool:
        return "rm" in arguments
