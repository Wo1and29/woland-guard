"""Exact Compose ownership, recovery, lifecycle and random-port verification."""

from __future__ import annotations

import json
import re
import secrets
import time
from pathlib import Path
from typing import Any, Final

from scripts.demo_e2e.commands import CommandResult, CommandRunner, DemoCommandError
from scripts.demo_e2e.contracts import (
    COMPOSE_PROJECT_LABEL_KEY,
    OWNERSHIP_LABEL_KEY,
    DemoDatabaseConfiguration,
    DemoE2EError,
    DemoRunIdentity,
    RecoveryPhase,
    RecoveryResource,
    RecoveryResourceKind,
    SecretValue,
)
from scripts.demo_e2e.recovery import RecoveryLedgerStore, cleanup_recorded_artifacts

CONTAINER_ID: Final = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
RESOURCE_ID: Final = re.compile(r"^[0-9a-f]{12,64}$|^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
BUILD_SERVICES: Final = frozenset({"demo-migrate", "demo-rule-sync", "demo-control-plane"})
RECOVERY_POLL_ATTEMPTS: Final = 10
RECOVERY_POLL_SECONDS: Final = 0.1


class DemoOwnershipError(DemoE2EError):
    """A Compose resource could not be attributed or removed safely."""


class ComposeDemoEnvironment:
    def __init__(
        self,
        *,
        project_root: Path,
        identity: DemoRunIdentity,
        ledger: RecoveryLedgerStore,
        runner: CommandRunner | None = None,
        password: SecretValue | None = None,
        restore: bool = False,
        recovery_poll_attempts: int = RECOVERY_POLL_ATTEMPTS,
        recovery_poll_seconds: float = RECOVERY_POLL_SECONDS,
    ) -> None:
        identity.validate()
        if ledger.identity != identity:
            raise DemoOwnershipError("demo recovery identity does not match the run")
        if recovery_poll_attempts < 1 or recovery_poll_seconds < 0:
            raise DemoOwnershipError("demo recovery polling configuration is invalid")
        self.project_root = project_root.resolve(strict=True)
        self.compose_file = self.project_root / "compose.demo.yaml"
        if not self.compose_file.is_file():
            raise DemoOwnershipError("demo Compose topology is unavailable")
        self.identity = identity
        self.project_name = identity.restore_project_name if restore else identity.project_name
        self._restore = restore
        self._runner = runner or CommandRunner()
        self._password = password or SecretValue(secrets.token_urlsafe(32))
        self._ledger = ledger
        self._started = False
        self._recovery_poll_attempts = recovery_poll_attempts
        self._recovery_poll_seconds = recovery_poll_seconds

    def __repr__(self) -> str:
        return f"ComposeDemoEnvironment(project={self.project_name}, <redacted>)"

    @property
    def ledger(self) -> RecoveryLedgerStore:
        return self._ledger

    @property
    def environment(self) -> dict[str, str]:
        return {
            "COMPOSE_ANSI": "never",
            "WG_DEMO_POSTGRES_PASSWORD": self._password.reveal(),
            "WG_DEMO_OWNERSHIP": self.identity.ownership_label,
        }

    def compose_arguments(self, *arguments: str) -> list[str]:
        self.identity.validate()
        return [
            "docker",
            "compose",
            "-f",
            str(self.compose_file),
            "-p",
            self.project_name,
            *arguments,
        ]

    def validate_topology(self) -> None:
        self._run("config", "--quiet", timeout_seconds=30)

    def start_foundation(self) -> None:
        if self._restore:
            raise DemoOwnershipError("restore environment cannot run the main foundation")
        if self._started:
            raise DemoOwnershipError("demo Compose environment is already running")
        self.validate_topology()
        self._ledger.set_phase(RecoveryPhase.COMPOSE_FOUNDATION)
        phase = "compose_up"
        try:
            self._run(
                "up",
                "-d",
                "--build",
                "demo-postgres",
                "demo-migrate",
                "demo-rule-sync",
                timeout_seconds=600,
                output_limit=8 * 1_048_576,
            )
            self._started = True
            phase = "postgres_readiness"
            self._wait_for_healthy("demo-postgres", timeout_seconds=90)
            phase = "migration_completion"
            self._wait_for_completed("demo-migrate", timeout_seconds=90)
            phase = "rule_sync_completion"
            self._wait_for_completed("demo-rule-sync", timeout_seconds=90)
            phase = "ownership_confirmation"
            self.verify_all_owned_resources()
        except Exception:
            self._recover_after_failed_start()
            raise DemoOwnershipError(f"demo Compose foundation failed during {phase}") from None

    def start_postgres_only(self) -> None:
        if self._started:
            raise DemoOwnershipError("demo Compose environment is already running")
        self.validate_topology()
        self._ledger.set_phase(
            RecoveryPhase.RESTORE if self._restore else RecoveryPhase.COMPOSE_FOUNDATION
        )
        try:
            self._run(
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                "90",
                "demo-postgres",
                timeout_seconds=120,
                output_limit=4 * 1_048_576,
            )
            self._started = True
            self._wait_for_healthy("demo-postgres", timeout_seconds=90)
            self.verify_all_owned_resources()
        except Exception:
            self._recover_after_failed_start()
            raise DemoOwnershipError("demo PostgreSQL environment failed to start") from None

    def verify_schema(self) -> None:
        current = self._run(
            "run",
            "--rm",
            "--no-deps",
            "demo-migrate",
            "alembic",
            "-c",
            "alembic.ini",
            "current",
            timeout_seconds=60,
        ).text()
        if "20260728_0009" not in current:
            raise DemoOwnershipError("demo database is not at the expected migration head")
        self._run(
            "run",
            "--rm",
            "--no-deps",
            "demo-migrate",
            "alembic",
            "-c",
            "alembic.ini",
            "check",
            timeout_seconds=60,
        )

    def start_control_plane(self) -> str:
        self._require_started()
        self._ledger.set_phase(RecoveryPhase.CONTROL_PLANE)
        self._run(
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            "90",
            "demo-control-plane",
            timeout_seconds=120,
            output_limit=4 * 1_048_576,
        )
        self.verify_all_owned_resources()
        port = self.published_port("demo-control-plane", "8000/tcp")
        return f"http://127.0.0.1:{port}"

    def stop_control_plane(self) -> None:
        self._require_started()
        try:
            container_id = self._service_container_id("demo-control-plane")
        except DemoOwnershipError:
            return
        self._confirm_resource(
            RecoveryResource(
                project_name=self.project_name,
                kind=RecoveryResourceKind.CONTAINER,
                resource_id=container_id,
            )
        )
        self._run(
            "stop",
            "--timeout",
            "15",
            "demo-control-plane",
            timeout_seconds=30,
            respect_shutdown=False,
        )

    def database_configuration(self) -> DemoDatabaseConfiguration:
        self._require_started()
        return DemoDatabaseConfiguration(
            host="127.0.0.1",
            port=self.published_port("demo-postgres", "5432/tcp"),
            database="wg_demo",
            username="wg_demo",
            password=self._password,
        )

    def service_container_id(self, service: str) -> str:
        if service not in {
            "demo-postgres",
            "demo-migrate",
            "demo-rule-sync",
            "demo-control-plane",
        }:
            raise DemoOwnershipError("demo service identity request is invalid")
        container_id = self._service_container_id(service)
        self._confirm_resource(
            RecoveryResource(
                project_name=self.project_name,
                kind=RecoveryResourceKind.CONTAINER,
                resource_id=container_id,
            )
        )
        return container_id

    def published_port(self, service: str, container_port: str) -> int:
        if service not in {"demo-postgres", "demo-control-plane"}:
            raise DemoOwnershipError("demo published-port service is invalid")
        if container_port not in {"5432/tcp", "8000/tcp"}:
            raise DemoOwnershipError("demo container port is invalid")
        container_id = self.service_container_id(service)
        raw = self._runner.run(
            ["docker", "inspect", "--format", "{{json .}}", container_id],
            cwd=self.project_root,
            timeout_seconds=15,
            output_limit=1_048_576,
        ).text()
        try:
            metadata = json.loads(raw)
            requested = metadata["HostConfig"]["PortBindings"][container_port]
            bindings = metadata["NetworkSettings"]["Ports"][container_port]
        except (KeyError, TypeError, json.JSONDecodeError):
            raise DemoOwnershipError("demo runtime port mapping is unavailable") from None
        if (
            not isinstance(requested, list)
            or len(requested) != 1
            or requested != [{"HostIp": "127.0.0.1", "HostPort": ""}]
        ):
            raise DemoOwnershipError("demo random port request is invalid")
        if (
            not isinstance(bindings, list)
            or len(bindings) != 1
            or not isinstance(bindings[0], dict)
        ):
            raise DemoOwnershipError("demo runtime port mapping is ambiguous")
        host_ip = bindings[0].get("HostIp")
        host_port = bindings[0].get("HostPort")
        if host_ip != "127.0.0.1" or type(host_port) is not str or not host_port.isascii():
            raise DemoOwnershipError("demo runtime port is not loopback-only")
        try:
            port = int(host_port)
        except ValueError:
            raise DemoOwnershipError("demo runtime port is invalid") from None
        if not 1 <= port <= 65_535:
            raise DemoOwnershipError("demo runtime port is invalid")
        return port

    def stop(self) -> None:
        self._ledger.set_phase(RecoveryPhase.CLEANUP)
        _cleanup_project(
            store=self._ledger,
            project_name=self.project_name,
            runner=self._runner,
            cwd=self.project_root,
            allow_initial_discovery=True,
        )
        self._started = False

    def verify_all_owned_resources(self) -> None:
        resources = _discover_exact_project(
            store=self._ledger,
            project_name=self.project_name,
            runner=self._runner,
            cwd=self.project_root,
        )
        if not resources:
            raise DemoOwnershipError("demo Compose project has no attributable resources")
        self._ledger.replace_project_resources(self.project_name, resources)

    def _recover_after_failed_start(self) -> None:
        self._ledger.set_phase(RecoveryPhase.CLEANUP)
        found = False
        for attempt in range(self._recovery_poll_attempts):
            resources = _discover_exact_project(
                store=self._ledger,
                project_name=self.project_name,
                runner=self._runner,
                cwd=self.project_root,
            )
            if resources:
                found = True
                self._ledger.replace_project_resources(self.project_name, resources)
                break
            if attempt + 1 < self._recovery_poll_attempts:
                time.sleep(self._recovery_poll_seconds)
        if not found:
            self._started = False
            raise DemoOwnershipError(
                "demo recovery could not prove that Docker created no resources"
            )
        _cleanup_project(
            store=self._ledger,
            project_name=self.project_name,
            runner=self._runner,
            cwd=self.project_root,
            allow_initial_discovery=False,
        )
        self._started = False

    def _service_container_id(self, service: str) -> str:
        output = (
            self._run("ps", "--all", "--quiet", service, timeout_seconds=15).text().splitlines()
        )
        values = [value.strip() for value in output if value.strip()]
        if len(values) != 1 or CONTAINER_ID.fullmatch(values[0]) is None:
            raise DemoOwnershipError("demo service container identity is unavailable")
        return str(values[0])

    def _wait_for_healthy(self, service: str, *, timeout_seconds: float) -> None:
        container_id = self._service_container_id(service)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            state = self._container_state(container_id)
            if state == ("running", "healthy", 0):
                return
            if state[0] in {"dead", "exited"}:
                break
            time.sleep(0.25)
        raise DemoOwnershipError("demo service readiness deadline expired")

    def _wait_for_completed(self, service: str, *, timeout_seconds: float) -> None:
        deadline = time.monotonic() + timeout_seconds
        container_id: str | None = None
        while time.monotonic() < deadline:
            try:
                container_id = self._service_container_id(service)
            except DemoOwnershipError:
                time.sleep(0.25)
                continue
            state = self._container_state(container_id)
            if state[0] == "exited":
                if state[2] == 0:
                    return
                break
            if state[0] == "dead":
                break
            time.sleep(0.25)
        raise DemoOwnershipError("demo one-shot service did not complete successfully")

    def _container_state(self, container_id: str) -> tuple[str, str, int]:
        resource = RecoveryResource(
            project_name=self.project_name,
            kind=RecoveryResourceKind.CONTAINER,
            resource_id=container_id,
        )
        self._confirm_resource(resource)
        raw = self._runner.run(
            ["docker", "inspect", "--format", "{{json .State}}", container_id],
            cwd=self.project_root,
            timeout_seconds=15,
        ).text()
        try:
            state = json.loads(raw)
            status = state["Status"]
            health = state.get("Health", {}).get("Status", "")
            exit_code = state.get("ExitCode", 0)
        except (KeyError, TypeError, json.JSONDecodeError):
            raise DemoOwnershipError("demo container state is invalid") from None
        if type(status) is not str or type(health) is not str or type(exit_code) is not int:
            raise DemoOwnershipError("demo container state is invalid")
        return status, health, exit_code

    def _confirm_resource(self, resource: RecoveryResource) -> None:
        _confirm_resource(resource, self.identity.ownership_label, self._runner, self.project_root)

    def _run(
        self,
        *arguments: str,
        timeout_seconds: float,
        output_limit: int = 1_048_576,
        respect_shutdown: bool = True,
    ) -> CommandResult:
        return self._runner.run(
            self.compose_arguments(*arguments),
            cwd=self.project_root,
            environment=self.environment,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            respect_shutdown=respect_shutdown,
        )

    def _require_started(self) -> None:
        if not self._started:
            raise DemoOwnershipError("demo Compose environment is not running")


def recover_from_ledger(store: RecoveryLedgerStore) -> None:
    """Resume exact cleanup in a new process using only validated ledger identity."""

    runner = CommandRunner()
    cwd = store.path.parent
    store.set_phase(RecoveryPhase.CLEANUP)
    for project_name in (store.ledger.restore_project_name, store.ledger.main_project_name):
        _cleanup_project(
            store=store,
            project_name=project_name,
            runner=runner,
            cwd=cwd,
            allow_initial_discovery=True,
        )
    cleanup_recorded_artifacts(store)
    store.finish()


def _cleanup_project(
    *,
    store: RecoveryLedgerStore,
    project_name: str,
    runner: CommandRunner,
    cwd: Path,
    allow_initial_discovery: bool,
) -> None:
    discovered = _discover_exact_project(
        store=store,
        project_name=project_name,
        runner=runner,
        cwd=cwd,
    )
    recorded = tuple(
        resource for resource in store.ledger.resources if resource.project_name == project_name
    )
    if not recorded and discovered and allow_initial_discovery:
        store.replace_project_resources(project_name, discovered)
        recorded = discovered
    elif set(discovered) - set(recorded):
        raise DemoOwnershipError("demo resource set changed before exact cleanup")
    for missing in sorted(set(recorded) - set(discovered), key=_deletion_key):
        _confirm_absent(missing, runner, cwd)
        store.remove_resource(missing)
    for resource in sorted(
        (item for item in store.ledger.resources if item.project_name == project_name),
        key=_deletion_key,
    ):
        current = _discover_exact_project(
            store=store,
            project_name=project_name,
            runner=runner,
            cwd=cwd,
        )
        expected = tuple(
            item for item in store.ledger.resources if item.project_name == project_name
        )
        if set(current) != set(expected):
            raise DemoOwnershipError("demo resource set changed before exact deletion")
        _confirm_resource(resource, store.ledger.ownership_label, runner, cwd)
        _delete_exact(resource, runner, cwd)
        _confirm_absent(resource, runner, cwd)
        store.remove_resource(resource)
    if _discover_exact_project(
        store=store,
        project_name=project_name,
        runner=runner,
        cwd=cwd,
    ):
        raise DemoOwnershipError("demo cleanup could not confirm exact project absence")


def _discover_exact_project(
    *,
    store: RecoveryLedgerStore,
    project_name: str,
    runner: CommandRunner,
    cwd: Path,
) -> tuple[RecoveryResource, ...]:
    if project_name not in {store.ledger.main_project_name, store.ledger.restore_project_name}:
        raise DemoOwnershipError("demo cleanup project is invalid")
    project_resources = _listed_resources(runner, cwd, ((COMPOSE_PROJECT_LABEL_KEY, project_name),))
    exact_resources = _listed_resources(
        runner,
        cwd,
        (
            (COMPOSE_PROJECT_LABEL_KEY, project_name),
            (OWNERSHIP_LABEL_KEY, store.ledger.ownership_label),
        ),
    )
    project_images = _listed_images(runner, cwd, ((COMPOSE_PROJECT_LABEL_KEY, project_name),))
    exact_images = _listed_images(
        runner,
        cwd,
        (
            (COMPOSE_PROJECT_LABEL_KEY, project_name),
            (OWNERSHIP_LABEL_KEY, store.ledger.ownership_label),
        ),
    )
    if set(project_resources) != set(exact_resources) or set(project_images) != set(exact_images):
        raise DemoOwnershipError("demo project contains mismatched ownership metadata")
    owned_resources = _listed_resources(
        runner, cwd, ((OWNERSHIP_LABEL_KEY, store.ledger.ownership_label),)
    )
    owned_images = _listed_images(
        runner, cwd, ((OWNERSHIP_LABEL_KEY, store.ledger.ownership_label),)
    )
    resources = tuple(
        RecoveryResource(project_name=project_name, kind=kind, resource_id=resource_id)
        for kind, resource_id in exact_resources
    ) + tuple(
        RecoveryResource(
            project_name=project_name,
            kind=RecoveryResourceKind.IMAGE,
            resource_id=image_id,
        )
        for image_id in exact_images
    )
    if len(resources) != len(set(resources)):
        raise DemoOwnershipError("demo resource discovery is ambiguous")
    counts = {
        kind: sum(resource.kind == kind for resource in resources) for kind in RecoveryResourceKind
    }
    if (
        counts[RecoveryResourceKind.CONTAINER] > 4
        or counts[RecoveryResourceKind.NETWORK] > 1
        or counts[RecoveryResourceKind.VOLUME] > 1
        or counts[RecoveryResourceKind.IMAGE] > len(BUILD_SERVICES)
    ):
        raise DemoOwnershipError("demo resource discovery is ambiguous")
    for resource in resources:
        _confirm_resource(resource, store.ledger.ownership_label, runner, cwd)
    allowed_projects = {store.ledger.main_project_name, store.ledger.restore_project_name}
    for kind, resource_id in (
        *owned_resources,
        *[(RecoveryResourceKind.IMAGE, i) for i in owned_images],
    ):
        owner_project = _resource_project(kind, resource_id, runner, cwd)
        if owner_project not in allowed_projects:
            raise DemoOwnershipError("demo ownership label is attached to a foreign project")
    return tuple(sorted(resources, key=_resource_key))


def _listed_resources(
    runner: CommandRunner,
    cwd: Path,
    labels: tuple[tuple[str, str], ...],
) -> list[tuple[RecoveryResourceKind, str]]:
    outputs: list[tuple[RecoveryResourceKind, list[str]]] = []
    commands = {
        RecoveryResourceKind.CONTAINER: ["docker", "ps", "-aq", "--no-trunc"],
        RecoveryResourceKind.NETWORK: ["docker", "network", "ls", "-q", "--no-trunc"],
        RecoveryResourceKind.VOLUME: ["docker", "volume", "ls", "-q"],
    }
    for kind, command in commands.items():
        arguments = [*command]
        for key, value in labels:
            arguments.extend(("--filter", f"label={key}={value}"))
        outputs.append((kind, _docker_lines(runner, cwd, arguments)))
    values = [(kind, resource) for kind, resources in outputs for resource in resources]
    if len(values) != len(set(values)):
        raise DemoOwnershipError("demo resource discovery returned duplicate identities")
    return values


def _listed_images(
    runner: CommandRunner,
    cwd: Path,
    labels: tuple[tuple[str, str], ...],
) -> list[str]:
    arguments = ["docker", "image", "ls", "--no-trunc", "--quiet"]
    for key, value in labels:
        arguments.extend(("--filter", f"label={key}={value}"))
    values = _docker_lines(runner, cwd, arguments)
    if len(values) != len(set(values)):
        raise DemoOwnershipError("demo image discovery returned duplicate identities")
    return values


def _confirm_resource(
    resource: RecoveryResource,
    ownership_label: str,
    runner: CommandRunner,
    cwd: Path,
) -> None:
    labels = _resource_labels(resource.kind, resource.resource_id, runner, cwd)
    if (
        labels.get(COMPOSE_PROJECT_LABEL_KEY) != resource.project_name
        or labels.get(OWNERSHIP_LABEL_KEY) != ownership_label
    ):
        raise DemoOwnershipError("demo resource ownership could not be confirmed")
    if resource.kind == RecoveryResourceKind.IMAGE:
        metadata = _inspect_json(
            runner,
            cwd,
            ["docker", "image", "inspect", "--format", "{{json .}}", resource.resource_id],
        )
        service = labels.get("com.docker.compose.service")
        repo_tags = metadata.get("RepoTags")
        if (
            type(service) is not str
            or service not in BUILD_SERVICES
            or repo_tags != [f"{resource.project_name}-{service}:latest"]
        ):
            raise DemoOwnershipError("demo image ownership could not be confirmed")


def _resource_project(
    kind: RecoveryResourceKind,
    resource_id: str,
    runner: CommandRunner,
    cwd: Path,
) -> str:
    labels = _resource_labels(kind, resource_id, runner, cwd)
    project = labels.get(COMPOSE_PROJECT_LABEL_KEY)
    if type(project) is not str:
        raise DemoOwnershipError("demo resource project metadata is invalid")
    return project


def _resource_labels(
    kind: RecoveryResourceKind,
    resource_id: str,
    runner: CommandRunner,
    cwd: Path,
) -> dict[str, str]:
    command = {
        RecoveryResourceKind.CONTAINER: [
            "docker",
            "inspect",
            "--format",
            "{{json .Config.Labels}}",
        ],
        RecoveryResourceKind.NETWORK: [
            "docker",
            "network",
            "inspect",
            "--format",
            "{{json .Labels}}",
        ],
        RecoveryResourceKind.VOLUME: [
            "docker",
            "volume",
            "inspect",
            "--format",
            "{{json .Labels}}",
        ],
        RecoveryResourceKind.IMAGE: [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{json .Config.Labels}}",
        ],
    }[kind]
    raw = runner.run(
        [*command, resource_id],
        cwd=cwd,
        timeout_seconds=15,
        respect_shutdown=False,
    ).text()
    try:
        labels = json.loads(raw)
    except json.JSONDecodeError:
        raise DemoOwnershipError("demo resource metadata is invalid") from None
    if not isinstance(labels, dict) or any(
        type(key) is not str or type(value) is not str for key, value in labels.items()
    ):
        raise DemoOwnershipError("demo resource metadata is invalid")
    return labels


def _delete_exact(resource: RecoveryResource, runner: CommandRunner, cwd: Path) -> None:
    command = {
        RecoveryResourceKind.CONTAINER: ["docker", "container", "rm", "--force"],
        RecoveryResourceKind.NETWORK: ["docker", "network", "rm"],
        RecoveryResourceKind.VOLUME: ["docker", "volume", "rm"],
        RecoveryResourceKind.IMAGE: ["docker", "image", "rm"],
    }[resource.kind]
    try:
        runner.run(
            [*command, resource.resource_id],
            cwd=cwd,
            timeout_seconds=120,
            output_limit=1_048_576,
            respect_shutdown=False,
        )
    except DemoCommandError:
        raise DemoOwnershipError("demo exact resource deletion failed") from None


def _confirm_absent(resource: RecoveryResource, runner: CommandRunner, cwd: Path) -> None:
    command = {
        RecoveryResourceKind.CONTAINER: ["docker", "inspect"],
        RecoveryResourceKind.NETWORK: ["docker", "network", "inspect"],
        RecoveryResourceKind.VOLUME: ["docker", "volume", "inspect"],
        RecoveryResourceKind.IMAGE: ["docker", "image", "inspect"],
    }[resource.kind]
    result = runner.run(
        [*command, resource.resource_id],
        cwd=cwd,
        timeout_seconds=15,
        check=False,
        output_limit=1_048_576,
        respect_shutdown=False,
    )
    if result.returncode == 0:
        raise DemoOwnershipError("demo exact resource absence could not be confirmed")


def _inspect_json(
    runner: CommandRunner,
    cwd: Path,
    arguments: list[str],
) -> dict[str, Any]:
    raw = runner.run(
        arguments,
        cwd=cwd,
        timeout_seconds=15,
        output_limit=1_048_576,
        respect_shutdown=False,
    ).text()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise DemoOwnershipError("demo Docker metadata is invalid") from None
    if not isinstance(value, dict):
        raise DemoOwnershipError("demo Docker metadata is invalid")
    return value


def _docker_lines(runner: CommandRunner, cwd: Path, arguments: list[str]) -> list[str]:
    text = runner.run(
        arguments,
        cwd=cwd,
        timeout_seconds=20,
        respect_shutdown=False,
    ).text()
    values = [line.strip() for line in text.splitlines() if line.strip()]
    if any(
        RESOURCE_ID.fullmatch(value) is None and IMAGE_ID.fullmatch(value) is None
        for value in values
    ):
        raise DemoOwnershipError("demo Docker identity output is malformed")
    return values


def _deletion_key(resource: RecoveryResource) -> tuple[int, str]:
    order = {
        RecoveryResourceKind.CONTAINER: 0,
        RecoveryResourceKind.NETWORK: 1,
        RecoveryResourceKind.VOLUME: 2,
        RecoveryResourceKind.IMAGE: 3,
    }
    return order[resource.kind], resource.resource_id


def _resource_key(resource: RecoveryResource) -> tuple[str, str, str]:
    return resource.project_name, resource.kind.value, resource.resource_id
