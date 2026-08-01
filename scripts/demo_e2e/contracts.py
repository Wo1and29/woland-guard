"""Closed, redacted contracts shared by the 8B orchestration layers."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

RUN_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{16}$")
PROJECT_PATTERN: Final = re.compile(r"^wg8b-[0-9a-f]{16}(?:-restore)?$")
OWNERSHIP_PATTERN: Final = re.compile(r"^wg8b-[0-9a-f]{16}$")
OWNERSHIP_LABEL_KEY: Final = "com.woland_guard.demo_owner"
COMPOSE_PROJECT_LABEL_KEY: Final = "com.docker.compose.project"
EXPECTED_HEAD_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")
CONTAINER_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
DOCKER_OBJECT_ID_PATTERN: Final = re.compile(r"^(?:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$")


class DemoE2EError(RuntimeError):
    """Safe orchestration failure that never embeds a nested exception."""


class SecretValue:
    """Short-lived plaintext available only at an explicit consumer boundary."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if type(value) is not str or not value:
            raise DemoE2EError("demo credential material is invalid")
        self.__value = value

    def reveal(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


class RecoveryPhase(StrEnum):
    CREATED = "created"
    COMPOSE_FOUNDATION = "compose_foundation"
    SCHEMA_VERIFICATION = "schema_verification"
    RULE_VERIFICATION = "rule_verification"
    PROVISIONING = "provisioning"
    CONTROL_PLANE = "control_plane"
    MANIFESTS = "manifests"
    INGESTION = "ingestion"
    OUTBOX = "outbox"
    BROWSER = "browser"
    REPLAY = "replay"
    BACKUP = "backup"
    RESTORE = "restore"
    CLEANUP = "cleanup"


class RecoveryResourceKind(StrEnum):
    CONTAINER = "container"
    NETWORK = "network"
    VOLUME = "volume"
    IMAGE = "image"


class RecoveryArtifactKind(StrEnum):
    CHECKOUT = "checkout"
    MANIFESTS = "manifests"
    BACKUP = "backup"
    TLS = "tls"
    ENVIRONMENT = "environment"
    CREDENTIALS = "credentials"
    BROWSER = "browser"


class RecoveryResource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    project_name: str
    kind: RecoveryResourceKind
    resource_id: str

    @field_validator("project_name")
    @classmethod
    def _project_is_closed(cls, value: str) -> str:
        if PROJECT_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid recovery project")
        return value

    @model_validator(mode="after")
    def _identity_is_closed(self) -> RecoveryResource:
        pattern = {
            RecoveryResourceKind.CONTAINER: CONTAINER_ID_PATTERN,
            RecoveryResourceKind.IMAGE: IMAGE_ID_PATTERN,
            RecoveryResourceKind.NETWORK: DOCKER_OBJECT_ID_PATTERN,
            RecoveryResourceKind.VOLUME: DOCKER_OBJECT_ID_PATTERN,
        }[self.kind]
        if pattern.fullmatch(self.resource_id) is None:
            raise ValueError("invalid recovery resource identity")
        return self


class RecoveryArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: RecoveryArtifactKind
    path: str

    @field_validator("path")
    @classmethod
    def _path_is_closed(cls, value: str) -> str:
        if (
            not 1 <= len(value) <= 1_024
            or "\x00" in value
            or any(ord(character) < 32 for character in value)
            or not Path(value).is_absolute()
        ):
            raise ValueError("invalid recovery artifact path")
        return value


class RecoveryLedger(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1]
    run_id: str
    main_project_name: str
    restore_project_name: str
    ownership_label: str
    phase: RecoveryPhase
    expected_resource_categories: tuple[RecoveryResourceKind, ...]
    resources: tuple[RecoveryResource, ...]
    artifacts: tuple[RecoveryArtifact, ...]

    @model_validator(mode="after")
    def _ledger_is_self_consistent(self) -> RecoveryLedger:
        identity = DemoRunIdentity.from_run_id(self.run_id)
        if (
            self.main_project_name != identity.project_name
            or self.restore_project_name != identity.restore_project_name
            or self.ownership_label != identity.ownership_label
            or self.expected_resource_categories != tuple(RecoveryResourceKind)
            or any(
                resource.project_name not in {self.main_project_name, self.restore_project_name}
                for resource in self.resources
            )
            or tuple(sorted(self.resources, key=_resource_sort_key)) != self.resources
            or len(set(self.resources)) != len(self.resources)
            or tuple(sorted(self.artifacts, key=_artifact_sort_key)) != self.artifacts
            or len(set(self.artifacts)) != len(self.artifacts)
        ):
            raise ValueError("invalid recovery ledger")
        return self

    @classmethod
    def create(cls, identity: DemoRunIdentity) -> RecoveryLedger:
        identity.validate()
        return cls(
            schema_version=1,
            run_id=identity.run_id,
            main_project_name=identity.project_name,
            restore_project_name=identity.restore_project_name,
            ownership_label=identity.ownership_label,
            phase=RecoveryPhase.CREATED,
            expected_resource_categories=tuple(RecoveryResourceKind),
            resources=(),
            artifacts=(),
        )


def _resource_sort_key(resource: RecoveryResource) -> tuple[str, str, str]:
    return resource.project_name, resource.kind.value, resource.resource_id


def _artifact_sort_key(artifact: RecoveryArtifact) -> tuple[str, str]:
    return artifact.kind.value, artifact.path


@dataclass(frozen=True, slots=True)
class DemoRunIdentity:
    run_id: str
    project_name: str
    restore_project_name: str
    ownership_label: str

    @classmethod
    def create(cls) -> DemoRunIdentity:
        return cls.from_run_id(secrets.token_hex(8))

    @classmethod
    def from_run_id(cls, run_id: str) -> DemoRunIdentity:
        if RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise DemoE2EError("demo run identity is invalid")
        identity = cls(
            run_id=run_id,
            project_name=f"wg8b-{run_id}",
            restore_project_name=f"wg8b-{run_id}-restore",
            ownership_label=f"wg8b-{run_id}",
        )
        identity.validate()
        return identity

    def validate(self) -> None:
        if (
            RUN_ID_PATTERN.fullmatch(self.run_id) is None
            or PROJECT_PATTERN.fullmatch(self.project_name) is None
            or PROJECT_PATTERN.fullmatch(self.restore_project_name) is None
            or OWNERSHIP_PATTERN.fullmatch(self.ownership_label) is None
            or self.project_name != f"wg8b-{self.run_id}"
            or self.restore_project_name != f"wg8b-{self.run_id}-restore"
            or self.ownership_label != f"wg8b-{self.run_id}"
        ):
            raise DemoE2EError("demo run identity is invalid")


@dataclass(frozen=True, slots=True)
class DemoDatabaseConfiguration:
    host: str
    port: int
    database: str
    username: str
    password: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.host != "127.0.0.1"
            or type(self.port) is not int
            or not 1 <= self.port <= 65_535
            or self.database != "wg_demo"
            or self.username != "wg_demo"
        ):
            raise DemoE2EError("demo database configuration is invalid")

    def application_environment(self) -> dict[str, str]:
        return {
            "WG_APP_ENV": "test",
            "WG_POSTGRES_HOST": self.host,
            "WG_POSTGRES_PORT": str(self.port),
            "WG_POSTGRES_DB": self.database,
            "WG_POSTGRES_USER": self.username,
            "WG_POSTGRES_PASSWORD": self.password.reveal(),
            "WG_RUN_INTEGRATION_TESTS": "1",
        }


@dataclass(frozen=True, slots=True)
class CleanCheckoutMetadata:
    source_head: str
    checkout_root: Path = field(repr=False)

    def __post_init__(self) -> None:
        if EXPECTED_HEAD_PATTERN.fullmatch(self.source_head) is None:
            raise DemoE2EError("clean checkout commit identity is invalid")
        if not self.checkout_root.is_absolute():
            raise DemoE2EError("clean checkout root must be absolute")
