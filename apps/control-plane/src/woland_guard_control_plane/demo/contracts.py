"""Closed, canonical contracts for untrusted synthetic demo manifests."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import UTC
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self, cast
from uuid import UUID, uuid4, uuid5

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from woland_guard_contracts import NormalizedEventV1
from woland_guard_control_plane.application.detection.rules import RuleKey, Severity

DEMO_MANIFEST_SCHEMA_VERSION = 1
DEMO_EVENT_NAMESPACE = UUID("9f0d4b1b-f49c-5f47-a50a-8d8f65484748")
MAX_MANIFEST_BYTES = 1_048_576
MAX_MANIFEST_EVENTS = 1_000
MAX_EVENT_BYTES = 32_768
MAX_SCENARIO_ID_LENGTH = 180

_SCENARIO_ID_PATTERN = r"^[a-z][a-z0-9_]*(?:[.][a-z][a-z0-9_]*){2}$"
_FORBIDDEN_KEY_NAMES = {
    "authorization",
    "cookie",
    "credential",
    "csrf",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
}
_FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+\S+"),
    re.compile(r"\bwg(?:ak|ok)_[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[0-9]{6,}:[A-Za-z0-9_-]{10,}\b"),
)
_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


class DemoManifestError(ValueError):
    """Safe manifest failure that never reflects untrusted content."""


class DemoArtifactError(ValueError):
    """Safe filesystem failure without paths or manifest contents."""


class DemoCaseType(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    BOUNDARY_BELOW = "boundary_below"
    BOUNDARY_EXACT = "boundary_exact"


class StrictDemoModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExpectedIncident(StrictDemoModel):
    rule_key: RuleKey
    severity: Severity
    title: str = Field(min_length=1, max_length=255)
    initial_status: Literal["new"] = "new"
    evidence_links: int = Field(ge=1, le=MAX_MANIFEST_EVENTS)


class ExpectedOutcomes(StrictDemoModel):
    """Full expected result under the one-low-severity-destination test assumption."""

    incidents: tuple[ExpectedIncident, ...] = Field(max_length=8)
    new_incident_count: int = Field(ge=0, le=8)
    evidence_link_count: int = Field(ge=0, le=8 * MAX_MANIFEST_EVENTS)
    outbox_count_delta: int = Field(ge=0, le=8)
    enabled_destination_count: Literal[1] = 1
    allowed_cross_rule_outcomes: tuple[RuleKey, ...] = Field(max_length=7)

    @model_validator(mode="after")
    def counts_and_rule_sets_are_exact(self) -> Self:
        keys = tuple(item.rule_key for item in self.incidents)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("expected incident rule keys must be unique and sorted")
        if self.new_incident_count != len(self.incidents):
            raise ValueError("expected incident count does not match incident details")
        if self.evidence_link_count != sum(item.evidence_links for item in self.incidents):
            raise ValueError("expected evidence count does not match incident details")
        if self.outbox_count_delta != self.new_incident_count:
            raise ValueError("one enabled destination requires one row per new incident")
        cross = self.allowed_cross_rule_outcomes
        if cross != tuple(sorted(cross)) or len(cross) != len(set(cross)):
            raise ValueError("allowed cross-rule outcomes must be unique and sorted")
        if any(key not in keys for key in cross):
            raise ValueError("cross-rule outcomes must belong to the full expected set")
        return self


class DemoManifest(StrictDemoModel):
    schema_version: Literal[1] = 1
    run_id: UUID
    anchor_utc: AwareDatetime
    scenario_id: Annotated[
        str,
        Field(min_length=5, max_length=MAX_SCENARIO_ID_LENGTH, pattern=_SCENARIO_ID_PATTERN),
    ]
    rule_key: RuleKey
    case_type: DemoCaseType
    events: tuple[NormalizedEventV1, ...] = Field(
        min_length=1,
        max_length=MAX_MANIFEST_EVENTS,
    )
    expected_outcomes: ExpectedOutcomes

    @model_validator(mode="after")
    def manifest_is_canonical_and_safe(self) -> Self:
        if self.anchor_utc.utcoffset() != UTC.utcoffset(self.anchor_utc):
            raise ValueError("manifest anchor must be UTC")
        identity = self.scenario_id.split(".")
        if (
            len(identity) != 3
            or identity[0] != self.rule_key
            or identity[1] != self.case_type.value
            or identity[2] != "v1"
        ):
            raise ValueError("scenario identity does not match the manifest contract")
        incident_keys = tuple(item.rule_key for item in self.expected_outcomes.incidents)
        matching = self.case_type in {
            DemoCaseType.POSITIVE,
            DemoCaseType.BOUNDARY_EXACT,
        }
        target_count = incident_keys.count(self.rule_key)
        if (matching and target_count != 1) or (not matching and target_count != 0):
            raise ValueError("target rule outcome does not match the scenario case")
        expected_cross_rules = tuple(key for key in incident_keys if key != self.rule_key)
        if self.expected_outcomes.allowed_cross_rule_outcomes != expected_cross_rules:
            raise ValueError("cross-rule outcome allowlist is not exact")
        if any(
            event.occurred_at.utcoffset() != UTC.utcoffset(event.occurred_at)
            for event in self.events
        ):
            raise ValueError("event timestamps must be UTC")
        if any(
            event.collected_at.utcoffset() != UTC.utcoffset(event.collected_at)
            for event in self.events
        ):
            raise ValueError("event timestamps must be UTC")
        if (
            tuple(sorted(self.events, key=lambda event: (event.occurred_at, event.event_id)))
            != self.events
        ):
            raise ValueError("manifest events must use stable chronological ordering")
        for ordinal, event in enumerate(self.events):
            if event.event_id != demo_event_id(self.run_id, self.scenario_id, ordinal):
                raise ValueError("manifest event id is not deterministic")
            event_bytes = _canonical_json_bytes(event.model_dump(mode="json"))
            if len(event_bytes) > MAX_EVENT_BYTES:
                raise ValueError("manifest event exceeds the safe size limit")
        dumped = self.model_dump(mode="json")
        _validate_untrusted_tree(dumped)
        return self


def demo_event_id(run_id: UUID, scenario_id: str, ordinal: int) -> UUID:
    if type(ordinal) is not int or ordinal < 0:
        raise ValueError("event ordinal must be a non-negative integer")
    return uuid5(DEMO_EVENT_NAMESPACE, f"event:{run_id}:{scenario_id}:{ordinal}")


def demo_batch_id(run_id: UUID, scenario_id: str, ordinal: int) -> UUID:
    if type(ordinal) is not int or ordinal < 0:
        raise ValueError("batch ordinal must be a non-negative integer")
    return uuid5(DEMO_EVENT_NAMESPACE, f"batch:{run_id}:{scenario_id}:{ordinal}")


def canonical_manifest_bytes(manifest: DemoManifest) -> bytes:
    encoded = _canonical_json_bytes(manifest.model_dump(mode="json"))
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise DemoManifestError("manifest exceeds the safe size limit")
    return encoded


def load_manifest(path: Path) -> DemoManifest:
    """Securely read and validate one canonical JSON manifest."""

    raw = _read_bounded_regular_file(path, maximum_bytes=MAX_MANIFEST_BYTES)
    return load_manifest_bytes(raw)


def load_manifest_bytes(raw: bytes) -> DemoManifest:
    if type(raw) is not bytes or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise DemoManifestError("manifest has an invalid size")
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        manifest = DemoManifest.model_validate(document)
    except (UnicodeError, json.JSONDecodeError, ValidationError, ValueError, TypeError):
        raise DemoManifestError("manifest failed strict validation") from None
    if canonical_manifest_bytes(manifest) != raw:
        raise DemoManifestError("manifest is not canonical JSON")
    return manifest


def write_manifest(path: Path, manifest: DemoManifest, *, overwrite: bool = False) -> None:
    """Publish canonical bytes without following a link or silently overwriting a file."""

    data = canonical_manifest_bytes(manifest)
    _validate_output_path(path, overwrite=overwrite)
    if not overwrite:
        _exclusive_write(path, data)
        return

    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        _exclusive_write(temporary, data)
        _validate_output_path(path, overwrite=True)
        os.replace(temporary, path)
    except DemoArtifactError:
        raise
    except OSError:
        raise DemoArtifactError("manifest could not be written safely") from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def validate_manifest_output_directory(path: Path) -> None:
    """Validate a directory used to publish a set of demo manifests."""

    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise DemoArtifactError("manifest output directory must be an absolute canonical path")
    try:
        _validate_directory_chain(path)
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise DemoArtifactError("manifest output directory is unsafe")
    except DemoArtifactError:
        raise
    except OSError:
        raise DemoArtifactError("manifest output directory is unavailable") from None


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise DemoManifestError("manifest cannot be serialized safely") from None


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _validate_untrusted_tree(value: object) -> None:
    if isinstance(value, str):
        if len(value) > 4_000:
            raise ValueError("manifest string exceeds the safe limit")
        if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value):
            raise ValueError("manifest text contains a prohibited character")
        if any(pattern.search(value) for pattern in _FORBIDDEN_VALUE_PATTERNS):
            raise ValueError("manifest contains prohibited credential material")
        if (
            "://" in value
            or value.lower().startswith("file:")
            or _WINDOWS_ABSOLUTE_PATH.match(value)
            or value.startswith(("/", "\\\\"))
            or re.search(r"(?:^|[\\/])[.][.](?:[\\/]|$)", value)
        ):
            raise ValueError("manifest contains a prohibited path or URL")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("manifest contains a non-finite number")
        return
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("manifest object keys must be strings")
            if key.casefold() in _FORBIDDEN_KEY_NAMES:
                raise ValueError("manifest contains a prohibited field")
            _validate_untrusted_tree(key)
            _validate_untrusted_tree(nested)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_untrusted_tree(item)


def _read_bounded_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError:
        raise DemoManifestError("manifest file is unavailable") from None
    if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise DemoManifestError("manifest file must be a regular non-link file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise DemoManifestError("manifest file has an invalid size")
    flags = os.O_RDONLY | cast(int, getattr(os, "O_NOFOLLOW", 0))
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise DemoManifestError("manifest file changed during secure open")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(maximum_bytes + 1)
    except DemoManifestError:
        raise
    except OSError:
        raise DemoManifestError("manifest file cannot be read safely") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > maximum_bytes:
        raise DemoManifestError("manifest file has an invalid size")
    return data


def _validate_output_path(path: Path, *, overwrite: bool) -> None:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise DemoArtifactError("manifest output must be an absolute canonical path")
    try:
        parent = path.parent
        _validate_directory_chain(parent)
        parent_metadata = parent.lstat()
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise DemoArtifactError("manifest output parent is unsafe")
        if path.exists() or path.is_symlink():
            target_metadata = path.lstat()
            if _is_reparse(target_metadata) or not stat.S_ISREG(target_metadata.st_mode):
                raise DemoArtifactError("manifest output target is unsafe")
            if not overwrite:
                raise DemoArtifactError("manifest output already exists")
    except DemoArtifactError:
        raise
    except OSError:
        raise DemoArtifactError("manifest output path is unavailable") from None


def _validate_directory_chain(path: Path) -> None:
    current = path
    while True:
        metadata = current.lstat()
        if _is_reparse(metadata):
            raise DemoArtifactError("manifest output path contains an unsafe link")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _exclusive_write(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | cast(int, getattr(os, "O_NOFOLLOW", 0))
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise DemoArtifactError("manifest could not be written safely") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _is_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = cast(int, getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    attributes = cast(int, getattr(metadata, "st_file_attributes", 0))
    return bool(reparse_flag and attributes & reparse_flag)
