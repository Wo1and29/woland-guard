"""Strict, non-executable YAML contracts for detection rules."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self, cast

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    TypeAdapter,
    ValidationError,
    model_validator,
)

_FIELD_PATTERN = r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$"
_RULE_KEY_PATTERN = r"^[a-z][a-z0-9_]{0,99}$"
_MITRE_PATTERN = r"^T[0-9]{4}(?:\.[0-9]{3})?$"

RuleKey = Annotated[str, Field(pattern=_RULE_KEY_PATTERN, max_length=100)]
_RULE_KEY_ADAPTER = TypeAdapter(RuleKey)

# Optional on the model so stored definitions keep validating, but mandatory for
# every rule file on disk: a new rule must never ship without its translation.
_REQUIRED_TRANSLATED_FIELDS = ("title_en", "description_en", "explanation_en", "recommendation_en")


class RuleValidationError(ValueError):
    """A safe aggregate error for an invalid rules directory."""


class RuleKeyValidationError(ValueError):
    """A safe error for a value outside the canonical rule-key contract."""


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SupportedEventType(StrEnum):
    SSH_AUTHENTICATION_FAILED = "linux.ssh.authentication_failed"
    SSH_LOGIN_SUCCEEDED = "linux.ssh.login_succeeded"
    SUDO_AUTHENTICATION_FAILED = "linux.sudo.authentication_failed"
    USER_CREATED = "linux.account.user_created"
    PRIVILEGED_GROUP_CHANGED = "linux.account.privileged_group_changed"
    # Only the failed request exists as an event: a successful one feeds no rule
    # and would outnumber every other source by orders of magnitude (ADR-0020 §7).
    NGINX_REQUEST_FAILED = "web.nginx.request_failed"
    CRON_JOB_CHANGED = "linux.cron.job_changed"
    SYSTEMD_UNIT_STOPPED = "linux.systemd.unit_stopped"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FieldMatcher(StrictModel):
    """A declarative equality or allowlist matcher; no expressions are accepted."""

    equals: JsonValue | None = None
    one_of: tuple[JsonValue, ...] | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def exactly_one_matcher(self) -> Self:
        if (self.equals is None) == (self.one_of is None):
            raise ValueError("a field matcher requires exactly one of equals or one_of")
        return self


class EventCondition(StrictModel):
    event_type: SupportedEventType
    filters: dict[Annotated[str, Field(pattern=_FIELD_PATTERN)], FieldMatcher] = Field(
        default_factory=dict
    )


class SingleCondition(EventCondition):
    type: Literal["single"]


class ThresholdCondition(EventCondition):
    type: Literal["threshold"]
    threshold: int = Field(gt=0)
    window_seconds: int = Field(gt=0)
    group_by: tuple[Annotated[str, Field(pattern=_FIELD_PATTERN)], ...] = Field(min_length=1)


class DistinctCountCondition(EventCondition):
    type: Literal["distinct_count"]
    distinct_field: Annotated[str, Field(pattern=_FIELD_PATTERN)]
    distinct_threshold: int = Field(gt=0)
    minimum_events: int = Field(gt=0)
    window_seconds: int = Field(gt=0)
    group_by: tuple[Annotated[str, Field(pattern=_FIELD_PATTERN)], ...] = Field(min_length=1)


class SequenceStep(EventCondition):
    repeat_at_least: int = Field(default=1, gt=0)


class SequenceCondition(StrictModel):
    type: Literal["sequence"]
    window_seconds: int = Field(gt=0)
    steps: tuple[SequenceStep, ...] = Field(min_length=2)


class FirstSeenCondition(EventCondition):
    type: Literal["first_seen"]
    value_field: Annotated[str, Field(pattern=_FIELD_PATTERN)]
    scope_fields: tuple[Annotated[str, Field(pattern=_FIELD_PATTERN)], ...] = Field(min_length=1)
    lookback_seconds: int = Field(gt=0)
    require_prior_baseline_events: int = Field(default=0, ge=0)


Condition = Annotated[
    SingleCondition
    | ThresholdCondition
    | DistinctCountCondition
    | SequenceCondition
    | FirstSeenCondition,
    Field(discriminator="type"),
]


class RuleDefinition(StrictModel):
    """Versioned immutable rule definition stored as an incident snapshot.

    The ``*_en`` prose fields are optional here on purpose, even though every
    rule file on disk is required to carry them (see ``load_rules_directory``).
    Stored definitions are re-validated through this model on every detection
    cycle and on every Rules page render, so a definition written before the
    English prose existed must keep validating; making these required would
    stop detection entirely on any database whose rules have not been re-synced.
    """

    schema_version: Literal[1]
    rule_key: RuleKey
    version: int = Field(gt=0)
    enabled: bool = True
    severity: Severity
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=2_000)
    explanation: str = Field(min_length=1, max_length=4_000)
    recommendation: str = Field(min_length=1, max_length=4_000)
    title_en: str | None = Field(default=None, min_length=1, max_length=255)
    description_en: str | None = Field(default=None, min_length=1, max_length=2_000)
    explanation_en: str | None = Field(default=None, min_length=1, max_length=4_000)
    recommendation_en: str | None = Field(default=None, min_length=1, max_length=4_000)
    mitre_attack_ids: tuple[Annotated[str, Field(pattern=_MITRE_PATTERN)], ...] = Field(
        default_factory=tuple
    )
    condition: Condition
    correlation_fields: tuple[Annotated[str, Field(pattern=_FIELD_PATTERN)], ...] = Field(
        min_length=1
    )

    @model_validator(mode="after")
    def field_lists_are_unique(self) -> Self:
        lists: list[tuple[str, ...]] = [self.correlation_fields]
        if isinstance(self.condition, (ThresholdCondition, DistinctCountCondition)):
            lists.append(self.condition.group_by)
        if isinstance(self.condition, FirstSeenCondition):
            lists.append(self.condition.scope_fields)
        if any(len(values) != len(set(values)) for values in lists):
            raise ValueError("rule field lists must not contain duplicates")
        return self


def validate_rule_key(value: object) -> str:
    """Validate one value with the same canonical contract as RuleDefinition.rule_key."""

    try:
        return _RULE_KEY_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        raise RuleKeyValidationError("invalid rule key") from None


def load_rules_directory(path: Path) -> tuple[RuleDefinition, ...]:
    """Validate every YAML file before returning any rule."""

    if not path.is_dir():
        raise RuleValidationError("rules directory is unavailable")
    files = sorted((*path.glob("*.yaml"), *path.glob("*.yml")))
    if not files:
        raise RuleValidationError("rules directory contains no YAML files")

    rules: list[RuleDefinition] = []
    for file_path in files:
        try:
            document = yaml.safe_load(file_path.read_text(encoding="utf-8"))
            rule = RuleDefinition.model_validate(document)
        except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as error:
            raise RuleValidationError(f"invalid rule file: {file_path.name}") from error
        if any(getattr(rule, name) is None for name in _REQUIRED_TRANSLATED_FIELDS):
            raise RuleValidationError(f"rule file is missing English prose: {file_path.name}")
        rules.append(rule)

    rule_keys = [rule.rule_key for rule in rules]
    if len(rule_keys) != len(set(rule_keys)):
        raise RuleValidationError("rules directory contains duplicate rule keys")
    return tuple(rules)


def canonical_rule(rule: RuleDefinition) -> dict[str, JsonValue]:
    """Return the JSON-compatible immutable representation used in PostgreSQL."""

    return cast(dict[str, JsonValue], rule.model_dump(mode="json"))


def rule_checksum(rule: RuleDefinition) -> str:
    encoded = json.dumps(
        canonical_rule(rule),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
