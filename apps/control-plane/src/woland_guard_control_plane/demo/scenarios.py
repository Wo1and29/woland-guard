"""Synthetic scenarios derived from the eight shipped detection-rule definitions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import cast
from uuid import UUID

from pydantic import JsonValue

from woland_guard_contracts import EventSource, NormalizedEventV1
from woland_guard_control_plane.application.detection.rules import (
    RuleDefinition,
    RuleValidationError,
    load_rules_directory,
)
from woland_guard_control_plane.demo.contracts import (
    DemoCaseType,
    DemoManifest,
    DemoManifestError,
    ExpectedIncident,
    ExpectedOutcomes,
    canonical_manifest_bytes,
    demo_event_id,
)

_SOURCE_RULES_DIRECTORY = Path(__file__).parents[5] / "detection-rules"
_CONTAINER_RULES_DIRECTORY = Path("/workspace/detection-rules")
RULES_DIRECTORY = next(
    (
        candidate
        for candidate in (_SOURCE_RULES_DIRECTORY, _CONTAINER_RULES_DIRECTORY)
        if candidate.is_dir()
    ),
    _SOURCE_RULES_DIRECTORY,
)
EXPECTED_RULE_KEYS = frozenset(
    {
        "privileged_group_membership_changed",
        "ssh_bruteforce_by_ip",
        "ssh_login_from_new_ip",
        "ssh_password_spray_by_ip",
        "ssh_root_login_success",
        "ssh_success_after_failures",
        "sudo_auth_failures",
        "user_account_created",
    }
)

_EVIDENCE_COUNTS = {
    "privileged_group_membership_changed": 1,
    "ssh_bruteforce_by_ip": 8,
    "ssh_login_from_new_ip": 2,
    "ssh_password_spray_by_ip": 5,
    "ssh_root_login_success": 1,
    "ssh_success_after_failures": 4,
    "sudo_auth_failures": 5,
    "user_account_created": 1,
}
_CASE_ORDER = (
    DemoCaseType.POSITIVE,
    DemoCaseType.NEGATIVE,
    DemoCaseType.BOUNDARY_BELOW,
    DemoCaseType.BOUNDARY_EXACT,
)


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    scenario_id: str
    rule_key: str
    case_type: DemoCaseType
    description: str
    ordinal: int


def list_scenarios() -> tuple[ScenarioDefinition, ...]:
    """Return a stable catalog after validating the shipped rule directory."""

    rules = _load_exact_rule_catalog()
    descriptions = {
        DemoCaseType.POSITIVE: "типичный синтетический match",
        DemoCaseType.NEGATIVE: "близкий синтетический non-match",
        DemoCaseType.BOUNDARY_BELOW: "значение непосредственно ниже границы",
        DemoCaseType.BOUNDARY_EXACT: "точная включительная граница",
    }
    definitions: list[ScenarioDefinition] = []
    for ordinal, rule_key in enumerate(sorted(rules)):
        for case_type in _CASE_ORDER:
            definitions.append(
                ScenarioDefinition(
                    scenario_id=f"{rule_key}.{case_type.value}.v1",
                    rule_key=rule_key,
                    case_type=case_type,
                    description=descriptions[case_type],
                    ordinal=ordinal * len(_CASE_ORDER) + _CASE_ORDER.index(case_type),
                )
            )
    return tuple(definitions)


def build_manifest(
    scenario_id: str,
    *,
    run_id: UUID,
    anchor_utc: datetime,
) -> DemoManifest:
    """Build one immutable scenario from an explicit run identity and UTC anchor."""

    if anchor_utc.tzinfo is None or anchor_utc.utcoffset() != UTC.utcoffset(anchor_utc):
        raise DemoManifestError("demo anchor must be timezone-aware UTC")
    definitions = {definition.scenario_id: definition for definition in list_scenarios()}
    try:
        definition = definitions[scenario_id]
    except (KeyError, TypeError):
        raise DemoManifestError("unsupported demo scenario") from None
    rules = _load_exact_rule_catalog()
    rule = rules[definition.rule_key]
    scenario_anchor = anchor_utc - timedelta(days=31 * definition.ordinal)
    event_specs = _build_event_specs(definition, scenario_anchor)
    events = tuple(
        _event_from_spec(
            spec,
            run_id=run_id,
            scenario_id=definition.scenario_id,
            ordinal=event_ordinal,
            scenario_ordinal=definition.ordinal,
        )
        for event_ordinal, spec in enumerate(sorted(event_specs, key=lambda item: item.occurred_at))
    )
    matching = definition.case_type in {
        DemoCaseType.POSITIVE,
        DemoCaseType.BOUNDARY_EXACT,
    }
    incidents = (
        (
            ExpectedIncident(
                rule_key=rule.rule_key,
                severity=rule.severity,
                title=rule.title,
                evidence_links=_EVIDENCE_COUNTS[rule.rule_key],
            ),
        )
        if matching
        else ()
    )
    expected = ExpectedOutcomes(
        incidents=incidents,
        new_incident_count=len(incidents),
        evidence_link_count=sum(item.evidence_links for item in incidents),
        outbox_count_delta=len(incidents),
        enabled_destination_count=1,
        allowed_cross_rule_outcomes=(),
    )
    return DemoManifest(
        run_id=run_id,
        anchor_utc=anchor_utc,
        scenario_id=definition.scenario_id,
        rule_key=definition.rule_key,
        case_type=definition.case_type,
        events=events,
        expected_outcomes=expected,
    )


def validate_catalog_manifest(manifest: DemoManifest) -> DemoManifest:
    """Require exact equality with the scenario rebuilt from the shipped catalog."""

    try:
        canonical = build_manifest(
            manifest.scenario_id,
            run_id=manifest.run_id,
            anchor_utc=manifest.anchor_utc,
        )
        matches = canonical_manifest_bytes(manifest) == canonical_manifest_bytes(canonical)
    except (DemoManifestError, TypeError, ValueError):
        raise DemoManifestError("demo manifest failed catalog validation") from None
    if not matches:
        raise DemoManifestError("demo manifest failed catalog validation")
    return manifest


@dataclass(frozen=True, slots=True)
class _EventSpec:
    event_type: str
    occurred_at: datetime
    actor: str | None
    source_ip: str | None
    attributes: dict[str, object]


def _build_event_specs(
    definition: ScenarioDefinition,
    anchor: datetime,
) -> tuple[_EventSpec, ...]:
    builders: dict[str, Callable[[DemoCaseType, datetime, int], tuple[_EventSpec, ...]]] = {
        "privileged_group_membership_changed": _privileged_group_specs,
        "ssh_bruteforce_by_ip": _bruteforce_specs,
        "ssh_login_from_new_ip": _first_seen_specs,
        "ssh_password_spray_by_ip": _password_spray_specs,
        "ssh_root_login_success": _root_login_specs,
        "ssh_success_after_failures": _sequence_specs,
        "sudo_auth_failures": _sudo_specs,
        "user_account_created": _user_created_specs,
    }
    return builders[definition.rule_key](definition.case_type, anchor, definition.ordinal)


def _privileged_group_specs(
    case: DemoCaseType, anchor: datetime, index: int
) -> tuple[_EventSpec, ...]:
    actor = _actor(index)
    if case is DemoCaseType.POSITIVE:
        attributes: dict[str, object] = {"group": "sudo", "action": "added"}
    elif case is DemoCaseType.NEGATIVE:
        attributes = {"group": "users", "action": "added"}
    elif case is DemoCaseType.BOUNDARY_BELOW:
        attributes = {"group": "sudo"}
    else:
        attributes = {"group": "wheel", "action": "removed"}
    return (_spec("linux.account.privileged_group_changed", anchor, actor, None, attributes),)


def _bruteforce_specs(case: DemoCaseType, anchor: datetime, index: int) -> tuple[_EventSpec, ...]:
    actor = _actor(index)
    if case is DemoCaseType.NEGATIVE:
        return tuple(
            _spec(
                "linux.ssh.authentication_failed",
                anchor + timedelta(seconds=offset - 7),
                actor,
                _documentation_ip(index, offset),
            )
            for offset in range(8)
        )
    count = 7 if case is DemoCaseType.BOUNDARY_BELOW else 8
    if case is DemoCaseType.BOUNDARY_EXACT:
        offsets: tuple[int, ...] = (-300, -6, -5, -4, -3, -2, -1, 0)
    else:
        offsets = tuple(range(-(count - 1), 1))
    source_ip = _documentation_ip(index, 0)
    return tuple(
        _spec(
            "linux.ssh.authentication_failed", anchor + timedelta(seconds=offset), actor, source_ip
        )
        for offset in offsets
    )


def _first_seen_specs(case: DemoCaseType, anchor: datetime, index: int) -> tuple[_EventSpec, ...]:
    actor = _actor(index)
    first_ip = _documentation_ip(index, 0)
    second_ip = first_ip if case is DemoCaseType.NEGATIVE else _documentation_ip(index, 1)
    baseline_offset = (
        -2_592_001
        if case is DemoCaseType.BOUNDARY_BELOW
        else (-2_592_000 if case is DemoCaseType.BOUNDARY_EXACT else -60)
    )
    return (
        _spec(
            "linux.ssh.login_succeeded",
            anchor + timedelta(seconds=baseline_offset),
            actor,
            first_ip,
        ),
        _spec("linux.ssh.login_succeeded", anchor, actor, second_ip),
    )


def _password_spray_specs(
    case: DemoCaseType, anchor: datetime, index: int
) -> tuple[_EventSpec, ...]:
    source_ip = _documentation_ip(index, 0)
    if case is DemoCaseType.NEGATIVE:
        return tuple(
            _spec(
                "linux.ssh.authentication_failed",
                anchor + timedelta(seconds=offset - 4),
                _actor(index, offset),
                _documentation_ip(index, offset),
            )
            for offset in range(5)
        )
    actors = [
        _actor(index, offset if offset < 4 else (3 if case is DemoCaseType.BOUNDARY_BELOW else 4))
        for offset in range(5)
    ]
    offsets = (-600, -3, -2, -1, 0) if case is DemoCaseType.BOUNDARY_EXACT else (-4, -3, -2, -1, 0)
    return tuple(
        _spec(
            "linux.ssh.authentication_failed", anchor + timedelta(seconds=offset), actor, source_ip
        )
        for offset, actor in zip(offsets, actors, strict=True)
    )


def _root_login_specs(case: DemoCaseType, anchor: datetime, index: int) -> tuple[_EventSpec, ...]:
    actor = (
        "root"
        if case in {DemoCaseType.POSITIVE, DemoCaseType.BOUNDARY_EXACT}
        else (_actor(index) if case is DemoCaseType.NEGATIVE else "Root")
    )
    return (
        _spec(
            "linux.ssh.login_succeeded",
            anchor,
            actor,
            _documentation_ip(index, 0),
        ),
    )


def _sequence_specs(case: DemoCaseType, anchor: datetime, index: int) -> tuple[_EventSpec, ...]:
    actor = _actor(index)
    source_ip = _documentation_ip(index, 0)
    failure_actor = _actor(index, 7) if case is DemoCaseType.NEGATIVE else actor
    count = 2 if case is DemoCaseType.BOUNDARY_BELOW else 3
    offsets = (-900, -2, -1) if case is DemoCaseType.BOUNDARY_EXACT else tuple(range(-count, 0))
    failures = tuple(
        _spec(
            "linux.ssh.authentication_failed",
            anchor + timedelta(seconds=offset),
            failure_actor,
            source_ip,
        )
        for offset in offsets
    )
    return (*failures, _spec("linux.ssh.login_succeeded", anchor, actor, source_ip))


def _sudo_specs(case: DemoCaseType, anchor: datetime, index: int) -> tuple[_EventSpec, ...]:
    if case is DemoCaseType.NEGATIVE:
        return tuple(
            _spec(
                "linux.sudo.authentication_failed",
                anchor + timedelta(seconds=offset - 4),
                _actor(index, offset),
                None,
            )
            for offset in range(5)
        )
    count = 4 if case is DemoCaseType.BOUNDARY_BELOW else 5
    offsets = (
        (-600, -3, -2, -1, 0)
        if case is DemoCaseType.BOUNDARY_EXACT
        else tuple(range(-(count - 1), 1))
    )
    actor = _actor(index)
    return tuple(
        _spec("linux.sudo.authentication_failed", anchor + timedelta(seconds=offset), actor, None)
        for offset in offsets
    )


def _user_created_specs(case: DemoCaseType, anchor: datetime, index: int) -> tuple[_EventSpec, ...]:
    event_type = (
        "linux.account.user_created"
        if case in {DemoCaseType.POSITIVE, DemoCaseType.BOUNDARY_EXACT}
        else (
            "linux.account.user_deleted"
            if case is DemoCaseType.NEGATIVE
            else "linux.account.user_create"
        )
    )
    actor = _actor(index)
    if case is DemoCaseType.BOUNDARY_EXACT:
        actor = "d" * 255
    return (_spec(event_type, anchor, actor, None),)


def _spec(
    event_type: str,
    occurred_at: datetime,
    actor: str | None,
    source_ip: str | None,
    attributes: dict[str, object] | None = None,
) -> _EventSpec:
    return _EventSpec(event_type, occurred_at, actor, source_ip, attributes or {})


def _event_from_spec(
    spec: _EventSpec,
    *,
    run_id: UUID,
    scenario_id: str,
    ordinal: int,
    scenario_ordinal: int,
) -> NormalizedEventV1:
    attributes = {
        **spec.attributes,
        "demo_scenario_id": scenario_id,
        "demo_source_id": f"synthetic-source-{scenario_ordinal:02d}",
    }
    return NormalizedEventV1(
        event_id=demo_event_id(run_id, scenario_id, ordinal),
        occurred_at=spec.occurred_at,
        collected_at=spec.occurred_at,
        source=EventSource.JOURNALD,
        event_type=spec.event_type,
        actor=spec.actor,
        source_ip=None if spec.source_ip is None else ip_address(spec.source_ip),
        summary="Synthetic Woland Guard demo event",
        attributes=cast(dict[str, JsonValue], attributes),
    )


def _actor(index: int, slot: int = 0) -> str:
    return f"synthetic_user_{index:02d}_{slot:02d}"


def _documentation_ip(index: int, slot: int) -> str:
    ordinal = index * 10 + slot
    networks = ("192.0.2", "198.51.100", "203.0.113")
    network = networks[(ordinal // 254) % len(networks)]
    host = ordinal % 254 + 1
    return f"{network}.{host}"


def _load_exact_rule_catalog() -> dict[str, RuleDefinition]:
    try:
        rules = load_rules_directory(RULES_DIRECTORY)
    except RuleValidationError:
        raise DemoManifestError("shipped detection rules are unavailable") from None
    by_key = {rule.rule_key: rule for rule in rules}
    if len(rules) != 8 or frozenset(by_key) != EXPECTED_RULE_KEYS:
        raise DemoManifestError("demo catalog requires the exact eight shipped detection rules")
    if any(not rule.enabled for rule in rules):
        raise DemoManifestError("demo catalog requires the shipped detection rules to be enabled")
    return by_key
