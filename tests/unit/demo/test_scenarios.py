"""Synthetic scenario catalog coverage and isolation tests."""

from __future__ import annotations

import ast
import ipaddress
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.demo.contracts import (
    DemoCaseType,
    DemoManifestError,
    canonical_manifest_bytes,
)
from woland_guard_control_plane.demo.scenarios import (
    EXPECTED_RULE_KEYS,
    RULES_DIRECTORY,
    build_manifest,
    list_scenarios,
    validate_catalog_manifest,
)

RUN_ID = UUID("22222222-2222-4222-8222-222222222222")
ANCHOR = datetime(2026, 7, 29, 12, tzinfo=UTC)
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def test_catalog_contains_exactly_four_cases_for_each_of_thirteen_rules() -> None:
    definitions = list_scenarios()

    assert len(definitions) == 52
    assert len({item.scenario_id for item in definitions}) == 52
    assert {item.rule_key for item in definitions} == EXPECTED_RULE_KEYS
    counts = Counter(item.rule_key for item in definitions)
    assert set(counts.values()) == {4}
    for rule_key in EXPECTED_RULE_KEYS:
        assert {item.case_type for item in definitions if item.rule_key == rule_key} == set(
            DemoCaseType
        )


def test_all_canonical_catalog_manifests_validate_by_exact_rebuild() -> None:
    for definition in list_scenarios():
        manifest = build_manifest(definition.scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)

        assert validate_catalog_manifest(manifest) is manifest


def test_catalog_validation_rejects_changed_metadata_without_reflection() -> None:
    manifest = build_manifest(
        "ssh_bruteforce_by_ip.positive.v1",
        run_id=RUN_ID,
        anchor_utc=ANCHOR,
    )
    incident = manifest.expected_outcomes.incidents[0].model_copy(
        update={"title": "catalog-validation-canary"}
    )
    outcomes = manifest.expected_outcomes.model_copy(update={"incidents": (incident,)})
    mutated = manifest.model_copy(update={"expected_outcomes": outcomes})

    with pytest.raises(DemoManifestError, match="catalog validation") as captured:
        validate_catalog_manifest(mutated)

    assert "catalog-validation-canary" not in str(captured.value)


def test_catalog_metadata_is_derived_from_the_exact_enabled_yaml_rules() -> None:
    rules = {rule.rule_key: rule for rule in load_rules_directory(RULES_DIRECTORY)}

    assert len(rules) == 13
    assert set(rules) == EXPECTED_RULE_KEYS
    # Deliberately not pinned to a literal version: expected outcomes are derived
    # from each rule's condition at manifest build time and re-verified by the
    # exact-rebuild test, so a prose-only rule bump must not break the catalog.
    assert all(rule.enabled for rule in rules.values())
    assert {rule.condition.type for rule in rules.values()} == {
        "single",
        "threshold",
        "distinct_count",
        "sequence",
        "first_seen",
    }


def test_matching_and_nonmatching_cases_have_full_exact_outcomes() -> None:
    for definition in list_scenarios():
        manifest = build_manifest(definition.scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)
        keys = tuple(item.rule_key for item in manifest.expected_outcomes.incidents)
        if definition.case_type in {DemoCaseType.POSITIVE, DemoCaseType.BOUNDARY_EXACT}:
            assert keys == (definition.rule_key,)
            assert manifest.expected_outcomes.new_incident_count == 1
            assert manifest.expected_outcomes.outbox_count_delta == 1
        else:
            assert keys == ()
            assert manifest.expected_outcomes.new_incident_count == 0
            assert manifest.expected_outcomes.evidence_link_count == 0
            assert manifest.expected_outcomes.outbox_count_delta == 0
        assert manifest.expected_outcomes.allowed_cross_rule_outcomes == ()


def test_scenario_events_are_deterministic_synthetic_and_documentation_only() -> None:
    actor_values: dict[str, set[str]] = {}
    for definition in list_scenarios():
        first = build_manifest(definition.scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)
        second = build_manifest(definition.scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)
        assert canonical_manifest_bytes(first) == canonical_manifest_bytes(second)
        for event in first.events:
            assert event.summary == "Synthetic Woland Guard demo event"
            assert event.attributes["demo_scenario_id"] == definition.scenario_id
            assert str(event.attributes["demo_source_id"]).startswith("synthetic-source-")
            if event.actor is not None and event.actor not in {"root", "Root"}:
                assert event.actor.startswith("synthetic_") or set(event.actor) == {"d"}
                actor_values.setdefault(definition.scenario_id, set()).add(event.actor)
            if event.source_ip is not None:
                assert any(event.source_ip in network for network in DOCUMENTATION_NETWORKS)
    assert all(actor_values.values())


def test_scenario_time_ranges_are_separated_beyond_maximum_rule_lookback() -> None:
    ranges = []
    for definition in list_scenarios():
        manifest = build_manifest(definition.scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)
        ranges.append((max(event.occurred_at for event in manifest.events), definition.ordinal))
    ordered = sorted(ranges, key=lambda item: item[1])

    for (newer, _), (older, _) in zip(ordered, ordered[1:], strict=False):
        assert newer - older > datetime.resolution
        assert (newer - older).days >= 30


def test_demo_implementation_has_no_database_or_orm_imports() -> None:
    demo_directory = (
        Path(__file__).parents[3] / "apps/control-plane/src/woland_guard_control_plane/demo"
    )
    prohibited = ("sqlalchemy", "woland_guard_control_plane.database", "infrastructure.database")

    for source_path in demo_directory.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        assert not any(any(marker in module for marker in prohibited) for module in imported)
