"""Reproducible, synthetic-only demo scenario support."""

from woland_guard_control_plane.demo.contracts import (
    DEMO_EVENT_NAMESPACE,
    DemoCaseType,
    DemoManifest,
    DemoManifestError,
    ExpectedIncident,
    ExpectedOutcomes,
    canonical_manifest_bytes,
    load_manifest,
)
from woland_guard_control_plane.demo.scenarios import (
    EXPECTED_RULE_KEYS,
    ScenarioDefinition,
    build_manifest,
    list_scenarios,
    validate_catalog_manifest,
)

__all__ = [
    "DEMO_EVENT_NAMESPACE",
    "EXPECTED_RULE_KEYS",
    "DemoCaseType",
    "DemoManifest",
    "DemoManifestError",
    "ExpectedIncident",
    "ExpectedOutcomes",
    "ScenarioDefinition",
    "build_manifest",
    "canonical_manifest_bytes",
    "list_scenarios",
    "load_manifest",
    "validate_catalog_manifest",
]
