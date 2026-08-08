from __future__ import annotations

from scripts.demo_e2e.pipeline import PipelineExpectations, build_all_manifests


def test_full_profile_contains_48_catalog_bound_scenarios_and_derived_totals() -> None:
    manifests = build_all_manifests()
    expectations = PipelineExpectations.from_manifests(manifests)

    assert len(manifests) == 48
    assert len({manifest.scenario_id for manifest in manifests}) == 48
    assert expectations.event_count == sum(len(manifest.events) for manifest in manifests)
    assert expectations.incidents == tuple(
        (
            incident.rule_key,
            incident.severity.value,
            incident.title,
            incident.evidence_links,
        )
        for manifest in manifests
        for incident in manifest.expected_outcomes.incidents
    )
    assert expectations.evidence_count == sum(
        manifest.expected_outcomes.evidence_link_count for manifest in manifests
    )
    assert expectations.outbox_count == sum(
        manifest.expected_outcomes.outbox_count_delta for manifest in manifests
    )
