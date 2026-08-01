"""Closed and canonical demo manifest contract tests."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from woland_guard_control_plane.demo.contracts import (
    DEMO_EVENT_NAMESPACE,
    MAX_MANIFEST_BYTES,
    DemoArtifactError,
    DemoManifest,
    DemoManifestError,
    canonical_manifest_bytes,
    demo_event_id,
    load_manifest,
    load_manifest_bytes,
    validate_manifest_output_directory,
    write_manifest,
)
from woland_guard_control_plane.demo.scenarios import build_manifest, list_scenarios

RUN_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ANCHOR = datetime(2026, 7, 29, 12, tzinfo=UTC)


def _manifest() -> DemoManifest:
    return build_manifest(list_scenarios()[0].scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)


def _scenario_manifest(scenario_id: str) -> DemoManifest:
    return build_manifest(scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)


def _canonical_document_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def test_manifest_canonical_round_trip_is_byte_stable() -> None:
    encoded = canonical_manifest_bytes(_manifest())

    loaded = load_manifest_bytes(encoded)

    assert canonical_manifest_bytes(loaded) == encoded
    assert b"\n" not in encoded


def test_namespace_and_event_uuid_are_fixed_and_deterministic() -> None:
    first = demo_event_id(RUN_ID, "ssh_root_login_success.positive.v1", 0)
    second = demo_event_id(RUN_ID, "ssh_root_login_success.positive.v1", 0)

    assert DEMO_EVENT_NAMESPACE == UUID("9f0d4b1b-f49c-5f47-a50a-8d8f65484748")
    assert first == second
    assert first.version == 5
    assert first != demo_event_id(RUN_ID, "ssh_root_login_success.positive.v1", 1)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b"not-json",
        b"\xff",
        b"{}",
    ],
)
def test_malformed_duplicate_and_non_finite_json_is_rejected(raw: bytes) -> None:
    with pytest.raises(DemoManifestError, match="manifest"):
        load_manifest_bytes(raw)


def test_noncanonical_whitespace_and_uppercase_uuid_are_rejected() -> None:
    document = json.loads(canonical_manifest_bytes(_manifest()))
    document["run_id"] = str(RUN_ID).upper()
    encoded = json.dumps(document, ensure_ascii=False, sort_keys=True).encode()

    with pytest.raises(DemoManifestError, match="canonical"):
        load_manifest_bytes(encoded)


@pytest.mark.parametrize(
    ("scenario_id", "case_type"),
    [
        ("ssh_bruteforce_by_ip.negative.v1", "positive"),
        ("ssh_bruteforce_by_ip.positive.v2", "positive"),
        ("ssh_bruteforce_by_ip.positive.v1.extra", "positive"),
        ("ssh_bruteforce_by_ip.unknown.v1", "positive"),
    ],
)
def test_scenario_identity_must_exactly_match_rule_case_and_v1(
    scenario_id: str,
    case_type: str,
) -> None:
    document = json.loads(
        canonical_manifest_bytes(_scenario_manifest("ssh_bruteforce_by_ip.positive.v1"))
    )
    document["scenario_id"] = scenario_id
    document["case_type"] = case_type

    with pytest.raises(DemoManifestError, match="strict"):
        load_manifest_bytes(_canonical_document_bytes(document))


def test_matching_and_nonmatching_cases_require_the_exact_target_outcome() -> None:
    positive_manifest = _scenario_manifest("ssh_bruteforce_by_ip.positive.v1")
    positive = json.loads(canonical_manifest_bytes(positive_manifest))
    positive["expected_outcomes"] = {
        "allowed_cross_rule_outcomes": [],
        "enabled_destination_count": 1,
        "evidence_link_count": 0,
        "incidents": [],
        "new_incident_count": 0,
        "outbox_count_delta": 0,
    }
    with pytest.raises(DemoManifestError, match="strict"):
        load_manifest_bytes(_canonical_document_bytes(positive))

    negative_manifest = _scenario_manifest("ssh_bruteforce_by_ip.negative.v1")
    negative = json.loads(canonical_manifest_bytes(negative_manifest))
    target = positive["expected_outcomes"]["incidents"]
    negative["expected_outcomes"] = {
        "allowed_cross_rule_outcomes": [],
        "enabled_destination_count": 1,
        "evidence_link_count": 8,
        "incidents": target,
        "new_incident_count": 1,
        "outbox_count_delta": 1,
    }
    with pytest.raises(DemoManifestError, match="strict"):
        load_manifest_bytes(_canonical_document_bytes(negative))


def test_cross_rule_allowlist_must_exactly_equal_all_non_target_incidents() -> None:
    document = json.loads(
        canonical_manifest_bytes(_scenario_manifest("ssh_bruteforce_by_ip.positive.v1"))
    )
    cross = json.loads(
        canonical_manifest_bytes(_scenario_manifest("user_account_created.positive.v1"))
    )["expected_outcomes"]["incidents"][0]
    incidents = sorted(
        [*document["expected_outcomes"]["incidents"], cross],
        key=lambda item: item["rule_key"],
    )
    document["expected_outcomes"].update(
        {
            "incidents": incidents,
            "new_incident_count": 2,
            "evidence_link_count": 9,
            "outbox_count_delta": 2,
            "allowed_cross_rule_outcomes": [],
        }
    )

    with pytest.raises(DemoManifestError, match="strict"):
        load_manifest_bytes(_canonical_document_bytes(document))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("extra",), "field"),
        (("run_id",), "not-a-uuid"),
        (("anchor_utc",), "2026-07-29T15:00:00+03:00"),
        (("scenario_id",), "unsupported"),
        (("rule_key",), "other_rule"),
        (("events", 0, "summary"), "Bearer canary-value"),
        (("events", 0, "summary"), "wgak_public.secret"),
        (("events", 0, "summary"), "-----BEGIN PRIVATE KEY-----"),
        (("events", 0, "summary"), "https://example.invalid/value"),
        (("events", 0, "summary"), "../unsafe"),
        (("events", 0, "summary"), "unsafe\u0001value"),
        (("events", 0, "summary"), "unsafe\u200bvalue"),
        (("events", 0, "attributes", "token"), "synthetic-value"),
    ],
)
def test_untrusted_manifest_values_are_rejected(path: tuple[object, ...], value: object) -> None:
    document = json.loads(canonical_manifest_bytes(_manifest()))
    if path == ("extra",):
        document["extra"] = value
    else:
        target = document
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(DemoManifestError, match="manifest"):
        load_manifest_bytes(encoded)


def test_invalid_event_schema_and_too_many_events_are_rejected() -> None:
    document = json.loads(canonical_manifest_bytes(_manifest()))
    document["events"][0]["schema_version"] = 2
    invalid_schema = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    with pytest.raises(DemoManifestError, match="manifest"):
        load_manifest_bytes(invalid_schema)

    document = json.loads(canonical_manifest_bytes(_manifest()))
    document["events"] = document["events"] * 1_001
    oversized_event_set = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    with pytest.raises(DemoManifestError, match="manifest"):
        load_manifest_bytes(oversized_event_set)


def test_escaped_surrogate_is_rejected() -> None:
    encoded = canonical_manifest_bytes(_manifest()).replace(
        b"Synthetic Woland Guard demo event",
        b"\\ud800",
    )

    with pytest.raises(DemoManifestError, match="manifest"):
        load_manifest_bytes(encoded)


def test_oversized_manifest_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (MAX_MANIFEST_BYTES + 1))

    with pytest.raises(DemoManifestError, match="size"):
        load_manifest(path)


def test_safe_writer_requires_absolute_path_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"
    write_manifest(output, _manifest())

    assert load_manifest(output) == _manifest()
    with pytest.raises(DemoArtifactError, match="exists"):
        write_manifest(output, _manifest())
    with pytest.raises(DemoArtifactError, match="absolute"):
        write_manifest(Path("../manifest.json"), _manifest())


def test_explicit_overwrite_replaces_only_regular_file(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"
    output.write_bytes(b"old")

    write_manifest(output, _manifest(), overwrite=True)

    assert output.read_bytes() == canonical_manifest_bytes(_manifest())


def test_symlink_input_and_output_are_rejected_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(canonical_manifest_bytes(_manifest()))
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is not available")

    with pytest.raises(DemoManifestError, match="regular non-link"):
        load_manifest(link)
    with pytest.raises(DemoArtifactError, match="unsafe"):
        write_manifest(link, _manifest(), overwrite=True)


def test_output_directory_link_is_rejected_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is not available")

    with pytest.raises(DemoArtifactError, match="unsafe link"):
        validate_manifest_output_directory(link)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode contract")
def test_writer_uses_private_mode_on_posix(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"
    write_manifest(output, _manifest())

    assert output.stat().st_mode & 0o077 == 0
