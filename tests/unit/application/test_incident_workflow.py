"""Unit tests for the exact 6B transition contract and canonicalization."""

from uuid import UUID

import pytest

from woland_guard_control_plane.application.incident_workflow import (
    TransitionValidationError,
    canonical_transition_hash,
    is_transition_allowed,
    normalize_reason,
    normalize_transition,
    validate_idempotency_key,
)
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (IncidentStatus.NEW, IncidentStatus.INVESTIGATING),
        (IncidentStatus.NEW, IncidentStatus.RESOLVED),
        (IncidentStatus.NEW, IncidentStatus.FALSE_POSITIVE),
        (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE),
    ],
)
def test_exact_allowed_status_transitions(
    current: IncidentStatus,
    target: IncidentStatus,
) -> None:
    assert is_transition_allowed(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (current, target)
        for current in IncidentStatus
        for target in IncidentStatus
        if (current, target)
        not in {
            (IncidentStatus.NEW, IncidentStatus.INVESTIGATING),
            (IncidentStatus.NEW, IncidentStatus.RESOLVED),
            (IncidentStatus.NEW, IncidentStatus.FALSE_POSITIVE),
            (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED),
            (IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE),
        }
    ],
)
def test_every_other_status_transition_is_forbidden(
    current: IncidentStatus,
    target: IncidentStatus,
) -> None:
    assert not is_transition_allowed(current, target)


@pytest.mark.parametrize("status", [IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE])
def test_terminal_status_requires_reason(status: IncidentStatus) -> None:
    with pytest.raises(TransitionValidationError):
        normalize_transition(target_status=status, expected_version=1, reason=None)


def test_reason_checks_raw_value_before_only_ascii_edge_spaces_are_removed() -> None:
    assert normalize_reason("  cafe\u0301  ") == "café"
    for value in ("\nvalid", "valid\n", "\tvalid", "valid\t", "safe\x00unsafe", "a\u2028b"):
        with pytest.raises(TransitionValidationError):
            normalize_reason(value)


def test_reason_length_is_checked_after_ascii_space_trim_and_nfc() -> None:
    assert normalize_reason(" " + ("a" * 1_000) + " ") == "a" * 1_000
    for value in ("", "   ", "a" * 1_001):
        with pytest.raises(TransitionValidationError):
            normalize_reason(value)


@pytest.mark.parametrize("value", ["a\x1fb", "a\u200bb", "a\ud800b", "a\u2029b"])
def test_reason_rejects_control_format_surrogate_and_paragraph_characters(value: str) -> None:
    with pytest.raises(TransitionValidationError):
        normalize_reason(value)


def test_idempotency_key_has_one_safe_ascii_format() -> None:
    assert validate_idempotency_key("transition:synthetic-01") == "transition:synthetic-01"
    for value in ("", " leading", "contains space", "x" * 129, "ключ"):
        with pytest.raises(TransitionValidationError):
            validate_idempotency_key(value)


def test_canonical_hash_includes_incident_version_status_and_normalized_reason() -> None:
    incident_id = UUID("00000000-0000-4000-8000-000000000001")
    transition = normalize_transition(
        target_status=IncidentStatus.RESOLVED,
        expected_version=2,
        reason="  café  ",
    )

    first = canonical_transition_hash(incident_id, transition)
    second = canonical_transition_hash(incident_id, transition)

    assert first == second
    assert len(first) == 64
