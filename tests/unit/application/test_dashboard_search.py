"""Literal Dashboard search never grants LIKE wildcard semantics."""

import pytest

from woland_guard_control_plane.application.dashboard_search import (
    DashboardQueryValidationError,
    literal_prefix_pattern,
    normalize_literal_prefix,
    parse_canonical_rule_key,
    parse_canonical_uuid,
)


@pytest.mark.parametrize(
    ("value", "pattern"),
    [
        ("percent%", "percent!%%"),
        ("under_score", "under!_score%"),
        ("bang!", "bang!!%"),
        ("!%_", "!!!%!_%"),
        ("Привет", "Привет%"),
    ],
)
def test_literal_prefix_escapes_every_like_metacharacter(value: str, pattern: str) -> None:
    assert literal_prefix_pattern(value) == pattern


def test_search_normalizes_nfc_and_only_outer_spaces() -> None:
    assert normalize_literal_prefix("  Cafe\u0301 test  ") == "Café test"


@pytest.mark.parametrize("value", ["   ", "nul\x00", "format\u200b", "surrogate\ud800"])
def test_empty_and_unsafe_prefixes_are_rejected(value: str) -> None:
    with pytest.raises(DashboardQueryValidationError, match="invalid dashboard search"):
        normalize_literal_prefix(value)


def test_only_absent_search_is_absent_and_empty_never_becomes_match_all() -> None:
    assert normalize_literal_prefix(None) is None
    with pytest.raises(DashboardQueryValidationError):
        normalize_literal_prefix("")


def test_canonical_rule_key_reuses_detection_contract() -> None:
    assert parse_canonical_rule_key(None) is None
    assert parse_canonical_rule_key("ssh_root_login_success") == "ssh_root_login_success"
    assert parse_canonical_rule_key("a" + "0" * 99) == "a" + "0" * 99


@pytest.mark.parametrize(
    "value",
    [
        "",
        "UPPERCASE",
        "1starts_with_digit",
        "contains-dash",
        "contains.dot",
        "contains space",
        "percent%",
        "path/symbol",
        "nul\x00",
        "format\u200b",
        "surrogate\ud800",
        "a" + "0" * 100,
    ],
)
def test_invalid_exact_rule_keys_are_rejected(value: str) -> None:
    with pytest.raises(DashboardQueryValidationError, match="invalid dashboard rule key"):
        parse_canonical_rule_key(value)


def test_canonical_uuid_is_exact_and_lowercase() -> None:
    canonical = "abcdef00-0000-4000-8000-000000000001"
    assert str(parse_canonical_uuid(canonical)) == canonical
    with pytest.raises(DashboardQueryValidationError):
        parse_canonical_uuid(canonical.upper())
