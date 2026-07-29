"""Unit contracts for safe incident comment normalization and hashing."""

import unicodedata
from uuid import UUID

import pytest

from woland_guard_control_plane.application.incident_comments import (
    MAX_COMMENT_LENGTH,
    CommentValidationError,
    canonical_comment_hash,
    normalize_comment,
)

_INCIDENT_ID = UUID("10000000-0000-4000-8000-000000000001")


def test_comment_normalizes_nfc_whitespace_and_browser_line_endings() -> None:
    normalized = normalize_comment("  cafe\u0301\r\nsecond\rline  ")
    assert normalized.body == "caf\u00e9\nsecond\nline"
    assert unicodedata.is_normalized("NFC", normalized.body)


@pytest.mark.parametrize("value", ["", " ", "\n\r", "\u00a0"])
def test_comment_rejects_empty_or_whitespace_only_values(value: str) -> None:
    with pytest.raises(CommentValidationError):
        normalize_comment(value)


@pytest.mark.parametrize(
    "value",
    [
        "nul\x00value",
        "tab\tvalue",
        "bidi\u202evalue",
        "line\u2028value",
        "paragraph\u2029value",
        "surrogate\ud800value",
    ],
)
def test_comment_rejects_control_format_separator_and_surrogate_values(value: str) -> None:
    with pytest.raises(CommentValidationError):
        normalize_comment(value)


def test_comment_enforces_limit_after_normalization() -> None:
    assert len(normalize_comment("x" * MAX_COMMENT_LENGTH).body) == MAX_COMMENT_LENGTH
    with pytest.raises(CommentValidationError):
        normalize_comment("x" * (MAX_COMMENT_LENGTH + 1))


def test_comment_hash_is_canonical_and_includes_incident_and_body() -> None:
    first = canonical_comment_hash(_INCIDENT_ID, normalize_comment("cafe\u0301"))
    second = canonical_comment_hash(_INCIDENT_ID, normalize_comment("caf\u00e9"))
    changed = canonical_comment_hash(_INCIDENT_ID, normalize_comment("other"))
    other_incident = canonical_comment_hash(
        UUID("20000000-0000-4000-8000-000000000002"),
        normalize_comment("caf\u00e9"),
    )
    assert first == second
    assert first != changed
    assert first != other_incident
    assert len(first) == 64
