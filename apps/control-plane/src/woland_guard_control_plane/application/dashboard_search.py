"""Strict literal-prefix normalization for untrusted Dashboard query input."""

from __future__ import annotations

import unicodedata
from uuid import UUID

from woland_guard_control_plane.application.detection.rules import (
    RuleKeyValidationError,
    validate_rule_key,
)

MAX_DASHBOARD_SEARCH_LENGTH = 100
LIKE_ESCAPE_CHARACTER = "!"
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


class DashboardQueryValidationError(ValueError):
    """A safe validation error that never reflects the supplied query value."""


def normalize_literal_prefix(value: str | None) -> str | None:
    """Normalize a present search term without granting SQL wildcard semantics."""

    if value is None:
        return None
    if type(value) is not str:
        raise DashboardQueryValidationError("invalid dashboard search")
    normalized = unicodedata.normalize("NFC", value.strip(" "))
    if not normalized or len(normalized) > MAX_DASHBOARD_SEARCH_LENGTH:
        raise DashboardQueryValidationError("invalid dashboard search")
    if any(unicodedata.category(character) in _FORBIDDEN_CATEGORIES for character in normalized):
        raise DashboardQueryValidationError("invalid dashboard search")
    return normalized


def parse_canonical_rule_key(value: str | None) -> str | None:
    """Validate an exact optional rule key through the detection-rule contract."""

    if value is None:
        return None
    try:
        return validate_rule_key(value)
    except RuleKeyValidationError:
        raise DashboardQueryValidationError("invalid dashboard rule key") from None


def literal_prefix_pattern(value: str) -> str:
    """Escape !, %, and _ before appending the only trusted LIKE wildcard."""

    escaped = (
        value.replace(LIKE_ESCAPE_CHARACTER, LIKE_ESCAPE_CHARACTER * 2)
        .replace("%", f"{LIKE_ESCAPE_CHARACTER}%")
        .replace("_", f"{LIKE_ESCAPE_CHARACTER}_")
    )
    return f"{escaped}%"


def parse_canonical_uuid(value: str | None) -> UUID | None:
    """Parse only lowercase canonical UUID text used by exact Dashboard filters."""

    if value is None or value == "":
        return None
    if type(value) is not str:
        raise DashboardQueryValidationError("invalid dashboard identifier")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise DashboardQueryValidationError("invalid dashboard identifier") from error
    if str(parsed) != value:
        raise DashboardQueryValidationError("invalid dashboard identifier")
    return parsed
