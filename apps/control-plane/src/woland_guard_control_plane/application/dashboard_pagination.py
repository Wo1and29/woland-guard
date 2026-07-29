"""Route-bound, strictly validated keyset cursors for Dashboard lists."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

MAX_DASHBOARD_CURSOR_LENGTH = 1024
DASHBOARD_PAGE_SIZES = frozenset({25, 50, 100})
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_FIELDS = frozenset({"filters", "keys", "list", "page_size", "search", "sort", "v"})

CursorKey = str | int | UUID | datetime
FilterValue = str | int | bool | None | list[str]


class DashboardListType(StrEnum):
    SERVERS = "servers"
    INCIDENTS = "incidents"
    RULES = "rules"
    AUDIT = "audit"
    EVIDENCE = "evidence"
    INCIDENT_HISTORY = "incident_history"
    INCIDENT_COMMENTS = "incident_comments"


_SORTS: dict[DashboardListType, frozenset[str]] = {
    DashboardListType.SERVERS: frozenset({"name_asc", "name_desc"}),
    DashboardListType.INCIDENTS: frozenset({"created_asc", "created_desc"}),
    DashboardListType.RULES: frozenset({"rule_key_asc", "rule_key_desc"}),
    DashboardListType.AUDIT: frozenset({"created_asc", "created_desc"}),
    DashboardListType.EVIDENCE: frozenset({"linked_asc"}),
    DashboardListType.INCIDENT_HISTORY: frozenset({"version_asc"}),
    DashboardListType.INCIDENT_COMMENTS: frozenset({"created_desc"}),
}
_KEY_TYPES: dict[DashboardListType, tuple[str, ...]] = {
    DashboardListType.SERVERS: ("text", "uuid"),
    DashboardListType.INCIDENTS: ("datetime", "uuid"),
    DashboardListType.RULES: ("text", "uuid"),
    DashboardListType.AUDIT: ("datetime", "uuid"),
    DashboardListType.EVIDENCE: ("datetime", "uuid"),
    DashboardListType.INCIDENT_HISTORY: ("integer",),
    DashboardListType.INCIDENT_COMMENTS: ("datetime", "uuid"),
}


class DashboardCursorValidationError(ValueError):
    """A safe error for every malformed or context-mismatched cursor."""


@dataclass(frozen=True, slots=True)
class DashboardCursorContext:
    list_type: DashboardListType
    filters: Mapping[str, FilterValue]
    search: str | None
    sort: str
    page_size: int

    def validate(self) -> None:
        if self.sort not in _SORTS[self.list_type]:
            raise ValueError("unsupported dashboard sort")
        if type(self.page_size) is not int or self.page_size not in DASHBOARD_PAGE_SIZES:
            raise ValueError("unsupported dashboard page size")
        _validate_filters(self.filters)
        if self.search is not None and type(self.search) is not str:
            raise ValueError("invalid dashboard search context")


@dataclass(frozen=True, slots=True)
class DashboardPage[T]:
    items: tuple[T, ...]
    next_cursor: str | None


def encode_dashboard_cursor(
    context: DashboardCursorContext,
    *,
    keys: tuple[CursorKey, ...],
) -> str:
    """Encode a canonical cursor; this is not a signature or authorization boundary."""

    context.validate()
    encoded_keys = _encode_keys(context.list_type, keys)
    payload = {
        "filters": dict(context.filters),
        "keys": encoded_keys,
        "list": context.list_type.value,
        "page_size": context.page_size,
        "search": context.search,
        "sort": context.sort,
        "v": 1,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_dashboard_cursor(
    value: str,
    *,
    expected: DashboardCursorContext,
) -> tuple[CursorKey, ...]:
    """Validate every untrusted cursor field and return typed ordering keys."""

    expected.validate()
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_DASHBOARD_CURSOR_LENGTH
        or _BASE64URL_PATTERN.fullmatch(value) is None
    ):
        raise DashboardCursorValidationError("invalid dashboard cursor")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
            raise ValueError("non-canonical encoding")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        canonical_raw = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if canonical_raw != raw:
            raise ValueError("non-canonical cursor JSON")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DashboardCursorValidationError("invalid dashboard cursor") from error
    if not isinstance(payload, dict) or set(payload) != _FIELDS:
        raise DashboardCursorValidationError("invalid dashboard cursor")
    if type(payload["v"]) is not int or payload["v"] != 1:
        raise DashboardCursorValidationError("invalid dashboard cursor")
    if payload["list"] != expected.list_type.value:
        raise DashboardCursorValidationError("invalid dashboard cursor")
    if type(payload["page_size"]) is not int or payload["page_size"] != expected.page_size:
        raise DashboardCursorValidationError("invalid dashboard cursor")
    if payload["sort"] != expected.sort or payload["search"] != expected.search:
        raise DashboardCursorValidationError("invalid dashboard cursor")
    filters = payload["filters"]
    try:
        _validate_filters(filters)
    except ValueError as error:
        raise DashboardCursorValidationError("invalid dashboard cursor") from error
    if filters != dict(expected.filters):
        raise DashboardCursorValidationError("invalid dashboard cursor")
    keys = payload["keys"]
    if not isinstance(keys, list):
        raise DashboardCursorValidationError("invalid dashboard cursor")
    return _decode_keys(expected.list_type, keys)


def _validate_filters(value: object) -> None:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise ValueError("invalid dashboard filters")
    for item in value.values():
        if item is None or type(item) in {str, int, bool}:
            continue
        if isinstance(item, list) and all(type(part) is str for part in item):
            continue
        raise ValueError("invalid dashboard filters")


def _encode_keys(list_type: DashboardListType, keys: tuple[CursorKey, ...]) -> list[str | int]:
    expected_types = _KEY_TYPES[list_type]
    if len(keys) != len(expected_types):
        raise ValueError("invalid dashboard ordering keys")
    encoded: list[str | int] = []
    for kind, value in zip(expected_types, keys, strict=True):
        if kind == "text" and type(value) is str:
            encoded.append(value)
        elif kind == "uuid" and isinstance(value, UUID):
            encoded.append(str(value))
        elif kind == "datetime" and isinstance(value, datetime):
            encoded.append(_utc_text(value))
        elif kind == "integer" and type(value) is int and value > 0:
            encoded.append(value)
        else:
            raise ValueError("invalid dashboard ordering keys")
    return encoded


def _decode_keys(list_type: DashboardListType, keys: list[Any]) -> tuple[CursorKey, ...]:
    expected_types = _KEY_TYPES[list_type]
    if len(keys) != len(expected_types):
        raise DashboardCursorValidationError("invalid dashboard cursor")
    decoded: list[CursorKey] = []
    for kind, value in zip(expected_types, keys, strict=True):
        if kind == "integer":
            if type(value) is not int or value <= 0:
                raise DashboardCursorValidationError("invalid dashboard cursor")
            decoded.append(value)
            continue
        if type(value) is not str:
            raise DashboardCursorValidationError("invalid dashboard cursor")
        if kind == "text":
            decoded.append(value)
        elif kind == "uuid":
            try:
                parsed = UUID(value)
            except ValueError as error:
                raise DashboardCursorValidationError("invalid dashboard cursor") from error
            if str(parsed) != value:
                raise DashboardCursorValidationError("invalid dashboard cursor")
            decoded.append(parsed)
        else:
            decoded.append(_parse_utc(value))
    return tuple(decoded)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dashboard cursor timestamps require timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise DashboardCursorValidationError("invalid dashboard cursor")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        raise DashboardCursorValidationError("invalid dashboard cursor") from error
    if _utc_text(parsed) != value:
        raise DashboardCursorValidationError("invalid dashboard cursor")
    return parsed.astimezone(UTC)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate cursor field")
        result[key] = value
    return result
