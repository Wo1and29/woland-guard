"""Strict opaque keyset cursors for untrusted API query input."""

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

MAX_CURSOR_LENGTH = 1024
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CURSOR_FIELDS = frozenset({"v", "created_at", "id", "filter_hash"})


class CursorValidationError(ValueError):
    """A safe cursor error that never includes the untrusted cursor value."""


@dataclass(frozen=True, slots=True)
class KeysetCursor:
    created_at: datetime
    row_id: UUID
    filter_hash: str


def normalized_filter_hash(filters: dict[str, Any]) -> str:
    """Hash sorted, duplicate-free filter values into a cursor binding."""

    normalized: dict[str, Any] = {}
    for key, value in sorted(filters.items()):
        if isinstance(value, list):
            normalized[key] = sorted(set(value))
        elif isinstance(value, datetime):
            normalized[key] = _utc_text(value)
        elif isinstance(value, UUID):
            normalized[key] = str(value)
        else:
            normalized[key] = value
    serialized = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def encode_cursor(*, created_at: datetime, row_id: UUID, filter_hash: str) -> str:
    if _HASH_PATTERN.fullmatch(filter_hash) is None:
        raise ValueError("filter_hash must be a lowercase SHA-256 hex digest")
    payload = {
        "created_at": _utc_text(created_at),
        "filter_hash": filter_hash,
        "id": str(row_id),
        "v": 1,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(value: str, *, expected_filter_hash: str) -> KeysetCursor:
    if not value or len(value) > MAX_CURSOR_LENGTH or _BASE64URL_PATTERN.fullmatch(value) is None:
        raise CursorValidationError("invalid cursor")
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        if canonical != value:
            raise ValueError("non-canonical base64url")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CursorValidationError("invalid cursor") from error
    if not isinstance(payload, dict) or set(payload) != _CURSOR_FIELDS:
        raise CursorValidationError("invalid cursor")
    if type(payload["v"]) is not int or payload["v"] != 1:
        raise CursorValidationError("invalid cursor")
    filter_hash = payload["filter_hash"]
    if not isinstance(filter_hash, str) or _HASH_PATTERN.fullmatch(filter_hash) is None:
        raise CursorValidationError("invalid cursor")
    if filter_hash != expected_filter_hash:
        raise CursorValidationError("invalid cursor")
    created_at = _parse_utc_timestamp(payload["created_at"])
    row_id = _parse_canonical_uuid(payload["id"])
    return KeysetCursor(created_at, row_id, filter_hash)


def _parse_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CursorValidationError("invalid cursor")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        raise CursorValidationError("invalid cursor") from error
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise CursorValidationError("invalid cursor")
    if _utc_text(parsed) != value:
        raise CursorValidationError("invalid cursor")
    return parsed.astimezone(UTC)


def _parse_canonical_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise CursorValidationError("invalid cursor")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise CursorValidationError("invalid cursor") from error
    if str(parsed) != value:
        raise CursorValidationError("invalid cursor")
    return parsed


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("cursor timestamps must include a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
