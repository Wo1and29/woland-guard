"""Strict cursor and normalized filter hashing tests."""

import base64
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from woland_guard_control_plane.application.pagination import (
    MAX_CURSOR_LENGTH,
    CursorValidationError,
    decode_cursor,
    encode_cursor,
    normalized_filter_hash,
)

_ROW_ID = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
_CREATED_AT = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


def _encoded(payload: object) -> str:
    return _encoded_raw(json.dumps(payload, separators=(",", ":")))


def _encoded_raw(payload: str) -> str:
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def test_cursor_round_trip_is_bound_to_normalized_filter_hash() -> None:
    filter_hash = normalized_filter_hash({"statuses": ["new", "new", "investigating"]})
    cursor = encode_cursor(created_at=_CREATED_AT, row_id=_ROW_ID, filter_hash=filter_hash)

    decoded = decode_cursor(cursor, expected_filter_hash=filter_hash)

    assert decoded.created_at == _CREATED_AT
    assert decoded.row_id == _ROW_ID
    assert "=" not in cursor


def test_filter_hash_sorts_and_deduplicates_repeated_values() -> None:
    assert normalized_filter_hash({"status": ["new", "resolved", "new"]}) == (
        normalized_filter_hash({"status": ["resolved", "new"]})
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "!not-base64url!",
        "a" * (MAX_CURSOR_LENGTH + 1),
        _encoded([]),
        _encoded({"v": 1, "created_at": "2026-07-22T12:00:00Z"}),
        _encoded(
            {
                "v": 1,
                "created_at": "2026-07-22T12:00:00Z",
                "id": str(_ROW_ID),
                "filter_hash": "a" * 64,
                "extra": "rejected",
            }
        ),
        _encoded(
            {
                "v": True,
                "created_at": "2026-07-22T12:00:00Z",
                "id": str(_ROW_ID),
                "filter_hash": "a" * 64,
            }
        ),
        _encoded(
            {
                "v": 2,
                "created_at": "2026-07-22T12:00:00Z",
                "id": str(_ROW_ID),
                "filter_hash": "a" * 64,
            }
        ),
        _encoded(
            {
                "v": 1,
                "created_at": "2026-07-22T12:00:00+00:00",
                "id": str(_ROW_ID),
                "filter_hash": "a" * 64,
            }
        ),
        _encoded(
            {
                "v": 1,
                "created_at": "2026-07-22T12:00:00Z",
                "id": str(_ROW_ID).upper(),
                "filter_hash": "a" * 64,
            }
        ),
        _encoded_raw(
            '{"v":1,"v":1,"created_at":"2026-07-22T12:00:00Z",'
            f'"id":"{_ROW_ID}","filter_hash":"{"a" * 64}"}}'
        ),
    ],
)
def test_cursor_rejects_malformed_untrusted_input(value: str) -> None:
    with pytest.raises(CursorValidationError, match="^invalid cursor$"):
        decode_cursor(value, expected_filter_hash="a" * 64)


def test_cursor_rejects_another_filter_set_without_echoing_input() -> None:
    cursor = encode_cursor(created_at=_CREATED_AT, row_id=_ROW_ID, filter_hash="a" * 64)
    with pytest.raises(CursorValidationError) as error:
        decode_cursor(cursor, expected_filter_hash="b" * 64)
    assert cursor not in str(error.value)
