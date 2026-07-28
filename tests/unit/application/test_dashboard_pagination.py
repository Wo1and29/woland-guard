"""Dashboard cursors are untrusted route-bound input, not integrity tokens."""

import base64
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from woland_guard_control_plane.application.dashboard_pagination import (
    DashboardCursorContext,
    DashboardCursorValidationError,
    DashboardListType,
    decode_dashboard_cursor,
    encode_dashboard_cursor,
)


def _context(
    list_type: DashboardListType = DashboardListType.SERVERS,
    *,
    sort: str = "name_asc",
) -> DashboardCursorContext:
    return DashboardCursorContext(
        list_type=list_type,
        filters={"state": "active"},
        search="same",
        sort=sort,
        page_size=25,
    )


def test_cursor_round_trip_keeps_full_server_ordering_tuple() -> None:
    row_id = UUID("10000000-0000-4000-8000-000000000001")
    cursor = encode_dashboard_cursor(_context(), keys=("same", row_id))
    assert decode_dashboard_cursor(cursor, expected=_context()) == ("same", row_id)


def test_formally_valid_arbitrary_position_is_accepted() -> None:
    row_id = UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")
    cursor = encode_dashboard_cursor(_context(), keys=("arbitrary", row_id))
    assert decode_dashboard_cursor(cursor, expected=_context()) == ("arbitrary", row_id)


@pytest.mark.parametrize("change", ["route", "sort", "filter", "page_size", "search"])
def test_cursor_cannot_cross_request_context(change: str) -> None:
    row_id = UUID("10000000-0000-4000-8000-000000000001")
    cursor = encode_dashboard_cursor(_context(), keys=("same", row_id))
    expected = _context()
    if change == "route":
        expected = DashboardCursorContext(
            DashboardListType.RULES, {"state": "active"}, "same", "rule_key_asc", 25
        )
    elif change == "sort":
        expected = _context(sort="name_desc")
    elif change == "filter":
        expected = DashboardCursorContext(
            DashboardListType.SERVERS, {"state": "inactive"}, "same", "name_asc", 25
        )
    elif change == "page_size":
        expected = DashboardCursorContext(
            DashboardListType.SERVERS, {"state": "active"}, "same", "name_asc", 50
        )
    elif change == "search":
        expected = DashboardCursorContext(
            DashboardListType.SERVERS, {"state": "active"}, "other", "name_asc", 25
        )
    with pytest.raises(DashboardCursorValidationError):
        decode_dashboard_cursor(cursor, expected=expected)


def test_duplicate_json_keys_and_noncanonical_encoding_are_rejected() -> None:
    raw = (
        b'{"filters":{"state":"active"},"keys":["same",'
        b'"10000000-0000-4000-8000-000000000001"],"list":"servers",'
        b'"page_size":25,"search":"same","sort":"name_asc","v":1,"v":1}'
    )
    duplicate = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    with pytest.raises(DashboardCursorValidationError):
        decode_dashboard_cursor(duplicate, expected=_context())

    valid = encode_dashboard_cursor(
        _context(), keys=("same", UUID("10000000-0000-4000-8000-000000000001"))
    )
    with pytest.raises(DashboardCursorValidationError):
        decode_dashboard_cursor(f"{valid}=", expected=_context())

    noncanonical_json = (
        base64.urlsafe_b64encode(
            b'{"v": 1, "sort": "name_asc", "search": "same", "page_size": 25, '
            b'"list": "servers", "keys": ["same", '
            b'"10000000-0000-4000-8000-000000000001"], '
            b'"filters": {"state": "active"}}'
        )
        .decode("ascii")
        .rstrip("=")
    )
    with pytest.raises(DashboardCursorValidationError):
        decode_dashboard_cursor(noncanonical_json, expected=_context())


def test_incident_cursor_requires_utc_datetime_and_uuid_keys() -> None:
    context = DashboardCursorContext(
        DashboardListType.INCIDENTS,
        {"statuses": ["new"]},
        None,
        "created_desc",
        25,
    )
    timestamp = datetime(2026, 7, 28, tzinfo=UTC)
    row_id = UUID("20000000-0000-4000-8000-000000000002")
    cursor = encode_dashboard_cursor(context, keys=(timestamp, row_id))
    assert decode_dashboard_cursor(cursor, expected=context) == (timestamp, row_id)


def test_malformed_ordering_key_type_is_rejected() -> None:
    payload = {
        "filters": {"state": "active"},
        "keys": [7, "10000000-0000-4000-8000-000000000001"],
        "list": "servers",
        "page_size": 25,
        "search": "same",
        "sort": "name_asc",
        "v": 1,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    cursor = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    with pytest.raises(DashboardCursorValidationError):
        decode_dashboard_cursor(cursor, expected=_context())
