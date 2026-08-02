"""Round-trip and adversarial-input coverage for incident-action callback_data."""

from __future__ import annotations

from uuid import UUID

import pytest

from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
from woland_guard_control_plane.infrastructure.telegram.callbacks import (
    CALLBACK_DATA_MAX_BYTES,
    CallbackDataError,
    encode_incident_action,
    parse_incident_action,
)

INCIDENT_ID = UUID("11111111-1111-4111-8111-111111111111")


@pytest.mark.parametrize(
    "status",
    [IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE],
)
def test_round_trip_recovers_the_original_values(status: IncidentStatus) -> None:
    encoded = encode_incident_action(
        incident_id=INCIDENT_ID,
        target_status=status,
        expected_version=7,
    )
    decoded = parse_incident_action(encoded)

    assert decoded.incident_id == INCIDENT_ID
    assert decoded.target_status is status
    assert decoded.expected_version == 7


def test_encoded_value_fits_the_telegram_button_limit() -> None:
    encoded = encode_incident_action(
        incident_id=INCIDENT_ID,
        target_status=IncidentStatus.FALSE_POSITIVE,
        expected_version=2_147_483_647,
    )
    assert len(encoded.encode("ascii")) <= CALLBACK_DATA_MAX_BYTES


def test_encoding_rejects_a_status_with_no_button() -> None:
    with pytest.raises(CallbackDataError):
        encode_incident_action(
            incident_id=INCIDENT_ID,
            target_status=IncidentStatus.NEW,
            expected_version=1,
        )


@pytest.mark.parametrize("version", [0, -1, 2_147_483_648])
def test_encoding_rejects_versions_outside_the_contract(version: int) -> None:
    with pytest.raises(CallbackDataError):
        encode_incident_action(
            incident_id=INCIDENT_ID,
            target_status=IncidentStatus.INVESTIGATING,
            expected_version=version,
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "1:iv",
        "1:iv:11111111-1111-4111-8111-111111111111",
        "1:iv:11111111-1111-4111-8111-111111111111:1:extra",
        "2:iv:11111111-1111-4111-8111-111111111111:1",
        "1:xx:11111111-1111-4111-8111-111111111111:1",
        "1:iv:not-a-uuid:1",
        "1:iv:11111111111141118111111111111111:1",  # missing dashes, not canonical
        "1:iv:11111111-1111-4111-8111-111111111111:0",
        "1:iv:11111111-1111-4111-8111-111111111111:01",  # leading zero
        "1:iv:11111111-1111-4111-8111-111111111111:-1",
        "1:iv:11111111-1111-4111-8111-111111111111:2147483648",
        "1:iv:11111111-1111-4111-8111-111111111111:abc",
        "1:iv:11111111-1111-4111-8111-111111111111: 1",
        "1::11111111-1111-4111-8111-111111111111:1",
    ],
)
def test_parsing_rejects_anything_outside_the_closed_contract(value: str) -> None:
    with pytest.raises(CallbackDataError):
        parse_incident_action(value)


def test_parsing_rejects_an_oversized_value() -> None:
    with pytest.raises(CallbackDataError):
        parse_incident_action("1:iv:" + "1" * 200)


def test_encoding_and_parsing_agree_on_the_action_codes() -> None:
    """Every closed button action must round-trip through the same code table."""

    for status in (
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    ):
        encoded = encode_incident_action(
            incident_id=INCIDENT_ID,
            target_status=status,
            expected_version=1,
        )
        assert parse_incident_action(encoded).target_status is status
