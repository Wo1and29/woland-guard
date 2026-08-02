"""Round-trip, dispatch, and adversarial-input coverage for block-action callback_data."""

from __future__ import annotations

from uuid import UUID

import pytest

from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
from woland_guard_control_plane.infrastructure.telegram.callbacks import (
    CALLBACK_DATA_MAX_BYTES,
    CallbackDataError,
    DecideBlockCallback,
    IncidentActionCallback,
    ProposeBlockCallback,
    encode_decide_block,
    encode_incident_action,
    encode_propose_block,
    parse_block_action,
    parse_callback_data,
)

INCIDENT_ID = UUID("11111111-1111-4111-8111-111111111111")
PLAN_ID = UUID("22222222-2222-4222-8222-222222222222")


def test_propose_block_round_trip_recovers_the_incident_id() -> None:
    encoded = encode_propose_block(incident_id=INCIDENT_ID)

    decoded = parse_block_action(encoded)

    assert decoded == ProposeBlockCallback(incident_id=INCIDENT_ID)
    assert len(encoded.encode("ascii")) <= CALLBACK_DATA_MAX_BYTES


@pytest.mark.parametrize("approve", [True, False])
def test_decide_block_round_trip_recovers_the_plan_id_and_decision(approve: bool) -> None:
    encoded = encode_decide_block(plan_id=PLAN_ID, approve=approve)

    decoded = parse_block_action(encoded)

    assert decoded == DecideBlockCallback(plan_id=PLAN_ID, approve=approve)
    assert len(encoded.encode("ascii")) <= CALLBACK_DATA_MAX_BYTES


def test_approve_and_reject_encode_to_different_values() -> None:
    approve = encode_decide_block(plan_id=PLAN_ID, approve=True)
    reject = encode_decide_block(plan_id=PLAN_ID, approve=False)

    assert approve != reject


def test_dispatcher_routes_every_family_to_its_own_type() -> None:
    incident_action = parse_callback_data(
        encode_incident_action(
            incident_id=INCIDENT_ID,
            target_status=IncidentStatus.INVESTIGATING,
            expected_version=1,
        )
    )
    propose_action = parse_callback_data(encode_propose_block(incident_id=INCIDENT_ID))
    approve_action = parse_callback_data(encode_decide_block(plan_id=PLAN_ID, approve=True))
    reject_action = parse_callback_data(encode_decide_block(plan_id=PLAN_ID, approve=False))

    assert isinstance(incident_action, IncidentActionCallback)
    assert isinstance(propose_action, ProposeBlockCallback)
    assert isinstance(approve_action, DecideBlockCallback)
    assert isinstance(reject_action, DecideBlockCallback)
    assert approve_action.approve is True
    assert reject_action.approve is False


@pytest.mark.parametrize(
    "value",
    [
        "",
        "1:bp",
        "1:bp:11111111-1111-4111-8111-111111111111:extra",
        "2:bp:11111111-1111-4111-8111-111111111111",  # unknown schema version
        "1:zz:11111111-1111-4111-8111-111111111111",  # unknown action code
        "1:bp:not-a-uuid",
        "1:bp:11111111111141118111111111111111",  # missing dashes, not canonical
        "1:ba:22222222-2222-4222-8222-222222222222 ",  # trailing whitespace
        "1::11111111-1111-4111-8111-111111111111",
    ],
)
def test_parse_block_action_rejects_anything_outside_the_closed_contract(value: str) -> None:
    with pytest.raises(CallbackDataError):
        parse_block_action(value)


def test_parse_block_action_rejects_an_oversized_value() -> None:
    with pytest.raises(CallbackDataError):
        parse_block_action("1:bp:" + "1" * 200)


def test_parse_block_action_rejects_the_incident_action_shape() -> None:
    """A four-part incident-status value must not be accepted by the block parser."""

    encoded = encode_incident_action(
        incident_id=INCIDENT_ID,
        target_status=IncidentStatus.RESOLVED,
        expected_version=1,
    )
    with pytest.raises(CallbackDataError):
        parse_block_action(encoded)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "no-colon-at-all",
        "1:qq:11111111-1111-4111-8111-111111111111",
        "1:",
    ],
)
def test_dispatcher_rejects_an_unknown_action_code(value: str) -> None:
    with pytest.raises(CallbackDataError):
        parse_callback_data(value)
