"""Closed, bounded encoding for inline-keyboard callback_data.

Telegram returns whatever callback_data the client sends back verbatim, so a
received value is untrusted input, not a value we can assume originated from a
button we built. Encoding and parsing are versioned and symmetric; anything
that fails to parse is rejected as a whole rather than partially accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from uuid import UUID

from woland_guard_control_plane.infrastructure.database.models import IncidentStatus

CALLBACK_DATA_MAX_BYTES: Final = 64
_SCHEMA_VERSION: Final = "1"
_MAX_EXPECTED_VERSION: Final = 2_147_483_647
_ACTION_CODES: Final[dict[IncidentStatus, str]] = {
    IncidentStatus.INVESTIGATING: "iv",
    IncidentStatus.RESOLVED: "rs",
    IncidentStatus.FALSE_POSITIVE: "fp",
}
_STATUS_BY_CODE: Final[dict[str, IncidentStatus]] = {
    code: status for status, code in _ACTION_CODES.items()
}
_PROPOSE_BLOCK_CODE: Final = "bp"
_APPROVE_BLOCK_CODE: Final = "ba"
_REJECT_BLOCK_CODE: Final = "br"


class CallbackDataError(ValueError):
    """A safe rejection of one malformed or out-of-contract callback_data value."""


@dataclass(frozen=True, slots=True)
class IncidentActionCallback:
    """One closed incident status-transition request encoded on a button."""

    incident_id: UUID
    target_status: IncidentStatus
    expected_version: int


@dataclass(frozen=True, slots=True)
class ProposeBlockCallback:
    """One request to propose blocking an incident's correlated source address."""

    incident_id: UUID


@dataclass(frozen=True, slots=True)
class DecideBlockCallback:
    """One request to approve or reject an existing, still-live block plan."""

    plan_id: UUID
    approve: bool


CallbackAction = IncidentActionCallback | ProposeBlockCallback | DecideBlockCallback


def encode_incident_action(
    *,
    incident_id: UUID,
    target_status: IncidentStatus,
    expected_version: int,
) -> str:
    """Build one bounded callback_data value for an outgoing keyboard button."""

    code = _ACTION_CODES.get(target_status)
    if code is None:
        raise CallbackDataError("incident action callback status is not a button action")
    if not 1 <= expected_version <= _MAX_EXPECTED_VERSION:
        raise CallbackDataError("incident action callback version is out of range")
    value = f"{_SCHEMA_VERSION}:{code}:{incident_id}:{expected_version}"
    if len(value.encode("ascii")) > CALLBACK_DATA_MAX_BYTES:
        raise CallbackDataError("incident action callback exceeds the Telegram size limit")
    return value


def parse_incident_action(value: str) -> IncidentActionCallback:
    """Parse one callback_data value, rejecting anything outside the closed contract."""

    if len(value.encode("utf-8")) > CALLBACK_DATA_MAX_BYTES:
        raise CallbackDataError("incident action callback exceeds the Telegram size limit")
    parts = value.split(":")
    if len(parts) != 4:
        raise CallbackDataError("incident action callback shape is invalid")
    schema_version, code, raw_incident_id, raw_expected_version = parts
    if schema_version != _SCHEMA_VERSION:
        raise CallbackDataError("incident action callback schema version is unsupported")
    target_status = _STATUS_BY_CODE.get(code)
    if target_status is None:
        raise CallbackDataError("incident action callback action code is unknown")
    try:
        incident_id = UUID(raw_incident_id)
    except ValueError:
        raise CallbackDataError("incident action callback incident id is invalid") from None
    if str(incident_id) != raw_incident_id:
        raise CallbackDataError("incident action callback incident id is not canonical")
    if (
        not raw_expected_version.isdecimal()
        or raw_expected_version.startswith("0")
        or len(raw_expected_version) > 10
    ):
        raise CallbackDataError("incident action callback version is invalid")
    expected_version = int(raw_expected_version)
    if not 1 <= expected_version <= _MAX_EXPECTED_VERSION:
        raise CallbackDataError("incident action callback version is out of range")
    return IncidentActionCallback(
        incident_id=incident_id,
        target_status=target_status,
        expected_version=expected_version,
    )


def encode_propose_block(*, incident_id: UUID) -> str:
    """Build one bounded callback_data value for the "propose an IP block" button."""

    value = f"{_SCHEMA_VERSION}:{_PROPOSE_BLOCK_CODE}:{incident_id}"
    if len(value.encode("ascii")) > CALLBACK_DATA_MAX_BYTES:
        raise CallbackDataError("block proposal callback exceeds the Telegram size limit")
    return value


def encode_decide_block(*, plan_id: UUID, approve: bool) -> str:
    """Build one bounded callback_data value for an approve/reject decision button."""

    code = _APPROVE_BLOCK_CODE if approve else _REJECT_BLOCK_CODE
    value = f"{_SCHEMA_VERSION}:{code}:{plan_id}"
    if len(value.encode("ascii")) > CALLBACK_DATA_MAX_BYTES:
        raise CallbackDataError("block decision callback exceeds the Telegram size limit")
    return value


def parse_block_action(value: str) -> ProposeBlockCallback | DecideBlockCallback:
    """Parse one propose/approve/reject callback_data value as untrusted input."""

    if len(value.encode("utf-8")) > CALLBACK_DATA_MAX_BYTES:
        raise CallbackDataError("block action callback exceeds the Telegram size limit")
    parts = value.split(":")
    if len(parts) != 3:
        raise CallbackDataError("block action callback shape is invalid")
    schema_version, code, raw_id = parts
    if schema_version != _SCHEMA_VERSION:
        raise CallbackDataError("block action callback schema version is unsupported")
    try:
        parsed_id = UUID(raw_id)
    except ValueError:
        raise CallbackDataError("block action callback identifier is invalid") from None
    if str(parsed_id) != raw_id:
        raise CallbackDataError("block action callback identifier is not canonical")
    if code == _PROPOSE_BLOCK_CODE:
        return ProposeBlockCallback(incident_id=parsed_id)
    if code == _APPROVE_BLOCK_CODE:
        return DecideBlockCallback(plan_id=parsed_id, approve=True)
    if code == _REJECT_BLOCK_CODE:
        return DecideBlockCallback(plan_id=parsed_id, approve=False)
    raise CallbackDataError("block action callback action code is unknown")


def parse_callback_data(value: str) -> CallbackAction:
    """Dispatch one callback_data value to its closed parser by action code.

    The two callback families use a different number of colon-separated parts
    (four for an incident status transition, three for a block proposal or
    decision), so the code segment alone -- read without assuming the rest of
    the shape is well-formed -- is enough to route to the right strict parser.
    """

    parts = value.split(":", 2)
    code = parts[1] if len(parts) >= 2 else ""
    if code in _STATUS_BY_CODE:
        return parse_incident_action(value)
    if code in (_PROPOSE_BLOCK_CODE, _APPROVE_BLOCK_CODE, _REJECT_BLOCK_CODE):
        return parse_block_action(value)
    raise CallbackDataError("callback action code is unknown")
