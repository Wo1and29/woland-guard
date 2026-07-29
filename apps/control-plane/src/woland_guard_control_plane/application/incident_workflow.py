"""Versioned incident transitions with durable operator-scoped idempotency."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import record_operator_action
from woland_guard_control_plane.application.operator_idempotency import (
    acquire_operator_idempotency_lock,
    load_operator_idempotency_record,
    store_operator_idempotency_record,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.infrastructure.database.models import (
    HistoryEntryType,
    Incident,
    IncidentHistoryEntry,
    IncidentStatus,
)

IDEMPOTENCY_OPERATION = "incident.status.transition.v1"
IDEMPOTENCY_REPLAY_HEADER = "Idempotency-Replayed"
_IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TERMINAL_STATUSES = frozenset({IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value})
_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    IncidentStatus.NEW.value: frozenset(
        {
            IncidentStatus.INVESTIGATING.value,
            IncidentStatus.RESOLVED.value,
            IncidentStatus.FALSE_POSITIVE.value,
        }
    ),
    IncidentStatus.INVESTIGATING.value: _TERMINAL_STATUSES,
    IncidentStatus.RESOLVED.value: frozenset(),
    IncidentStatus.FALSE_POSITIVE.value: frozenset(),
}


class TransitionValidationError(ValueError):
    """A safe syntactic transition request error handled before idempotency begins."""


@dataclass(frozen=True, slots=True)
class NormalizedTransition:
    target_status: IncidentStatus
    expected_version: int
    reason: str | None


@dataclass(frozen=True, slots=True)
class TransitionOutcome:
    http_status: int
    response_body: dict[str, Any]
    replayed: bool = False
    conflict_type: str | None = None


def normalize_transition(
    *,
    target_status: IncidentStatus,
    expected_version: int,
    reason: str | None,
) -> NormalizedTransition:
    """Validate and normalize client-controlled fields before starting idempotency."""

    if expected_version < 1 or expected_version > 2_147_483_647:
        raise TransitionValidationError("expected_version is outside the allowed range")
    normalized_reason = normalize_reason(reason)
    if target_status.value in _TERMINAL_STATUSES and normalized_reason is None:
        raise TransitionValidationError("reason is required for a terminal status")
    return NormalizedTransition(target_status, expected_version, normalized_reason)


def normalize_reason(reason: str | None) -> str | None:
    """Reject unsafe raw code points before removing only ordinary edge spaces."""

    if reason is None:
        return None
    _reject_prohibited_reason_characters(reason)
    normalized = unicodedata.normalize("NFC", reason.strip(" "))
    _reject_prohibited_reason_characters(normalized)
    if not 1 <= len(normalized) <= 1_000:
        raise TransitionValidationError("reason must contain 1 to 1000 characters")
    return normalized


def validate_idempotency_key(value: str) -> str:
    if _IDEMPOTENCY_KEY_PATTERN.fullmatch(value) is None:
        raise TransitionValidationError("invalid Idempotency-Key")
    return value


def is_transition_allowed(current_status: IncidentStatus, target_status: IncidentStatus) -> bool:
    """Return the single authoritative finite-state-machine decision."""

    return target_status.value in _ALLOWED_TRANSITIONS[current_status.value]


def allowed_transition_targets(current_status: IncidentStatus) -> tuple[IncidentStatus, ...]:
    """Expose the authoritative state machine in stable enum order for HTML forms."""

    allowed = _ALLOWED_TRANSITIONS[current_status.value]
    return tuple(status for status in IncidentStatus if status.value in allowed)


def canonical_transition_hash(incident_id: UUID, transition: NormalizedTransition) -> str:
    canonical = {
        "expected_version": transition.expected_version,
        "incident_id": str(incident_id),
        "operation": IDEMPOTENCY_OPERATION,
        "reason": transition.reason,
        "status": transition.target_status.value,
    }
    serialized = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def transition_incident(
    session: Session,
    *,
    actor: OperatorPrincipal,
    incident_id: UUID,
    transition: NormalizedTransition,
    idempotency_key: str,
    canonical_request_hash: str,
    request_id: str,
    now: datetime | None = None,
) -> TransitionOutcome:
    """Evaluate and persist one completed outcome inside a caller-owned transaction."""

    acquire_operator_idempotency_lock(
        session,
        operator_id=actor.operator_id,
        idempotency_key=idempotency_key,
    )
    existing = load_operator_idempotency_record(
        session,
        operator_id=actor.operator_id,
        idempotency_key=idempotency_key,
    )
    if existing is not None:
        if existing.canonical_request_hash == canonical_request_hash:
            return TransitionOutcome(
                http_status=existing.response_status,
                response_body=dict(existing.response_body),
                replayed=True,
                conflict_type=_stored_conflict_type(existing.response_body),
            )
        return TransitionOutcome(
            http_status=409,
            response_body={"detail": "Idempotency-Key was already used for another request"},
            conflict_type="idempotency_key_reused",
        )

    incident = session.scalar(select(Incident).where(Incident.id == incident_id).with_for_update())
    if incident is None:
        return _store_outcome(
            session,
            actor=actor,
            incident_id=incident_id,
            idempotency_key=idempotency_key,
            canonical_request_hash=canonical_request_hash,
            http_status=404,
            response_body={"detail": "incident not found", "conflict_type": "not_found"},
            conflict_type="not_found",
        )
    if incident.lock_version != transition.expected_version:
        return _store_outcome(
            session,
            actor=actor,
            incident_id=incident_id,
            idempotency_key=idempotency_key,
            canonical_request_hash=canonical_request_hash,
            http_status=409,
            response_body={
                "detail": "incident version conflict",
                "conflict_type": "stale_version",
                "current_version": incident.lock_version,
            },
            conflict_type="stale_version",
        )
    if not is_transition_allowed(IncidentStatus(incident.status), transition.target_status):
        return _store_outcome(
            session,
            actor=actor,
            incident_id=incident_id,
            idempotency_key=idempotency_key,
            canonical_request_hash=canonical_request_hash,
            http_status=409,
            response_body={
                "detail": "incident status transition is not allowed",
                "conflict_type": "transition_not_allowed",
            },
            conflict_type="transition_not_allowed",
        )

    changed_at = (now or datetime.now(UTC)).astimezone(UTC)
    previous_status = incident.status
    next_version = incident.lock_version + 1
    incident.status = transition.target_status.value
    incident.lock_version = next_version
    incident.updated_at = changed_at
    history = IncidentHistoryEntry(
        incident_id=incident.id,
        version=next_version,
        entry_type=HistoryEntryType.STATUS_TRANSITION.value,
        from_status=previous_status,
        to_status=incident.status,
        reason=transition.reason,
        changed_by_operator_id=actor.operator_id,
        actor_username_snapshot=actor.username,
        auth_method_type=actor.auth_method_type.value,
        auth_method_id=actor.auth_method_id,
        request_id=request_id,
        created_at=changed_at,
    )
    session.add(history)
    session.flush()
    record_operator_action(
        session,
        actor=actor,
        action="incident.status_changed",
        target_type="incident",
        target_id=incident.id,
        request_id=request_id,
        incident_history_id=history.id,
        details={
            "from_status": previous_status,
            "from_version": next_version - 1,
            "history_id": str(history.id),
            "to_status": incident.status,
            "to_version": next_version,
        },
    )
    response_body = {
        "incident": _incident_snapshot(incident),
        "transition": _history_snapshot(history),
    }
    return _store_outcome(
        session,
        actor=actor,
        incident_id=incident_id,
        idempotency_key=idempotency_key,
        canonical_request_hash=canonical_request_hash,
        http_status=200,
        response_body=response_body,
    )


def add_baseline_history(session: Session, incident: Incident) -> IncidentHistoryEntry:
    """Attach the immutable version-one state to a newly flushed incident."""

    baseline = IncidentHistoryEntry(
        incident_id=incident.id,
        version=1,
        entry_type=HistoryEntryType.BASELINE.value,
        from_status=None,
        to_status=incident.status,
        reason=None,
        changed_by_operator_id=None,
        actor_username_snapshot=None,
        auth_method_type=None,
        auth_method_id=None,
        request_id=None,
        created_at=incident.created_at,
    )
    session.add(baseline)
    return baseline


def _reject_prohibited_reason_characters(value: str) -> None:
    prohibited_categories = {"Cc", "Cf", "Cs", "Zl", "Zp"}
    if any(unicodedata.category(character) in prohibited_categories for character in value):
        raise TransitionValidationError("reason contains a prohibited Unicode character")


def _store_outcome(
    session: Session,
    *,
    actor: OperatorPrincipal,
    incident_id: UUID,
    idempotency_key: str,
    canonical_request_hash: str,
    http_status: int,
    response_body: dict[str, Any],
    conflict_type: str | None = None,
) -> TransitionOutcome:
    store_operator_idempotency_record(
        session,
        operator_id=actor.operator_id,
        idempotency_key=idempotency_key,
        operation=IDEMPOTENCY_OPERATION,
        resource_id=incident_id,
        canonical_request_hash=canonical_request_hash,
        response_status=http_status,
        response_body=response_body,
    )
    return TransitionOutcome(http_status, response_body, conflict_type=conflict_type)


def _incident_snapshot(incident: Incident) -> dict[str, Any]:
    return {
        "created_at": incident.created_at.isoformat(),
        "event_count": incident.event_count,
        "first_seen_at": incident.first_seen_at.isoformat(),
        "id": str(incident.id),
        "last_seen_at": incident.last_seen_at.isoformat(),
        "rule_key": incident.rule_key,
        "rule_version": incident.rule_version,
        "server_id": str(incident.server_id),
        "severity": incident.severity,
        "status": incident.status,
        "title": incident.title,
        "updated_at": incident.updated_at.isoformat(),
        "version": incident.lock_version,
    }


def _history_snapshot(history: IncidentHistoryEntry) -> dict[str, Any]:
    return {
        "created_at": history.created_at.isoformat(),
        "from_status": history.from_status,
        "id": str(history.id),
        "operator_id": str(history.changed_by_operator_id),
        "operator_username": history.actor_username_snapshot,
        "reason": history.reason,
        "to_status": history.to_status,
        "version": history.version,
    }


def _stored_conflict_type(response_body: dict[str, Any]) -> str | None:
    value = response_body.get("conflict_type")
    return value if isinstance(value, str) else None
