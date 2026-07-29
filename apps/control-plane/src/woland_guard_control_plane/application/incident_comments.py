"""Normalized, auditable and idempotent incident comments."""

from __future__ import annotations

import hashlib
import json
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
from woland_guard_control_plane.infrastructure.database.models import Incident, IncidentComment

COMMENT_IDEMPOTENCY_OPERATION = "incident.comment.create.v1"
MAX_COMMENT_LENGTH = 1_000


class CommentValidationError(ValueError):
    """A safe comment validation error that never contains submitted text."""


@dataclass(frozen=True, slots=True)
class NormalizedComment:
    body: str


@dataclass(frozen=True, slots=True)
class CommentOutcome:
    http_status: int
    response_body: dict[str, Any]
    replayed: bool = False
    conflict_type: str | None = None


def normalize_comment(value: str) -> NormalizedComment:
    """Canonicalize browser line endings and reject unsafe Unicode."""

    if type(value) is not str:
        raise CommentValidationError("comment is invalid")
    _reject_comment_characters(value, allow_browser_line_endings=True)
    canonical_lines = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = unicodedata.normalize("NFC", canonical_lines).strip()
    _reject_comment_characters(normalized, allow_browser_line_endings=False)
    if not 1 <= len(normalized) <= MAX_COMMENT_LENGTH:
        raise CommentValidationError("comment length is invalid")
    return NormalizedComment(normalized)


def canonical_comment_hash(incident_id: UUID, comment: NormalizedComment) -> str:
    canonical = {
        "comment": comment.body,
        "incident_id": str(incident_id),
        "operation": COMMENT_IDEMPOTENCY_OPERATION,
    }
    serialized = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def add_incident_comment(
    session: Session,
    *,
    actor: OperatorPrincipal,
    incident_id: UUID,
    comment: NormalizedComment,
    idempotency_key: str,
    canonical_request_hash: str,
    request_id: str,
    now: datetime | None = None,
) -> CommentOutcome:
    """Create or replay one comment outcome inside a caller-owned transaction."""

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
        if (
            existing.operation == COMMENT_IDEMPOTENCY_OPERATION
            and existing.canonical_request_hash == canonical_request_hash
        ):
            return CommentOutcome(
                http_status=existing.response_status,
                response_body=dict(existing.response_body),
                replayed=True,
                conflict_type=_stored_conflict_type(existing.response_body),
            )
        return CommentOutcome(
            http_status=409,
            response_body={"detail": "Idempotency-Key was already used for another request"},
            conflict_type="idempotency_key_reused",
        )

    incident_exists = session.scalar(select(Incident.id).where(Incident.id == incident_id))
    if incident_exists is None:
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

    created_at = (now or datetime.now(UTC)).astimezone(UTC)
    stored = IncidentComment(
        incident_id=incident_id,
        operator_id=actor.operator_id,
        actor_username_snapshot=actor.username,
        auth_method_type=actor.auth_method_type.value,
        auth_method_id=actor.auth_method_id,
        request_id=request_id,
        body=comment.body,
        created_at=created_at,
    )
    session.add(stored)
    session.flush()
    record_operator_action(
        session,
        actor=actor,
        action="incident.comment_added",
        target_type="incident_comment",
        target_id=stored.id,
        request_id=request_id,
        incident_history_id=None,
        details={"incident_id": str(incident_id)},
    )
    return _store_outcome(
        session,
        actor=actor,
        incident_id=incident_id,
        idempotency_key=idempotency_key,
        canonical_request_hash=canonical_request_hash,
        http_status=200,
        response_body={
            "comment_id": str(stored.id),
            "created_at": stored.created_at.isoformat(),
            "incident_id": str(incident_id),
        },
    )


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
) -> CommentOutcome:
    store_operator_idempotency_record(
        session,
        operator_id=actor.operator_id,
        idempotency_key=idempotency_key,
        operation=COMMENT_IDEMPOTENCY_OPERATION,
        resource_id=incident_id,
        canonical_request_hash=canonical_request_hash,
        response_status=http_status,
        response_body=response_body,
    )
    return CommentOutcome(http_status, response_body, conflict_type=conflict_type)


def _stored_conflict_type(response_body: dict[str, Any]) -> str | None:
    value = response_body.get("conflict_type")
    return value if isinstance(value, str) else None


def _reject_comment_characters(value: str, *, allow_browser_line_endings: bool) -> None:
    for character in value:
        if character in {"\r", "\n"} and allow_browser_line_endings:
            continue
        if character == "\n" and not allow_browser_line_endings:
            continue
        if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            raise CommentValidationError("comment contains a prohibited Unicode character")
