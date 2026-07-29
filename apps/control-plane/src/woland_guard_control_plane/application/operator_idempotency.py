"""Shared operator-scoped durable idempotency primitives."""

import hashlib
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from woland_guard_control_plane.infrastructure.database.models import (
    OperatorIdempotencyRecord,
)


def acquire_operator_idempotency_lock(
    session: Session,
    *,
    operator_id: UUID,
    idempotency_key: str,
) -> None:
    """Serialize one operator/key scope for the duration of its transaction."""

    material = f"{operator_id}:{idempotency_key}".encode()
    lock_key = int.from_bytes(hashlib.sha256(material).digest()[:8], "big", signed=True)
    session.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": lock_key})


def load_operator_idempotency_record(
    session: Session,
    *,
    operator_id: UUID,
    idempotency_key: str,
) -> OperatorIdempotencyRecord | None:
    """Load a completed outcome after its advisory lock has been acquired."""

    return session.scalar(
        select(OperatorIdempotencyRecord).where(
            OperatorIdempotencyRecord.operator_id == operator_id,
            OperatorIdempotencyRecord.idempotency_key == idempotency_key,
        )
    )


def store_operator_idempotency_record(
    session: Session,
    *,
    operator_id: UUID,
    idempotency_key: str,
    operation: str,
    resource_id: UUID,
    canonical_request_hash: str,
    response_status: int,
    response_body: dict[str, Any],
) -> OperatorIdempotencyRecord:
    """Persist one allowlisted business outcome in the caller-owned transaction."""

    record = OperatorIdempotencyRecord(
        operator_id=operator_id,
        idempotency_key=idempotency_key,
        operation=operation,
        resource_id=resource_id,
        canonical_request_hash=canonical_request_hash,
        response_status=response_status,
        response_body=response_body,
    )
    session.add(record)
    session.flush()
    return record
