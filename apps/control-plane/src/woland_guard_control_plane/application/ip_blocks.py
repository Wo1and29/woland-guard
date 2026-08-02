"""Propose, approve, and reject dry-run IP block plans; nothing here executes.

An ``IpBlockPlan`` row only ever records what an operator proposed and what a
second operator decided about it. No process in the control plane ever runs
``command_argv`` -- that is the explicit boundary of stage 9C. Execution, if it
is ever added, is a separate pull-based agent capability (stage 9D) gated by
its own independent configuration.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import ip_network
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import (
    record_local_cli_action,
    record_operator_action,
)
from woland_guard_control_plane.application.ip_block_policy import (
    BlockTargetRejectionReason,
    build_nft_block_command,
    classify_block_target,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.infrastructure.database.models import (
    Incident,
    IpBlockAllowlistEntry,
    IpBlockPlan,
)

_PROPOSED = "proposed"
_APPROVED = "approved"
_REJECTED = "rejected"


class IpBlockError(ValueError):
    """A safe validation or lifecycle conflict for IP block plans and allowlist entries."""


class ProposeIpBlockStatus(StrEnum):
    """Closed outcome of one propose request; only CREATED and REUSED persist a plan."""

    CREATED = "created"
    REUSED = "reused"
    INCIDENT_NOT_FOUND = "incident_not_found"
    NO_SOURCE_ADDRESS = "no_source_address"
    REJECTED = "rejected"


class DecideIpBlockStatus(StrEnum):
    """Closed outcome of one approve or reject request against an existing plan."""

    APPROVED = "approved"
    REJECTED = "rejected"
    PLAN_NOT_FOUND = "plan_not_found"
    ALREADY_DECIDED = "already_decided"
    EXPIRED = "expired"
    SAME_OPERATOR = "same_operator"
    NOW_BLOCKED = "now_blocked"


@dataclass(frozen=True, slots=True)
class IpBlockPlanSummary:
    """A safe, fully materialized snapshot of one plan row."""

    plan_id: UUID
    incident_id: UUID
    server_id: UUID
    ip_address: str
    status: str
    command_argv: tuple[str, ...]
    proposed_by_operator_id: UUID
    proposed_at: datetime
    expires_at: datetime
    proposal_request_id: str
    decided_by_operator_id: UUID | None
    decided_at: datetime | None


@dataclass(frozen=True, slots=True)
class ProposeIpBlockResult:
    status: ProposeIpBlockStatus
    plan: IpBlockPlanSummary | None
    rejection_reason: BlockTargetRejectionReason | None


@dataclass(frozen=True, slots=True)
class DecideIpBlockResult:
    status: DecideIpBlockStatus
    plan: IpBlockPlanSummary | None
    rejection_reason: BlockTargetRejectionReason | None = None


@dataclass(frozen=True, slots=True)
class AllowlistEntrySummary:
    entry_id: UUID
    cidr: str
    label: str
    reason: str
    created_at: datetime
    revoked_at: datetime | None


def propose_ip_block(
    session: Session,
    *,
    actor: OperatorPrincipal,
    incident_id: UUID,
    request_id: str,
    plan_ttl_seconds: int,
    nft_table: str,
    nft_set_v4: str,
    nft_set_v6: str,
    now: datetime | None = None,
) -> ProposeIpBlockResult:
    """Propose blocking one incident's correlated source address, or reuse a live plan.

    A second press for the same incident and address while a plan is still live
    returns the same plan untouched -- it is not re-audited as a new proposal.
    Only when no live plan exists (never proposed, or the previous one expired)
    is a plan created or refreshed and a fresh audit entry written.
    """

    if plan_ttl_seconds < 1:
        raise IpBlockError("plan TTL must be positive")
    current_time = _as_utc(now or datetime.now(UTC))
    incident = session.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        return ProposeIpBlockResult(ProposeIpBlockStatus.INCIDENT_NOT_FOUND, None, None)
    raw_address = _extract_source_ip(incident.correlation)
    if raw_address is None:
        return ProposeIpBlockResult(ProposeIpBlockStatus.NO_SOURCE_ADDRESS, None, None)

    # Serializes concurrent proposals for the same incident and address, the same
    # role `_acquire_correlation_lock` plays in the detection engine: without it,
    # two concurrent first-time proposals could both pass the "no live plan yet"
    # check and race to insert, tripping the partial unique index.
    _acquire_proposal_lock(session, incident_id=incident_id, raw_address=raw_address)

    decision = classify_block_target(session, raw_address=raw_address)
    if not decision.allowed or decision.address is None:
        return ProposeIpBlockResult(ProposeIpBlockStatus.REJECTED, None, decision.rejection_reason)
    address_text = str(decision.address)
    argv = build_nft_block_command(
        decision.address,
        table=nft_table,
        set_v4=nft_set_v4,
        set_v6=nft_set_v6,
    )

    existing = session.scalar(
        select(IpBlockPlan).where(
            IpBlockPlan.incident_id == incident_id,
            IpBlockPlan.ip_address == address_text,
            IpBlockPlan.status == _PROPOSED,
        )
    )
    if existing is not None and _as_utc(existing.expires_at) > current_time:
        return ProposeIpBlockResult(ProposeIpBlockStatus.REUSED, _plan_summary(existing), None)

    expires_at = current_time + timedelta(seconds=plan_ttl_seconds)
    if existing is not None:
        plan = existing
        plan.command_argv = list(argv)
        plan.proposed_by_operator_id = actor.operator_id
        plan.proposed_at = current_time
        plan.expires_at = expires_at
        plan.proposal_request_id = request_id
    else:
        plan = IpBlockPlan(
            incident_id=incident_id,
            server_id=incident.server_id,
            ip_address=address_text,
            status=_PROPOSED,
            command_argv=list(argv),
            proposed_by_operator_id=actor.operator_id,
            proposed_at=current_time,
            expires_at=expires_at,
            proposal_request_id=request_id,
        )
        session.add(plan)
    session.flush()
    record_operator_action(
        session,
        actor=actor,
        action="ip_block_plan.proposed",
        target_type="ip_block_plan",
        target_id=plan.id,
        request_id=request_id,
        incident_history_id=None,
        details={"incident_id": str(incident_id), "ip_address": address_text},
    )
    return ProposeIpBlockResult(ProposeIpBlockStatus.CREATED, _plan_summary(plan), None)


def approve_ip_block(
    session: Session,
    *,
    actor: OperatorPrincipal,
    plan_id: UUID,
    request_id: str,
    require_second_operator: bool,
    now: datetime | None = None,
) -> DecideIpBlockResult:
    """Approve one still-live plan after re-checking policy from scratch.

    The address is re-classified here, not just at proposal time: the allowlist
    may have changed between proposal and approval, and that change must win.
    A plan that no longer passes the policy check is auto-rejected rather than
    left proposed, so the database never holds an approvable-looking plan that
    the policy has since disallowed.
    """

    current_time = _as_utc(now or datetime.now(UTC))
    plan = session.scalar(select(IpBlockPlan).where(IpBlockPlan.id == plan_id).with_for_update())
    if plan is None:
        return DecideIpBlockResult(DecideIpBlockStatus.PLAN_NOT_FOUND, None)
    if plan.status != _PROPOSED:
        return DecideIpBlockResult(DecideIpBlockStatus.ALREADY_DECIDED, _plan_summary(plan))
    if _as_utc(plan.expires_at) <= current_time:
        return DecideIpBlockResult(DecideIpBlockStatus.EXPIRED, _plan_summary(plan))
    if require_second_operator and plan.proposed_by_operator_id == actor.operator_id:
        return DecideIpBlockResult(DecideIpBlockStatus.SAME_OPERATOR, _plan_summary(plan))

    decision = classify_block_target(session, raw_address=plan.ip_address)
    if not decision.allowed:
        _decide(plan, status=_REJECTED, actor=actor, now=current_time)
        session.flush()
        _record_decision_action(
            session,
            action="ip_block_plan.rejected",
            actor=actor,
            plan=plan,
            request_id=request_id,
        )
        return DecideIpBlockResult(
            DecideIpBlockStatus.NOW_BLOCKED,
            _plan_summary(plan),
            decision.rejection_reason,
        )

    _decide(plan, status=_APPROVED, actor=actor, now=current_time)
    session.flush()
    _record_decision_action(
        session,
        action="ip_block_plan.approved",
        actor=actor,
        plan=plan,
        request_id=request_id,
    )
    return DecideIpBlockResult(DecideIpBlockStatus.APPROVED, _plan_summary(plan))


def reject_ip_block(
    session: Session,
    *,
    actor: OperatorPrincipal,
    plan_id: UUID,
    request_id: str,
    now: datetime | None = None,
) -> DecideIpBlockResult:
    """Reject one still-live plan; rejecting a dangerous action needs no reason."""

    current_time = _as_utc(now or datetime.now(UTC))
    plan = session.scalar(select(IpBlockPlan).where(IpBlockPlan.id == plan_id).with_for_update())
    if plan is None:
        return DecideIpBlockResult(DecideIpBlockStatus.PLAN_NOT_FOUND, None)
    if plan.status != _PROPOSED:
        return DecideIpBlockResult(DecideIpBlockStatus.ALREADY_DECIDED, _plan_summary(plan))
    if _as_utc(plan.expires_at) <= current_time:
        return DecideIpBlockResult(DecideIpBlockStatus.EXPIRED, _plan_summary(plan))

    _decide(plan, status=_REJECTED, actor=actor, now=current_time)
    session.flush()
    _record_decision_action(
        session,
        action="ip_block_plan.rejected",
        actor=actor,
        plan=plan,
        request_id=request_id,
    )
    return DecideIpBlockResult(DecideIpBlockStatus.REJECTED, _plan_summary(plan))


def add_allowlist_entry(
    session: Session,
    *,
    cidr: str,
    label: str,
    reason: str,
    now: datetime | None = None,
) -> AllowlistEntrySummary:
    """Add one active allowlist network through the local CLI."""

    current_time = _as_utc(now or datetime.now(UTC))
    normalized = _validate_cidr(cidr)
    if not 1 <= len(label) <= 100:
        raise IpBlockError("label must contain 1 to 100 characters")
    if not 1 <= len(reason) <= 500:
        raise IpBlockError("reason must contain 1 to 500 characters")
    existing = session.scalar(
        select(IpBlockAllowlistEntry).where(
            IpBlockAllowlistEntry.cidr == normalized,
            IpBlockAllowlistEntry.revoked_at.is_(None),
        )
    )
    if existing is not None:
        raise IpBlockError("an active allowlist entry already covers this network")
    entry = IpBlockAllowlistEntry(
        cidr=normalized,
        label=label,
        reason=reason,
        created_at=current_time,
    )
    session.add(entry)
    session.flush()
    record_local_cli_action(
        session,
        action="ip_block_allowlist.created",
        target_type="ip_block_allowlist_entry",
        target_id=entry.id,
        details={"cidr": normalized},
    )
    return _allowlist_summary(entry)


def revoke_allowlist_entry(
    session: Session,
    *,
    entry_id: UUID,
    now: datetime | None = None,
) -> AllowlistEntrySummary:
    """Revoke one active allowlist entry without deleting its provenance."""

    current_time = _as_utc(now or datetime.now(UTC))
    entry = session.get(IpBlockAllowlistEntry, entry_id, with_for_update=True)
    if entry is None:
        raise IpBlockError("allowlist entry does not exist")
    if entry.revoked_at is not None:
        raise IpBlockError("allowlist entry is already revoked")
    entry.revoked_at = current_time
    session.flush()
    record_local_cli_action(
        session,
        action="ip_block_allowlist.revoked",
        target_type="ip_block_allowlist_entry",
        target_id=entry.id,
        details={"cidr": entry.cidr},
    )
    return _allowlist_summary(entry)


def list_allowlist_entries(session: Session) -> tuple[AllowlistEntrySummary, ...]:
    """Return every active allowlist entry for safe local inspection."""

    rows = session.scalars(
        select(IpBlockAllowlistEntry)
        .where(IpBlockAllowlistEntry.revoked_at.is_(None))
        .order_by(IpBlockAllowlistEntry.created_at)
    ).all()
    return tuple(_allowlist_summary(row) for row in rows)


def _decide(
    plan: IpBlockPlan,
    *,
    status: str,
    actor: OperatorPrincipal,
    now: datetime,
) -> None:
    plan.status = status
    plan.decided_by_operator_id = actor.operator_id
    plan.decided_at = now


def _record_decision_action(
    session: Session,
    *,
    action: str,
    actor: OperatorPrincipal,
    plan: IpBlockPlan,
    request_id: str,
) -> None:
    record_operator_action(
        session,
        actor=actor,
        action=action,
        target_type="ip_block_plan",
        target_id=plan.id,
        request_id=request_id,
        incident_history_id=None,
        details={
            "ip_address": plan.ip_address,
            "proposed_by_operator_id": str(plan.proposed_by_operator_id),
        },
    )


def _plan_summary(plan: IpBlockPlan) -> IpBlockPlanSummary:
    return IpBlockPlanSummary(
        plan_id=plan.id,
        incident_id=plan.incident_id,
        server_id=plan.server_id,
        ip_address=plan.ip_address,
        status=plan.status,
        command_argv=tuple(plan.command_argv),
        proposed_by_operator_id=plan.proposed_by_operator_id,
        proposed_at=plan.proposed_at,
        expires_at=plan.expires_at,
        proposal_request_id=plan.proposal_request_id,
        decided_by_operator_id=plan.decided_by_operator_id,
        decided_at=plan.decided_at,
    )


def _allowlist_summary(entry: IpBlockAllowlistEntry) -> AllowlistEntrySummary:
    return AllowlistEntrySummary(
        entry_id=entry.id,
        cidr=entry.cidr,
        label=entry.label,
        reason=entry.reason,
        created_at=entry.created_at,
        revoked_at=entry.revoked_at,
    )


def _extract_source_ip(correlation: Mapping[str, object]) -> str | None:
    value = correlation.get("source_ip")
    return value if isinstance(value, str) and value else None


def _validate_cidr(value: str) -> str:
    try:
        network = ip_network(value)
    except ValueError as error:
        raise IpBlockError("CIDR is not a valid network in strict canonical form") from error
    if str(network) != value:
        raise IpBlockError("CIDR is not a valid network in strict canonical form") from None
    return value


def _acquire_proposal_lock(session: Session, *, incident_id: UUID, raw_address: str) -> None:
    lock_material = f"{incident_id}:{raw_address}".encode()
    lock_key = int.from_bytes(hashlib.sha256(lock_material).digest()[:8], "big", signed=True)
    session.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": lock_key})


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
