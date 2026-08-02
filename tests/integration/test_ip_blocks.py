"""Propose/approve/reject flow for dry-run IP block plans against real PostgreSQL.

Nothing here ever executes ``command_argv`` -- these tests only verify the state
machine, the policy re-check at approval time, and that the allowlist's CIDR
containment check (which cannot be exercised with a mocked session) works
against the real ``inet``/``cidr`` PostgreSQL types.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from tests.integration.conftest import OperatorFactory, RegisteredOperator
from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.application.detection.sync import sync_rules
from woland_guard_control_plane.application.ip_block_policy import BlockTargetRejectionReason
from woland_guard_control_plane.application.ip_blocks import (
    DecideIpBlockStatus,
    IpBlockError,
    ProposeIpBlockResult,
    ProposeIpBlockStatus,
    add_allowlist_entry,
    approve_ip_block,
    list_allowlist_entries,
    propose_ip_block,
    reject_ip_block,
    revoke_allowlist_entry,
)
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    DetectionRuleVersion,
    Incident,
    IpBlockPlan,
    OperatorAuthMethodType,
    OperatorRole,
    Server,
)

pytestmark = pytest.mark.integration

RULES_DIR = Path(__file__).parents[2] / "detection-rules"
NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
_NFT_TABLE = "woland_guard"
_NFT_SET_V4 = "blocked_v4"
_NFT_SET_V6 = "blocked_v6"


def _principal(operator: RegisteredOperator) -> OperatorPrincipal:
    return OperatorPrincipal(
        operator_id=operator.operator_id,
        username=operator.username,
        role=operator.role,
        auth_method_type=OperatorAuthMethodType.OPERATOR_API_KEY,
        auth_method_id=operator.key_id,
    )


def _create_incident(*, correlation: dict[str, object]) -> tuple[UUID, UUID]:
    """Return (incident_id, server_id) for one incident carrying this correlation."""

    rule = load_rules_directory(RULES_DIR)[0]
    with get_session_factory().begin() as session:
        sync_rules(session, (rule,), activated_at=NOW)
        stored_rule = session.scalar(
            select(DetectionRuleVersion).where(DetectionRuleVersion.rule_key == rule.rule_key)
        )
        assert stored_rule is not None
        server = Server(name=f"ip-block-{uuid4().hex}", hostname=f"{uuid4().hex}.invalid")
        session.add(server)
        session.flush()
        incident = Incident(
            server_id=server.id,
            rule_version_id=stored_rule.id,
            rule_key=rule.rule_key,
            rule_version=rule.version,
            severity=rule.severity.value,
            status="new",
            title=rule.title,
            explanation=rule.explanation,
            recommendation=rule.recommendation,
            correlation=correlation,
            correlation_hash="c" * 64,
            rule_snapshot=rule.model_dump(mode="json"),
            first_seen_at=NOW,
            last_seen_at=NOW,
            event_count=1,
        )
        session.add(incident)
        session.flush()
        return incident.id, server.id


def _propose(
    *,
    actor: OperatorPrincipal,
    incident_id: UUID,
    request_id: str = "test-propose",
    plan_ttl_seconds: int = 3_600,
    now: datetime = NOW,
) -> ProposeIpBlockResult:
    with get_session_factory().begin() as session:
        return propose_ip_block(
            session,
            actor=actor,
            incident_id=incident_id,
            request_id=request_id,
            plan_ttl_seconds=plan_ttl_seconds,
            nft_table=_NFT_TABLE,
            nft_set_v4=_NFT_SET_V4,
            nft_set_v6=_NFT_SET_V6,
            now=now,
        )


def _audit_count(action: str, target_id: UUID) -> int:
    with get_session_factory()() as session:
        rows = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action == action,
                AuditLogEntry.target_id == target_id,
            )
        ).all()
        return len(rows)


def test_propose_reports_incident_not_found(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)

    result = _propose(actor=_principal(operator), incident_id=uuid4())

    assert result.status is ProposeIpBlockStatus.INCIDENT_NOT_FOUND
    assert result.plan is None


def test_propose_reports_missing_source_address(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"actor": "root"})

    result = _propose(actor=_principal(operator), incident_id=incident_id)

    assert result.status is ProposeIpBlockStatus.NO_SOURCE_ADDRESS


def test_propose_rejects_a_never_block_address(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "127.0.0.1"})

    result = _propose(actor=_principal(operator), incident_id=incident_id)

    assert result.status is ProposeIpBlockStatus.REJECTED
    assert result.rejection_reason is BlockTargetRejectionReason.NEVER_BLOCK
    assert result.plan is None


def test_propose_rejects_an_allowlisted_address(register_operator: OperatorFactory) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    with get_session_factory().begin() as session:
        add_allowlist_entry(session, cidr="8.0.0.0/8", label="synthetic", reason="test isolation")

    result = _propose(actor=_principal(operator), incident_id=incident_id)

    assert result.status is ProposeIpBlockStatus.REJECTED
    assert result.rejection_reason is BlockTargetRejectionReason.ALLOWLISTED


def test_propose_creates_a_plan_with_the_expected_command(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, server_id = _create_incident(correlation={"source_ip": "8.8.8.8"})

    result = _propose(actor=_principal(operator), incident_id=incident_id)

    assert result.status is ProposeIpBlockStatus.CREATED
    assert result.plan is not None
    assert result.plan.incident_id == incident_id
    assert result.plan.server_id == server_id
    assert result.plan.ip_address == "8.8.8.8"
    assert result.plan.status == "proposed"
    assert result.plan.command_argv == (
        "nft",
        "add",
        "element",
        "inet",
        "woland_guard",
        "blocked_v4",
        "{",
        "8.8.8.8",
        "}",
    )
    assert _audit_count("ip_block_plan.proposed", result.plan.plan_id) == 1


def test_second_propose_while_live_is_reused_without_a_new_audit_entry(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})

    first = _propose(actor=_principal(operator), incident_id=incident_id)
    second = _propose(actor=_principal(operator), incident_id=incident_id)

    assert first.status is ProposeIpBlockStatus.CREATED
    assert second.status is ProposeIpBlockStatus.REUSED
    assert first.plan is not None
    assert second.plan is not None
    assert first.plan.plan_id == second.plan.plan_id
    assert _audit_count("ip_block_plan.proposed", first.plan.plan_id) == 1


def test_propose_after_expiry_refreshes_the_same_row_and_re_audits(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})

    first = _propose(actor=_principal(operator), incident_id=incident_id, plan_ttl_seconds=60)
    assert first.plan is not None
    later = NOW + timedelta(seconds=61)
    second = _propose(
        actor=_principal(operator),
        incident_id=incident_id,
        plan_ttl_seconds=3_600,
        now=later,
    )

    assert second.status is ProposeIpBlockStatus.CREATED
    assert second.plan is not None
    assert second.plan.plan_id == first.plan.plan_id
    assert second.plan.expires_at > first.plan.expires_at
    assert _audit_count("ip_block_plan.proposed", first.plan.plan_id) == 2


def test_approve_requires_a_different_operator_by_default(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        result = approve_ip_block(
            session,
            actor=_principal(proposer),
            plan_id=proposal.plan.plan_id,
            request_id="test-approve",
            require_second_operator=True,
            now=NOW,
        )

    assert result.status is DecideIpBlockStatus.SAME_OPERATOR


def test_approve_by_a_second_operator_succeeds_and_never_executes(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    approver = register_operator(role=OperatorRole.ADMIN)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        result = approve_ip_block(
            session,
            actor=_principal(approver),
            plan_id=proposal.plan.plan_id,
            request_id="test-approve",
            require_second_operator=True,
            now=NOW,
        )

    assert result.status is DecideIpBlockStatus.APPROVED
    assert result.plan is not None
    assert result.plan.status == "approved"
    assert result.plan.decided_by_operator_id == approver.operator_id
    assert _audit_count("ip_block_plan.approved", proposal.plan.plan_id) == 1
    with get_session_factory()() as session:
        stored = session.get(IpBlockPlan, proposal.plan.plan_id)
        assert stored is not None
        assert stored.status == "approved"


def test_approve_twice_reports_already_decided(register_operator: OperatorFactory) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    approver = register_operator(role=OperatorRole.ADMIN)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        approve_ip_block(
            session,
            actor=_principal(approver),
            plan_id=proposal.plan.plan_id,
            request_id="first",
            require_second_operator=True,
            now=NOW,
        )
    with get_session_factory().begin() as session:
        second = approve_ip_block(
            session,
            actor=_principal(approver),
            plan_id=proposal.plan.plan_id,
            request_id="second",
            require_second_operator=True,
            now=NOW,
        )

    assert second.status is DecideIpBlockStatus.ALREADY_DECIDED


def test_approve_expired_plan_is_reported_as_expired(register_operator: OperatorFactory) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    approver = register_operator(role=OperatorRole.ADMIN)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id, plan_ttl_seconds=60)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        result = approve_ip_block(
            session,
            actor=_principal(approver),
            plan_id=proposal.plan.plan_id,
            request_id="test-approve",
            require_second_operator=True,
            now=NOW + timedelta(seconds=61),
        )

    assert result.status is DecideIpBlockStatus.EXPIRED


def test_approve_rechecks_policy_and_auto_rejects_when_now_blocked(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    approver = register_operator(role=OperatorRole.ADMIN)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        add_allowlist_entry(session, cidr="8.0.0.0/8", label="synthetic", reason="became trusted")

    with get_session_factory().begin() as session:
        result = approve_ip_block(
            session,
            actor=_principal(approver),
            plan_id=proposal.plan.plan_id,
            request_id="test-approve",
            require_second_operator=True,
            now=NOW,
        )

    assert result.status is DecideIpBlockStatus.NOW_BLOCKED
    assert result.rejection_reason is BlockTargetRejectionReason.ALLOWLISTED
    assert result.plan is not None
    assert result.plan.status == "rejected"
    assert _audit_count("ip_block_plan.rejected", proposal.plan.plan_id) == 1
    assert _audit_count("ip_block_plan.approved", proposal.plan.plan_id) == 0


def test_require_second_operator_false_allows_the_same_operator(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ADMIN)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        result = approve_ip_block(
            session,
            actor=_principal(proposer),
            plan_id=proposal.plan.plan_id,
            request_id="test-approve",
            require_second_operator=False,
            now=NOW,
        )

    assert result.status is DecideIpBlockStatus.APPROVED


def test_reject_by_the_proposer_does_not_require_a_second_operator(
    register_operator: OperatorFactory,
) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        result = reject_ip_block(
            session,
            actor=_principal(proposer),
            plan_id=proposal.plan.plan_id,
            request_id="test-reject",
            now=NOW,
        )

    assert result.status is DecideIpBlockStatus.REJECTED
    assert result.plan is not None
    assert result.plan.status == "rejected"
    assert _audit_count("ip_block_plan.rejected", proposal.plan.plan_id) == 1


def test_reject_not_found_and_already_decided(register_operator: OperatorFactory) -> None:
    proposer = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident(correlation={"source_ip": "8.8.8.8"})
    proposal = _propose(actor=_principal(proposer), incident_id=incident_id)
    assert proposal.plan is not None

    with get_session_factory().begin() as session:
        missing = reject_ip_block(
            session,
            actor=_principal(proposer),
            plan_id=uuid4(),
            request_id="missing",
            now=NOW,
        )
    assert missing.status is DecideIpBlockStatus.PLAN_NOT_FOUND

    with get_session_factory().begin() as session:
        reject_ip_block(
            session,
            actor=_principal(proposer),
            plan_id=proposal.plan.plan_id,
            request_id="first-reject",
            now=NOW,
        )
    with get_session_factory().begin() as session:
        second = reject_ip_block(
            session,
            actor=_principal(proposer),
            plan_id=proposal.plan.plan_id,
            request_id="second-reject",
            now=NOW,
        )
    assert second.status is DecideIpBlockStatus.ALREADY_DECIDED


def test_allowlist_lifecycle_through_the_application_service() -> None:
    with get_session_factory().begin() as session:
        entry = add_allowlist_entry(
            session,
            cidr="203.0.113.0/24",
            label="synthetic-partner",
            reason="known monitoring probe",
        )
    with get_session_factory()() as session:
        active = list_allowlist_entries(session)
    assert any(item.entry_id == entry.entry_id for item in active)
    assert _audit_count("ip_block_allowlist.created", entry.entry_id) == 1

    with get_session_factory().begin() as session:
        with pytest.raises(IpBlockError):
            add_allowlist_entry(
                session,
                cidr="203.0.113.0/24",
                label="duplicate",
                reason="should be rejected",
            )

    with get_session_factory().begin() as session:
        revoked = revoke_allowlist_entry(session, entry_id=entry.entry_id)
    assert revoked.revoked_at is not None
    with get_session_factory()() as session:
        after_revoke = list_allowlist_entries(session)
    assert all(item.entry_id != entry.entry_id for item in after_revoke)
    assert _audit_count("ip_block_allowlist.revoked", entry.entry_id) == 1

    with get_session_factory().begin() as session:
        with pytest.raises(IpBlockError):
            revoke_allowlist_entry(session, entry_id=entry.entry_id)


def test_allowlist_rejects_a_non_canonical_cidr() -> None:
    with get_session_factory().begin() as session:
        with pytest.raises(IpBlockError):
            add_allowlist_entry(
                session,
                cidr="203.0.113.5/24",
                label="synthetic",
                reason="host bits set",
            )
