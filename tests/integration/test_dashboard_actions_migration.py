"""Alembic and PostgreSQL invariants for Dashboard incident comments."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from tests.integration.conftest import OperatorFactory
from tests.integration.test_dashboard_queries import _create_incident_with_evidence
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    IncidentComment,
    OperatorIdempotencyRecord,
    OperatorRole,
)

pytestmark = pytest.mark.integration
REVISION_0008 = "20260728_0008"
REVISION_0009 = "20260728_0009"


def _current_revision() -> str | None:
    """Return the applied revision so refusals can be checked without pinning a value."""

    with get_engine().connect() as connection:
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
    return None if revision is None else str(revision)


def test_comment_constraints_and_append_only_triggers(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with pytest.raises(IntegrityError):
        with get_session_factory().begin() as session:
            session.add(
                IncidentComment(
                    incident_id=incident_id,
                    operator_id=operator.operator_id,
                    actor_username_snapshot=operator.username,
                    auth_method_type="web_session",
                    auth_method_id=uuid4(),
                    request_id="empty-body",
                    body="",
                )
            )
    with pytest.raises(IntegrityError):
        with get_session_factory().begin() as session:
            session.add(
                IncidentComment(
                    incident_id=incident_id,
                    operator_id=operator.operator_id,
                    actor_username_snapshot=operator.username,
                    auth_method_type="unknown",
                    auth_method_id=uuid4(),
                    request_id="invalid-auth-method",
                    body="valid",
                )
            )

    with get_session_factory().begin() as session:
        stored = IncidentComment(
            incident_id=incident_id,
            operator_id=operator.operator_id,
            actor_username_snapshot=operator.username,
            auth_method_type="web_session",
            auth_method_id=uuid4(),
            request_id="immutable-comment",
            body="immutable",
            created_at=datetime.now(UTC),
        )
        session.add(stored)
        session.flush()
        comment_id = stored.id

    for statement in (
        "UPDATE incident_comments SET body = 'changed' WHERE id = :comment_id",
        "DELETE FROM incident_comments WHERE id = :comment_id",
        "TRUNCATE TABLE incident_comments",
    ):
        with pytest.raises(DBAPIError, match="immutable Woland Guard table"):
            with get_engine().begin() as connection:
                connection.execute(text(statement), {"comment_id": comment_id})


def test_0009_upgrade_downgrade_upgrade_cycle() -> None:
    config = Config("alembic.ini")
    try:
        command.downgrade(config, REVISION_0008)
        assert "incident_comments" not in inspect(get_engine()).get_table_names()
        command.upgrade(config, REVISION_0009)
        assert "incident_comments" in inspect(get_engine()).get_table_names()
        command.downgrade(config, REVISION_0008)
        command.upgrade(config, REVISION_0009)
        with get_engine().connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM alembic_version")) == REVISION_0009
            )
    finally:
        command.upgrade(config, "head")


def test_0009_downgrade_refuses_populated_comment(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id, _ = _create_incident_with_evidence()
    with get_session_factory().begin() as session:
        session.add(
            IncidentComment(
                incident_id=incident_id,
                operator_id=operator.operator_id,
                actor_username_snapshot=operator.username,
                auth_method_type="web_session",
                auth_method_id=uuid4(),
                request_id="downgrade-refusal",
                body="preserve this comment",
            )
        )

    config = Config("alembic.ini")
    with pytest.raises(DBAPIError, match="cannot downgrade populated incident comments safely"):
        command.downgrade(config, REVISION_0008)

    with get_engine().begin() as connection:
        connection.execute(text("ALTER TABLE incident_comments DISABLE TRIGGER USER"))
        connection.execute(text("DELETE FROM incident_comments"))
        connection.execute(text("ALTER TABLE incident_comments ENABLE TRIGGER USER"))
    command.downgrade(config, REVISION_0008)
    command.upgrade(config, "head")


def test_0009_downgrade_refuses_orphan_comment_audit(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    audit_id = uuid4()
    incident_id = uuid4()
    with get_session_factory().begin() as session:
        session.add(
            AuditLogEntry(
                id=audit_id,
                actor_type="operator",
                operator_id=operator.operator_id,
                actor_username_snapshot=operator.username,
                auth_method_type="operator_api_key",
                auth_method_id=operator.key_id,
                action="incident.comment_added",
                target_type="incident_comment",
                target_id=uuid4(),
                incident_history_id=None,
                request_id="orphan-comment-audit",
                details={"incident_id": str(incident_id)},
            )
        )

    with get_session_factory()() as session:
        assert session.query(IncidentComment).count() == 0
        assert (
            session.query(OperatorIdempotencyRecord)
            .filter(OperatorIdempotencyRecord.operation == "incident.comment.create.v1")
            .count()
            == 0
        )

    config = Config("alembic.ini")
    revision_before = _current_revision()
    with pytest.raises(DBAPIError, match="cannot downgrade incident comment audit safely"):
        command.downgrade(config, REVISION_0008)

    assert _current_revision() == revision_before
    with get_session_factory()() as session:
        assert session.get(AuditLogEntry, audit_id) is not None

    with get_engine().begin() as connection:
        connection.execute(text("ALTER TABLE audit_log_entries DISABLE TRIGGER USER"))
        connection.execute(
            text("DELETE FROM audit_log_entries WHERE id = :audit_id"),
            {"audit_id": audit_id},
        )
        connection.execute(text("ALTER TABLE audit_log_entries ENABLE TRIGGER USER"))
    command.downgrade(config, REVISION_0008)
    command.upgrade(config, "head")


def test_0009_downgrade_refuses_orphan_comment_outcome(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    outcome_id = uuid4()
    incident_id = uuid4()
    comment_id = uuid4()
    with get_session_factory().begin() as session:
        session.add(
            OperatorIdempotencyRecord(
                id=outcome_id,
                operator_id=operator.operator_id,
                idempotency_key=str(uuid4()),
                operation="incident.comment.create.v1",
                resource_id=incident_id,
                canonical_request_hash="a" * 64,
                response_status=200,
                response_body={
                    "comment_id": str(comment_id),
                    "created_at": "2026-07-29T00:00:00+00:00",
                    "incident_id": str(incident_id),
                },
            )
        )

    with get_session_factory()() as session:
        assert session.query(IncidentComment).count() == 0
        assert (
            session.query(AuditLogEntry)
            .filter(AuditLogEntry.action == "incident.comment_added")
            .count()
            == 0
        )

    config = Config("alembic.ini")
    revision_before = _current_revision()
    with pytest.raises(DBAPIError, match="cannot downgrade incident comment outcomes safely"):
        command.downgrade(config, REVISION_0008)

    assert _current_revision() == revision_before
    with get_session_factory()() as session:
        assert session.get(OperatorIdempotencyRecord, outcome_id) is not None

    with get_engine().begin() as connection:
        connection.execute(text("ALTER TABLE operator_idempotency_records DISABLE TRIGGER USER"))
        connection.execute(
            text("DELETE FROM operator_idempotency_records WHERE id = :outcome_id"),
            {"outcome_id": outcome_id},
        )
        connection.execute(text("ALTER TABLE operator_idempotency_records ENABLE TRIGGER USER"))
    command.downgrade(config, REVISION_0008)
    command.upgrade(config, "head")
