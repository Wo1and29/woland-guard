"""Alembic invariants for Dashboard authentication and read projections."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from tests.integration.conftest import OperatorFactory
from woland_guard_control_plane.application.operator_authentication import authenticate_operator
from woland_guard_control_plane.application.web_sessions import create_operator_web_session
from woland_guard_control_plane.database import get_engine, get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    DetectionRuleVersion,
    Incident,
    IncidentHistoryEntry,
    OperatorRole,
    Server,
)

pytestmark = pytest.mark.integration

REVISION_0006 = "20260727_0006"
REVISION_0007 = "20260727_0007"
REVISION_0008 = "20260728_0008"
REVISION_0009 = "20260728_0009"


def test_auth_method_constraints_are_closed_in_both_tables() -> None:
    with get_engine().connect() as connection:
        rows = connection.execute(
            text(
                "SELECT conrelid::regclass::text, pg_get_constraintdef(oid) "
                "FROM pg_constraint WHERE conname = "
                "'ck_incident_history_auth_method_type_allowed' "
                "OR conname = 'ck_audit_log_entries_auth_method_type_allowed'"
            )
        ).all()
        definitions: dict[str, str] = {str(row[0]): str(row[1]) for row in rows}

    assert set(definitions) == {"incident_history", "audit_log_entries"}
    for definition in definitions.values():
        assert "operator_api_key" in definition
        assert "web_session" in definition


def test_database_rejects_arbitrary_audit_auth_method(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    with pytest.raises(IntegrityError):
        with get_session_factory().begin() as session:
            session.add(
                AuditLogEntry(
                    actor_type="operator",
                    operator_id=operator.operator_id,
                    actor_username_snapshot=operator.username,
                    auth_method_type="arbitrary_method",
                    auth_method_id=operator.key_id,
                    action="synthetic.action",
                    target_type="synthetic_target",
                    target_id=uuid4(),
                    details={},
                )
            )


def test_database_rejects_arbitrary_incident_history_auth_method(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ANALYST)
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        server = Server(name=f"server-{uuid4().hex}", hostname="synthetic.invalid")
        rule = DetectionRuleVersion(
            rule_key=f"rule_{uuid4().hex}",
            version=1,
            schema_version=1,
            enabled=True,
            severity="high",
            checksum="a" * 64,
            definition={},
            is_active=False,
        )
        session.add_all((server, rule))
        session.flush()
        incident = Incident(
            server_id=server.id,
            rule_version_id=rule.id,
            rule_key=rule.rule_key,
            rule_version=1,
            severity="high",
            status="new",
            title="Synthetic incident",
            explanation="Synthetic explanation",
            recommendation="Synthetic recommendation",
            correlation={},
            correlation_hash="b" * 64,
            rule_snapshot={},
            first_seen_at=now,
            last_seen_at=now,
            event_count=1,
        )
        session.add(incident)
        session.flush()
        incident_id = incident.id

    with pytest.raises(IntegrityError):
        with get_session_factory().begin() as session:
            session.add(
                IncidentHistoryEntry(
                    incident_id=incident_id,
                    version=2,
                    entry_type="status_transition",
                    from_status="new",
                    to_status="investigating",
                    reason=None,
                    changed_by_operator_id=operator.operator_id,
                    actor_username_snapshot=operator.username,
                    auth_method_type="arbitrary_method",
                    auth_method_id=operator.key_id,
                    request_id="synthetic-history",
                )
            )


def test_upgrade_preserves_existing_operator_api_key_auth_rows(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    config = Config("alembic.ini")
    command.downgrade(config, REVISION_0006)
    audit_id = uuid4()
    try:
        with get_engine().begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO audit_log_entries "
                    "(id, actor_type, operator_id, actor_username_snapshot, auth_method_type, "
                    "auth_method_id, action, target_type, target_id, details) VALUES "
                    "(:id, 'operator', :operator_id, :username, 'operator_api_key', :key_id, "
                    "'synthetic.action', 'synthetic_target', :target_id, '{}'::jsonb)"
                ),
                {
                    "id": audit_id,
                    "operator_id": operator.operator_id,
                    "username": operator.username,
                    "key_id": operator.key_id,
                    "target_id": uuid4(),
                },
            )
        command.upgrade(config, "head")
        with get_session_factory()() as session:
            stored = session.get(AuditLogEntry, audit_id)
            assert stored is not None and stored.auth_method_type == "operator_api_key"
    finally:
        command.upgrade(config, "head")


def test_downgrade_refuses_populated_web_sessions(
    register_operator: OperatorFactory,
) -> None:
    operator = register_operator(role=OperatorRole.ADMIN)
    now = datetime.now(UTC)
    with get_session_factory().begin() as session:
        authenticated = authenticate_operator(session, operator.token, now=now)
        create_operator_web_session(
            session,
            authenticated=authenticated,
            now=now,
            idle_seconds=1_800,
            absolute_seconds=43_200,
            request_id="migration-refusal",
        )

    config = Config("alembic.ini")
    with pytest.raises(DBAPIError, match="cannot downgrade populated operator web sessions"):
        command.downgrade(config, REVISION_0006)

    with get_engine().begin() as connection:
        connection.execute(text("DELETE FROM operator_web_sessions"))
        connection.execute(text("ALTER TABLE audit_log_entries DISABLE TRIGGER USER"))
        connection.execute(
            text("DELETE FROM audit_log_entries WHERE action LIKE 'operator_web_session.%'")
        )
        connection.execute(text("ALTER TABLE audit_log_entries ENABLE TRIGGER USER"))
    command.downgrade(config, REVISION_0006)
    command.upgrade(config, "head")


def test_dashboard_query_indexes_upgrade_and_downgrade() -> None:
    config = Config("alembic.ini")
    try:
        command.downgrade(config, REVISION_0007)
        assert _dashboard_query_indexes() == set()
        command.upgrade(config, REVISION_0008)
        assert _dashboard_query_indexes() == {
            "ix_incident_events_incident_linked_event",
            "ix_servers_lower_hostname_pattern",
            "ix_servers_lower_name_id",
            "ix_servers_lower_name_pattern",
        }
    finally:
        command.upgrade(config, "head")


def test_current_revision_is_head() -> None:
    """Assert against the script head so a new migration never breaks this check."""

    head = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    with get_engine().connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == head
    with get_session_factory()() as session:
        assert session.scalar(select(IncidentHistoryEntry).limit(1)) is None


def _dashboard_query_indexes() -> set[str]:
    with get_engine().connect() as connection:
        return {
            str(value)
            for value in connection.scalars(
                text(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE indexname IN "
                    "('ix_incident_events_incident_linked_event', "
                    "'ix_servers_lower_hostname_pattern', "
                    "'ix_servers_lower_name_id', "
                    "'ix_servers_lower_name_pattern')"
                )
            )
        }
