"""Tests for persistence metadata and security-sensitive columns."""

from sqlalchemy import CheckConstraint, UniqueConstraint

from woland_guard_control_plane.infrastructure.database.base import Base
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    AuditLogEntry,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    Operator,
    OperatorApiKey,
    OperatorIdempotencyRecord,
    OutboxMessage,
    Server,
)

MODEL_TYPES = (
    AgentApiKey,
    AuditLogEntry,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    Operator,
    OperatorApiKey,
    OperatorIdempotencyRecord,
    OutboxMessage,
    Server,
)


def test_expected_tables_are_registered() -> None:
    """The metadata contains the accepted foundation and stage 5 persistence tables."""

    assert set(Base.metadata.tables) == {
        "agent_api_keys",
        "audit_log_entries",
        "detection_rule_versions",
        "events",
        "incident_events",
        "incident_history",
        "incidents",
        "operator_api_keys",
        "operator_idempotency_records",
        "operators",
        "outbox_messages",
        "servers",
    }


def test_agent_key_table_requires_exact_digest_length_without_plaintext() -> None:
    """The database metadata requires a 32-byte digest and has no plaintext column."""

    agent_key_table = Base.metadata.tables["agent_api_keys"]
    columns = agent_key_table.columns
    check_constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in agent_key_table.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert "secret_hash" in columns
    assert check_constraints["ck_agent_api_keys_secret_hash_length"] == (
        "octet_length(secret_hash) = 32"  # noqa: S105 - SQL expression, not a secret
    )
    assert "token" not in columns
    assert "secret" not in columns


def test_event_idempotency_is_scoped_to_server() -> None:
    """Agent retries are deduplicated independently for each server."""

    event_table = Base.metadata.tables["events"]
    unique_column_sets = {
        tuple(column.name for column in constraint.columns)
        for constraint in event_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert ("server_id", "agent_event_id") in unique_column_sets


def test_operator_identity_is_separate_from_authentication_methods() -> None:
    """Operator roles live on identities while only key rows contain credential digests."""

    operator_columns = Base.metadata.tables["operators"].columns
    key_table = Base.metadata.tables["operator_api_keys"]
    key_columns = key_table.columns
    check_constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in key_table.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert {"username", "role", "is_active"} <= set(operator_columns.keys())
    assert "secret_hash" not in operator_columns
    assert {"operator_id", "secret_hash", "rotated_from_id"} <= set(key_columns.keys())
    assert check_constraints["ck_operator_api_keys_secret_hash_length"] == (
        "octet_length(secret_hash) = 32"  # noqa: S105 - SQL expression, not a secret
    )
    assert "token" not in key_columns
    assert "secret" not in key_columns


def test_detection_metadata_has_explicit_concurrency_constraints_and_indexes() -> None:
    """PostgreSQL enforces one active version/incident and indexes correlation paths."""

    rule_indexes = {index.name for index in Base.metadata.tables["detection_rule_versions"].indexes}
    incident_indexes = {index.name for index in Base.metadata.tables["incidents"].indexes}
    evidence_indexes = {index.name for index in Base.metadata.tables["incident_events"].indexes}
    event_indexes = {index.name for index in Base.metadata.tables["events"].indexes}

    assert "uq_detection_rule_versions_active_rule_key" in rule_indexes
    assert "uq_incidents_active_server_rule_version_correlation" in incident_indexes
    assert "ix_incidents_server_status_last_seen" in incident_indexes
    assert "ix_incidents_rule_key_correlation_hash" in incident_indexes
    assert "ix_incident_events_event_id" in evidence_indexes
    assert "ix_events_server_id_event_type_occurred_at" in event_indexes
    active_incident_index = next(
        index
        for index in Base.metadata.tables["incidents"].indexes
        if index.name == "uq_incidents_active_server_rule_version_correlation"
    )
    assert tuple(column.name for column in active_incident_index.columns) == (
        "server_id",
        "rule_version_id",
        "correlation_hash",
    )


def test_incident_workflow_metadata_has_versions_and_immutable_record_shapes() -> None:
    """Stage 6B metadata makes versions, history, audit, and replay results explicit."""

    incident_table = Base.metadata.tables["incidents"]
    history_table = Base.metadata.tables["incident_history"]
    audit_table = Base.metadata.tables["audit_log_entries"]
    idempotency_table = Base.metadata.tables["operator_idempotency_records"]
    history_unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in history_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    idempotency_unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in idempotency_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert "lock_version" in incident_table.columns
    assert ("incident_id", "version") in history_unique_columns
    assert "incident_history_id" in audit_table.columns
    assert ("operator_id", "idempotency_key") in idempotency_unique_columns
    assert {"canonical_request_hash", "response_status", "response_body"} <= set(
        idempotency_table.columns.keys()
    )


def test_outbox_has_required_states_and_retry_columns() -> None:
    """Metadata captures the required delivery lifecycle and retry data."""

    outbox_table = Base.metadata.tables["outbox_messages"]
    check_sql = " ".join(
        str(constraint.sqltext)
        for constraint in outbox_table.constraints
        if isinstance(constraint, CheckConstraint)
    )
    columns = outbox_table.columns

    assert {"pending", "processing", "delivered", "failed"} <= set(check_sql.split("'"))
    assert {
        "attempt_count",
        "max_attempts",
        "available_at",
        "locked_at",
        "locked_by",
        "last_error",
        "idempotency_key",
    } <= set(columns.keys())
