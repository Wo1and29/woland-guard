"""Tests for persistence metadata and security-sensitive columns."""

from sqlalchemy import CheckConstraint, UniqueConstraint

from woland_guard_control_plane.infrastructure.database.base import Base
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    OutboxMessage,
    Server,
)

MODEL_TYPES = (
    AgentApiKey,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    OutboxMessage,
    Server,
)


def test_expected_tables_are_registered() -> None:
    """The metadata contains the accepted foundation and stage 5 persistence tables."""

    assert set(Base.metadata.tables) == {
        "agent_api_keys",
        "detection_rule_versions",
        "events",
        "incident_events",
        "incidents",
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
