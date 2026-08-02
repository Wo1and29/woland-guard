"""Tests for persistence metadata and security-sensitive columns."""

from sqlalchemy import CheckConstraint, UniqueConstraint

from woland_guard_control_plane.infrastructure.database.base import Base
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    AuditLogEntry,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentComment,
    IncidentEvent,
    IncidentHistoryEntry,
    NotificationDestination,
    Operator,
    OperatorApiKey,
    OperatorIdempotencyRecord,
    OutboxMessage,
    Server,
    TelegramDestinationConfig,
)

MODEL_TYPES = (
    AgentApiKey,
    AuditLogEntry,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentComment,
    IncidentEvent,
    IncidentHistoryEntry,
    NotificationDestination,
    Operator,
    OperatorApiKey,
    OperatorIdempotencyRecord,
    OutboxMessage,
    Server,
    TelegramDestinationConfig,
)


def test_expected_tables_are_registered() -> None:
    """The metadata contains the accepted foundation and stage 5 persistence tables."""

    assert set(Base.metadata.tables) == {
        "agent_api_keys",
        "audit_log_entries",
        "detection_rule_versions",
        "events",
        "incident_events",
        "incident_comments",
        "incident_history",
        "incidents",
        "operator_api_keys",
        "operator_idempotency_records",
        "operator_web_sessions",
        "operators",
        "notification_destinations",
        "operator_telegram_links",
        "outbox_messages",
        "servers",
        "telegram_bot_offsets",
        "telegram_destination_configs",
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


def test_incident_comment_metadata_is_minimal_and_append_only_ready() -> None:
    table = Base.metadata.tables["incident_comments"]
    checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    comment_index = next(
        index for index in table.indexes if index.name == "ix_incident_comments_incident_created_id"
    )

    assert set(table.columns.keys()) == {
        "id",
        "incident_id",
        "operator_id",
        "actor_username_snapshot",
        "auth_method_type",
        "auth_method_id",
        "request_id",
        "body",
        "created_at",
    }
    assert "BETWEEN 1 AND 1000" in checks["ck_incident_comments_body_length"]
    assert "operator_api_key" in checks["ck_incident_comments_auth_method_type_allowed"]
    assert "web_session" in checks["ck_incident_comments_auth_method_type_allowed"]
    assert tuple(column.name for column in comment_index.columns) == (
        "incident_id",
        "created_at",
        "id",
    )


def test_outbox_has_destination_lease_and_immutable_envelope_metadata() -> None:
    """Metadata captures the destination-aware lease and retry lifecycle."""

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
        "notification_type",
        "incident_id",
        "destination_id",
        "payload_schema_version",
        "payload",
        "next_attempt_at",
        "claim_token",
        "claimed_at",
        "lease_expires_at",
        "failed_at",
        "last_error_code",
        "last_error",
        "idempotency_key",
    } <= set(columns.keys())
    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in outbox_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("notification_type", "incident_id", "destination_id") in unique_columns
    assert "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" in check_sql
    assert "[0-9a-f-]{36}" not in check_sql


def test_notification_destination_is_provider_neutral_and_telegram_only() -> None:
    destination_table = Base.metadata.tables["notification_destinations"]
    check_sql = " ".join(
        str(constraint.sqltext)
        for constraint in destination_table.constraints
        if isinstance(constraint, CheckConstraint)
    )

    assert {"adapter_kind", "enabled", "minimum_severity", "created_at", "updated_at"} <= set(
        destination_table.columns.keys()
    )
    assert "telegram" in check_sql
    assert "synthetic" not in check_sql
    assert "fake" not in check_sql
    assert "chat_id" not in destination_table.columns
    assert "token_file" not in destination_table.columns


def test_telegram_provider_configuration_is_one_to_one_without_token_column() -> None:
    table = Base.metadata.tables["telegram_destination_configs"]
    check_sql = " ".join(
        str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    )

    assert table.primary_key.columns.keys() == ["destination_id"]
    assert {"destination_id", "chat_id", "token_file_name", "created_at", "updated_at"} == set(
        table.columns.keys()
    )
    assert "token_file_name" in check_sql
    stored_columns = {column.name for column in table.columns if column.name != "token_file_name"}
    assert "token" not in stored_columns
