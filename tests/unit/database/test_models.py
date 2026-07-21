"""Tests for persistence metadata and security-sensitive columns."""

from sqlalchemy import CheckConstraint, UniqueConstraint

from woland_guard_control_plane.infrastructure.database.base import Base
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    Event,
    OutboxMessage,
    Server,
)

MODEL_TYPES = (AgentApiKey, Event, OutboxMessage, Server)


def test_expected_tables_are_registered() -> None:
    """The initial metadata contains only the stage 2 persistence tables."""

    assert set(Base.metadata.tables) == {
        "agent_api_keys",
        "events",
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
