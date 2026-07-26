"""Alembic environment for the Woland Guard PostgreSQL schema."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from woland_guard_control_plane.config import get_settings
from woland_guard_control_plane.database import build_database_url
from woland_guard_control_plane.infrastructure.database.base import Base
from woland_guard_control_plane.infrastructure.database.models import (
    AgentApiKey,
    AuditLogEntry,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    NotificationDestination,
    Operator,
    OperatorApiKey,
    OperatorIdempotencyRecord,
    OutboxMessage,
    Server,
)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata
_REGISTERED_MODEL_TYPES = (
    AgentApiKey,
    AuditLogEntry,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    NotificationDestination,
    Operator,
    OperatorApiKey,
    OperatorIdempotencyRecord,
    OutboxMessage,
    Server,
)


def run_migrations_offline() -> None:
    """Configure an offline migration context."""

    context.configure(
        url=build_database_url(get_settings()),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations through a short-lived PostgreSQL connection."""

    connectable = create_engine(
        build_database_url(get_settings()),
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
