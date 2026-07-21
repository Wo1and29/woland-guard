"""Minimal database connectivity used by the readiness probe."""

from functools import lru_cache

from sqlalchemy import URL, Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from woland_guard_control_plane.config import get_settings


class DatabaseConfigurationError(SQLAlchemyError):
    """Raised when required database settings are absent."""


@lru_cache
def get_engine() -> Engine:
    """Create the shared SQLAlchemy engine without opening a connection."""

    settings = get_settings()
    if settings.postgres_password is None:
        raise DatabaseConfigurationError("PostgreSQL password is not configured")

    database_url = URL.create(
        drivername="postgresql+psycopg",
        username=settings.postgres_user,
        password=settings.postgres_password.get_secret_value(),
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
    )
    return create_engine(
        database_url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": settings.postgres_connect_timeout_seconds},
    )


def check_database() -> None:
    """Run the smallest possible database readiness query."""

    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
