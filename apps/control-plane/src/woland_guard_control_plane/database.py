"""Shared database engine, sessions, and readiness connectivity."""

from collections.abc import Iterator
from functools import lru_cache

from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import URL, Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from woland_guard_control_plane.config import Settings, get_settings


class DatabaseConfigurationError(SQLAlchemyError):
    """Raised when required database settings are absent."""


class MigrationDriftError(SQLAlchemyError):
    """Raised when the database schema is not at the code's expected migration head."""


def build_database_url(settings: Settings) -> URL:
    """Build a PostgreSQL URL without converting the password to a plain loggable string."""

    if settings.postgres_password is None:
        raise DatabaseConfigurationError("PostgreSQL password is not configured")

    return URL.create(
        drivername="postgresql+psycopg",
        username=settings.postgres_user,
        password=settings.postgres_password.get_secret_value(),
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
    )


@lru_cache
def get_engine() -> Engine:
    """Create the shared SQLAlchemy engine without opening a connection."""

    settings = get_settings()
    return create_engine(
        build_database_url(settings),
        pool_pre_ping=True,
        connect_args={"connect_timeout": settings.postgres_connect_timeout_seconds},
        # psycopg3 decodes inet/cidr columns to ipaddress objects by default; every
        # other identifier in this codebase is a plain str, and the ORM models declare
        # `Mapped[str]` for these columns, so native decoding is turned off to keep the
        # declared and runtime types the same.
        native_inet_types=False,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide SQLAlchemy session factory."""

    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_session() -> Iterator[Session]:
    """Yield one request-scoped session without implicit commits."""

    with get_session_factory()() as session:
        yield session


@lru_cache
def _expected_head_revision() -> str | None:
    """Return the migration head baked into this image (the set of files never
    changes at runtime, so this only needs to be read from disk once)."""

    script = ScriptDirectory.from_config(AlembicConfig("alembic.ini"))
    return script.get_current_head()


def check_database() -> None:
    """Run the smallest possible readiness query and confirm the schema is migrated.

    A live connection alone isn't readiness: a container that starts before
    `alembic upgrade head` has run would otherwise report "ready" while the
    schema doesn't match the code serving requests against it.
    """

    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
        current = MigrationContext.configure(connection).get_current_revision()
        expected = _expected_head_revision()
        if current != expected:
            raise MigrationDriftError(
                f"database schema is at revision {current!r}, code expects {expected!r}"
            )
