"""check_database() must fail closed when the schema is behind the code's head.

A live connection alone isn't readiness: a container started before
`alembic upgrade head` has run would otherwise report ready while serving
requests against a schema the code doesn't match.
"""

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from woland_guard_control_plane.database import MigrationDriftError, check_database

pytestmark = pytest.mark.integration


def test_check_database_passes_at_head() -> None:
    check_database()


def test_check_database_fails_closed_one_revision_behind_head() -> None:
    config = Config("alembic.ini")
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None
    parent = ScriptDirectory.from_config(config).get_revision(head).down_revision
    assert isinstance(parent, str), "this project's migration history is a linear chain"

    command.downgrade(config, parent)
    try:
        with pytest.raises(MigrationDriftError, match=f"expects {head!r}"):
            check_database()
    finally:
        command.upgrade(config, "head")
