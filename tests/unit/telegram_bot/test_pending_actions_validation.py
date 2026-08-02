"""Argument validation in pending-action storage that runs before any query."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
from woland_guard_control_plane.telegram_bot.pending_actions import store_pending_action

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
INCIDENT_ID = UUID("11111111-1111-4111-8111-111111111111")


class _ExplodingSession:
    """Fails the test if validation did not reject the call before querying."""

    def execute(self, *_args: object, **_kwargs: object) -> Any:
        raise AssertionError("invalid arguments must be rejected before any query")


def test_only_terminal_statuses_may_have_a_pending_action() -> None:
    with pytest.raises(ValueError, match="terminal-status"):
        store_pending_action(
            _ExplodingSession(),  # type: ignore[arg-type]
            telegram_user_id=4242,
            incident_id=INCIDENT_ID,
            target_status=IncidentStatus.INVESTIGATING,
            expected_version=1,
            ttl_seconds=300,
            now=NOW,
        )


@pytest.mark.parametrize("ttl_seconds", [0, -1])
def test_ttl_must_be_positive(ttl_seconds: int) -> None:
    with pytest.raises(ValueError, match="TTL"):
        store_pending_action(
            _ExplodingSession(),  # type: ignore[arg-type]
            telegram_user_id=4242,
            incident_id=INCIDENT_ID,
            target_status=IncidentStatus.RESOLVED,
            expected_version=1,
            ttl_seconds=ttl_seconds,
            now=NOW,
        )
