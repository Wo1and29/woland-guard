from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest
from scripts.demo_e2e.browser import DemoBrowserError, _validate_raw_audit_rows


def test_comment_audit_extra_body_is_rejected_without_reflection() -> None:
    incident_id = UUID("11111111-1111-4111-8111-111111111111")
    comment_id = UUID("22222222-2222-4222-8222-222222222222")
    history_id = UUID("33333333-3333-4333-8333-333333333333")
    canary = "synthetic-comment-body-canary"
    status = SimpleNamespace(
        action="incident.status_changed",
        actor_type="operator",
        actor_username_snapshot="demo-analyst",
        auth_method_type="web_session",
        auth_method_id=UUID("44444444-4444-4444-8444-444444444444"),
        target_type="incident",
        target_id=incident_id,
        incident_history_id=history_id,
        details={
            "from_status": "new",
            "from_version": 1,
            "history_id": str(history_id),
            "to_status": "investigating",
            "to_version": 2,
        },
    )
    comment = SimpleNamespace(
        action="incident.comment_added",
        actor_type="operator",
        actor_username_snapshot="demo-analyst",
        auth_method_type="web_session",
        auth_method_id=UUID("55555555-5555-4555-8555-555555555555"),
        target_type="incident_comment",
        target_id=comment_id,
        incident_history_id=None,
        details={"incident_id": str(incident_id), "body": canary},
    )

    with pytest.raises(DemoBrowserError) as captured:
        _validate_raw_audit_rows(
            status=status,  # type: ignore[arg-type]
            comment=comment,  # type: ignore[arg-type]
            incident_id=incident_id,
            comment_target_id=comment_id,
            analyst_username="demo-analyst",
        )

    assert canary not in str(captured.value)
