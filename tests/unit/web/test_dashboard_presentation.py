"""Audit details degrade as one unit when stored data violates the registry."""

from datetime import UTC, datetime
from uuid import UUID

import pytest

from woland_guard_control_plane.application.audit_queries import AuditDashboardEntry
from woland_guard_control_plane.web.presentation import audit_entry_view


def _entry(
    details: object,
    *,
    action: str = "incident.status_changed",
    target_type: str = "incident",
) -> AuditDashboardEntry:
    return AuditDashboardEntry(
        id=UUID("10000000-0000-4000-8000-000000000001"),
        actor_type="operator",
        operator_id=UUID("20000000-0000-4000-8000-000000000002"),
        actor_username="synthetic-admin",
        auth_method_type="web_session",
        action=action,
        target_type=target_type,
        target_id=UUID("30000000-0000-4000-8000-000000000003"),
        request_id="safe-request",
        details=details,
        created_at=datetime(2026, 7, 28, tzinfo=UTC),
    )


def test_valid_audit_details_are_rendered_from_closed_registry() -> None:
    view = audit_entry_view(
        _entry(
            {
                "from_status": "new",
                "from_version": 1,
                "history_id": "40000000-0000-4000-8000-000000000004",
                "to_status": "investigating",
                "to_version": 2,
            }
        )
    )
    assert view.details is not None
    assert dict(view.details)["to_status"] == "investigating"


def test_comment_audit_presents_only_allowlisted_incident_id() -> None:
    view = audit_entry_view(
        _entry(
            {"incident_id": "40000000-0000-4000-8000-000000000004"},
            action="incident.comment_added",
            target_type="incident_comment",
        )
    )
    assert view.details == (("incident_id", "40000000-0000-4000-8000-000000000004"),)


def test_one_extra_field_hides_all_audit_details_but_keeps_metadata() -> None:
    canary = "canary-credential-value"
    view = audit_entry_view(
        _entry(
            {
                "from_status": "new",
                "from_version": 1,
                "history_id": "40000000-0000-4000-8000-000000000004",
                "to_status": "investigating",
                "to_version": 2,
                "credential": canary,
            }
        )
    )
    assert view.details is None
    assert view.action == "incident.status_changed"
    assert canary not in repr(view)


@pytest.mark.parametrize(
    ("action", "details"),
    [
        ("incident.status_changed", ["canary-array"]),
        ("incident.status_changed", "canary-string"),
        ("incident.status_changed", 7),
        ("incident.status_changed", True),
        ("incident.status_changed", None),
        (
            "incident.status_changed",
            {
                "from_status": "new",
                "from_version": 1,
                "history_id": "40000000-0000-4000-8000-000000000004",
                "to_status": "investigating",
                "to_version": 2,
                "extra": "canary-extra",
            },
        ),
        ("incident.status_changed", {"from_status": "new"}),
        (
            "incident.status_changed",
            {
                "from_status": "new",
                "from_version": "wrong",
                "history_id": "40000000-0000-4000-8000-000000000004",
                "to_status": "investigating",
                "to_version": 2,
            },
        ),
        ("unknown.action", {"role": "admin"}),
    ],
)
def test_every_untrusted_audit_shape_degrades_as_one_unit(
    action: str,
    details: object,
) -> None:
    view = audit_entry_view(_entry(details, action=action))
    assert view.details is None
    assert view.action == action
    assert "canary" not in repr(view)
