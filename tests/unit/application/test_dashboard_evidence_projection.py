"""Evidence projection structurally excludes the JSONB event payload."""

from dataclasses import fields
from uuid import UUID

from sqlalchemy.dialects import postgresql

from woland_guard_control_plane.application.incident_queries import (
    DashboardEvidence,
    dashboard_evidence_statement,
)


def test_evidence_dto_and_select_have_exact_allowlist() -> None:
    assert [field.name for field in fields(DashboardEvidence)] == [
        "event_id",
        "event_type",
        "source",
        "occurred_at",
        "collected_at",
        "linked_at",
    ]
    statement = dashboard_evidence_statement(UUID("10000000-0000-4000-8000-000000000001"))
    sql = str(
        statement.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]
    ).casefold()
    selected = sql.split(" from ", maxsplit=1)[0]
    assert "payload" not in selected
    assert "correlation" not in selected
    assert "source_ip" not in selected
    assert "actor" not in selected
