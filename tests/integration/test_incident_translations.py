"""Backfill of English prose onto incidents frozen before the rules were bilingual."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.detection.rules import (
    RuleDefinition,
    load_rules_directory,
)
from woland_guard_control_plane.application.detection.sync import sync_rules
from woland_guard_control_plane.application.incident_translations import (
    backfill_incident_translations,
)
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    DetectionRuleVersion,
    Incident,
    Server,
)

pytestmark = pytest.mark.integration

RULES_DIR = Path(__file__).parents[2] / "detection-rules"
NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _rule(rule_key: str = "ssh_root_login_success") -> RuleDefinition:
    return next(rule for rule in load_rules_directory(RULES_DIR) if rule.rule_key == rule_key)


def _server(session: Session) -> UUID:
    server = Server(
        name=f"host-{uuid4().hex[:8]}",
        hostname=f"host-{uuid4().hex[:8]}.internal",
        is_active=True,
    )
    session.add(server)
    session.flush()
    return server.id


def _legacy_incident(
    session: Session, *, rule_version_id: UUID, rule: RuleDefinition, **overrides: object
) -> UUID:
    """One incident frozen the way it looked before English prose existed."""

    values: dict[str, object] = {
        "title": rule.title,
        "explanation": rule.explanation,
        "recommendation": rule.recommendation,
    }
    values.update(overrides)
    incident = Incident(
        server_id=_server(session),
        rule_version_id=rule_version_id,
        rule_key=rule.rule_key,
        rule_version=rule.version,
        severity=rule.severity.value,
        status="new",
        title_en=None,
        explanation_en=None,
        recommendation_en=None,
        correlation={},
        correlation_hash=uuid4().hex + uuid4().hex[:32],
        rule_snapshot={"version": rule.version},
        first_seen_at=NOW,
        last_seen_at=NOW,
        event_count=1,
        **values,
    )
    session.add(incident)
    session.flush()
    return incident.id


def test_incident_with_identical_russian_prose_receives_the_translation() -> None:
    rule = _rule()
    with get_session_factory().begin() as session:
        sync_rules(session, (rule,))
        version_id = session.query(DetectionRuleVersion.id).scalar()
        incident_id = _legacy_incident(session, rule_version_id=version_id, rule=rule)

    with get_session_factory().begin() as session:
        assert backfill_incident_translations(session) == 1

    with get_session_factory()() as session:
        incident = session.get(Incident, incident_id)
        assert incident is not None
        assert incident.title_en == rule.title_en
        assert incident.explanation_en == rule.explanation_en
        assert incident.recommendation_en == rule.recommendation_en
        # The frozen Russian text is never rewritten, only complemented.
        assert incident.title == rule.title


def test_incident_whose_russian_prose_differs_is_left_untranslated() -> None:
    """A later version that reworded the Russian says nothing about the old text."""

    rule = _rule()
    with get_session_factory().begin() as session:
        sync_rules(session, (rule,))
        version_id = session.query(DetectionRuleVersion.id).scalar()
        incident_id = _legacy_incident(
            session,
            rule_version_id=version_id,
            rule=rule,
            title="Совершенно другой заголовок из прошлой версии правила",
        )

    with get_session_factory().begin() as session:
        assert backfill_incident_translations(session) == 0

    with get_session_factory()() as session:
        incident = session.get(Incident, incident_id)
        assert incident is not None
        assert incident.title_en is None
        assert incident.title == "Совершенно другой заголовок из прошлой версии правила"


def test_backfill_is_idempotent_and_never_overwrites_existing_prose() -> None:
    rule = _rule()
    with get_session_factory().begin() as session:
        sync_rules(session, (rule,))
        version_id = session.query(DetectionRuleVersion.id).scalar()
        incident_id = _legacy_incident(session, rule_version_id=version_id, rule=rule)

    with get_session_factory().begin() as session:
        assert backfill_incident_translations(session) == 1
    with get_session_factory().begin() as session:
        session.get(Incident, incident_id).title_en = "Operator-corrected English title"  # type: ignore[union-attr]

    with get_session_factory().begin() as session:
        assert backfill_incident_translations(session) == 0

    with get_session_factory()() as session:
        incident = session.get(Incident, incident_id)
        assert incident is not None
        assert incident.title_en == "Operator-corrected English title"
