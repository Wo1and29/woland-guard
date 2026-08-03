"""Backfill of English incident prose for incidents detected before ADR-0017.

An incident freezes its prose at detection time (ADR-0017), so incidents created
before the rules carried English text have none. This is not fixed by inventing
a translation: it is fixed only where one provably exists for exactly the text
that was frozen.

The safety condition is that a rule version's Russian prose matches the
incident's frozen Russian prose byte for byte. If it does, that version's
English fields are a translation of precisely that text, so attaching them adds
a rendering of what the incident already says rather than changing what it says.
Where no version matches -- for instance because a later version genuinely
reworded the Russian -- the incident keeps its Russian text and nothing is
guessed.
"""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from woland_guard_control_plane.infrastructure.database.models import (
    DetectionRuleVersion,
    Incident,
)


def backfill_incident_translations(session: Session) -> int:
    """Attach existing translations to incidents that froze identical Russian prose.

    Returns the number of incidents filled. Idempotent: an incident that already
    has English prose is never touched, so a corrected translation published
    later does not silently rewrite the text of a historical incident.
    """

    filled = 0
    versions = session.scalars(
        # Newest first so the most current translation of a given Russian text
        # wins; older versions with the same prose then match nothing, because
        # the rows they would have filled are no longer NULL.
        select(DetectionRuleVersion).order_by(DetectionRuleVersion.version.desc())
    ).all()
    for version in versions:
        definition = version.definition
        translated = (
            definition.get("title_en"),
            definition.get("explanation_en"),
            definition.get("recommendation_en"),
        )
        if not all(isinstance(value, str) and value for value in translated):
            continue
        russian = (
            definition.get("title"),
            definition.get("explanation"),
            definition.get("recommendation"),
        )
        if not all(isinstance(value, str) and value for value in russian):
            continue
        title_en, explanation_en, recommendation_en = translated
        title, explanation, recommendation = russian
        updated = session.scalars(
            update(Incident)
            .where(
                Incident.rule_key == version.rule_key,
                Incident.title_en.is_(None),
                Incident.title == title,
                Incident.explanation == explanation,
                Incident.recommendation == recommendation,
            )
            .values(
                title_en=title_en,
                explanation_en=explanation_en,
                recommendation_en=recommendation_en,
            )
            .returning(Incident.id)
        ).all()
        filled += len(updated)
    return filled
