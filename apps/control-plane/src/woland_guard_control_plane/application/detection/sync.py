"""Atomic persistence and activation of fully validated rule sets."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.detection.rules import (
    RuleDefinition,
    canonical_rule,
    rule_checksum,
)
from woland_guard_control_plane.infrastructure.database.models import DetectionRuleVersion


class RuleSyncError(ValueError):
    """A safe conflict raised before an immutable rule would be rewritten."""


def sync_rules(
    session: Session,
    rules: tuple[RuleDefinition, ...],
    *,
    activated_at: datetime | None = None,
) -> int:
    """Append missing versions and atomically activate the requested set."""

    activation_time = (activated_at or datetime.now(UTC)).astimezone(UTC)
    targets: list[DetectionRuleVersion] = []
    for rule in rules:
        checksum = rule_checksum(rule)
        existing = session.scalar(
            select(DetectionRuleVersion).where(
                DetectionRuleVersion.rule_key == rule.rule_key,
                DetectionRuleVersion.version == rule.version,
            )
        )
        if existing is not None:
            if existing.checksum.strip() != checksum:
                raise RuleSyncError(
                    f"immutable rule version conflicts with database: {rule.rule_key}"
                )
            targets.append(existing)
            continue

        duplicate_definition = session.scalar(
            select(DetectionRuleVersion.id).where(
                DetectionRuleVersion.rule_key == rule.rule_key,
                DetectionRuleVersion.checksum == checksum,
            )
        )
        if duplicate_definition is not None:
            raise RuleSyncError(
                f"rule definition already exists under another version: {rule.rule_key}"
            )
        stored = DetectionRuleVersion(
            rule_key=rule.rule_key,
            version=rule.version,
            schema_version=rule.schema_version,
            enabled=rule.enabled,
            severity=rule.severity.value,
            checksum=checksum,
            definition=canonical_rule(rule),
            is_active=False,
        )
        session.add(stored)
        session.flush()
        targets.append(stored)

    for stored in targets:
        session.execute(
            update(DetectionRuleVersion)
            .where(
                DetectionRuleVersion.rule_key == stored.rule_key,
                DetectionRuleVersion.is_active.is_(True),
                DetectionRuleVersion.id != stored.id,
            )
            .values(is_active=False)
        )
        if not stored.is_active:
            stored.is_active = True
            stored.activated_at = activation_time
    session.flush()
    return len(targets)
