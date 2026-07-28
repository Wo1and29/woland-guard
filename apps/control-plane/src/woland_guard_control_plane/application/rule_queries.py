"""Validated, transport-neutral read projections for active detection rules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, assert_never, cast
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import and_, bindparam, func, or_, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from woland_guard_control_plane.application.dashboard_pagination import (
    DashboardCursorContext,
    DashboardListType,
    DashboardPage,
    decode_dashboard_cursor,
    encode_dashboard_cursor,
)
from woland_guard_control_plane.application.dashboard_search import (
    LIKE_ESCAPE_CHARACTER,
    literal_prefix_pattern,
)
from woland_guard_control_plane.application.detection.rules import (
    DistinctCountCondition,
    FirstSeenCondition,
    RuleDefinition,
    SequenceCondition,
    SingleCondition,
    ThresholdCondition,
)
from woland_guard_control_plane.infrastructure.database.models import DetectionRuleVersion

MAX_ACTIVE_RULES_FOR_DASHBOARD = 1_000


class RuleSort(StrEnum):
    RULE_KEY_ASC = "rule_key_asc"
    RULE_KEY_DESC = "rule_key_desc"


class RuleEnabledFilter(StrEnum):
    ALL = "all"
    YES = "yes"
    NO = "no"


class RuleConditionType(StrEnum):
    SINGLE = "single"
    THRESHOLD = "threshold"
    DISTINCT_COUNT = "distinct_count"
    SEQUENCE = "sequence"
    FIRST_SEEN = "first_seen"


@dataclass(frozen=True, slots=True)
class RuleFilters:
    severities: tuple[str, ...] = ()
    enabled: RuleEnabledFilter = RuleEnabledFilter.ALL
    condition_type: RuleConditionType | None = None
    search: str | None = None

    def normalized(self) -> RuleFilters:
        return RuleFilters(
            severities=tuple(sorted(set(self.severities))),
            enabled=self.enabled,
            condition_type=self.condition_type,
            search=self.search,
        )

    def cursor_filters(self) -> dict[str, str | list[str] | None]:
        value = self.normalized()
        return {
            "condition": None if value.condition_type is None else value.condition_type.value,
            "enabled": value.enabled.value,
            "severities": list(value.severities),
        }


@dataclass(frozen=True, slots=True)
class RuleConditionSummary:
    type: str
    event_types: tuple[str, ...]
    threshold: int | None = None
    distinct_threshold: int | None = None
    minimum_events: int | None = None
    repeat_steps: tuple[int, ...] = ()
    window_seconds: int | None = None
    lookback_seconds: int | None = None
    require_prior_baseline_events: int | None = None


@dataclass(frozen=True, slots=True)
class RuleSummary:
    id: UUID
    rule_key: str
    version: int
    enabled: bool
    severity: str
    title: str
    description: str
    mitre_attack_ids: tuple[str, ...]
    condition: RuleConditionSummary


class StoredRuleDefinitionError(ValueError):
    """A safe failure identifying only the invalid stored rule row."""

    def __init__(self, rule_version_id: UUID) -> None:
        super().__init__("stored rule definition is invalid")
        self.rule_version_id = rule_version_id


class ActiveRuleSetLimitError(ValueError):
    """A safe failure when bounded active-rule validation cannot be completed."""


def list_active_rules(
    session: Session,
    *,
    filters: RuleFilters,
    sort: RuleSort,
    page_size: int,
    cursor: str | None,
) -> DashboardPage[RuleSummary]:
    """Return active definitions after strict Pydantic revalidation."""

    normalized = filters.normalized()
    statement = select(
        DetectionRuleVersion.id,
        DetectionRuleVersion.rule_key,
        DetectionRuleVersion.version,
        DetectionRuleVersion.enabled,
        DetectionRuleVersion.severity,
        DetectionRuleVersion.definition,
    ).where(DetectionRuleVersion.is_active.is_(True))
    conditions: list[ColumnElement[bool]] = []
    if normalized.severities:
        conditions.append(DetectionRuleVersion.severity.in_(normalized.severities))
    if normalized.enabled is RuleEnabledFilter.YES:
        conditions.append(DetectionRuleVersion.enabled.is_(True))
    elif normalized.enabled is RuleEnabledFilter.NO:
        conditions.append(DetectionRuleVersion.enabled.is_(False))
    if normalized.condition_type is not None:
        conditions.append(
            DetectionRuleVersion.definition["condition"]["type"].astext
            == normalized.condition_type.value
        )
    if normalized.search is not None:
        pattern = literal_prefix_pattern(normalized.search)
        parameter = func.lower(bindparam("rule_prefix_pattern", pattern))
        conditions.append(
            func.lower(DetectionRuleVersion.rule_key).like(
                parameter,
                escape=LIKE_ESCAPE_CHARACTER,
            )
        )
    context = DashboardCursorContext(
        list_type=DashboardListType.RULES,
        filters=normalized.cursor_filters(),
        search=normalized.search,
        sort=sort.value,
        page_size=page_size,
    )
    context.validate()
    if cursor is not None:
        cursor_key, cursor_id = decode_dashboard_cursor(cursor, expected=context)
        cursor_key = cast(str, cursor_key)
        cursor_id = cast(UUID, cursor_id)
        if sort is RuleSort.RULE_KEY_ASC:
            conditions.append(
                or_(
                    DetectionRuleVersion.rule_key > cursor_key,
                    and_(
                        DetectionRuleVersion.rule_key == cursor_key,
                        DetectionRuleVersion.id > cursor_id,
                    ),
                )
            )
        else:
            conditions.append(
                or_(
                    DetectionRuleVersion.rule_key < cursor_key,
                    and_(
                        DetectionRuleVersion.rule_key == cursor_key,
                        DetectionRuleVersion.id < cursor_id,
                    ),
                )
            )
    if conditions:
        statement = statement.where(*conditions)

    _validate_all_active_rules(session)
    ordering = (
        (DetectionRuleVersion.rule_key.asc(), DetectionRuleVersion.id.asc())
        if sort is RuleSort.RULE_KEY_ASC
        else (DetectionRuleVersion.rule_key.desc(), DetectionRuleVersion.id.desc())
    )
    rows = session.execute(statement.order_by(*ordering).limit(page_size + 1)).mappings().all()
    page_rows = rows[:page_size]
    items = tuple(_validated_summary(row) for row in page_rows)
    next_cursor = None
    if len(rows) > page_size and page_rows:
        last = page_rows[-1]
        next_cursor = encode_dashboard_cursor(
            context,
            keys=(last["rule_key"], last["id"]),
        )
    return DashboardPage(items, next_cursor)


def _validate_all_active_rules(session: Session) -> None:
    """Fail closed if any active definition is invalid, independent of list filters."""

    rows = (
        session.execute(
            select(
                DetectionRuleVersion.id,
                DetectionRuleVersion.rule_key,
                DetectionRuleVersion.version,
                DetectionRuleVersion.enabled,
                DetectionRuleVersion.severity,
                DetectionRuleVersion.definition,
            )
            .where(DetectionRuleVersion.is_active.is_(True))
            .order_by(DetectionRuleVersion.id.asc())
            .limit(MAX_ACTIVE_RULES_FOR_DASHBOARD + 1)
        )
        .mappings()
        .all()
    )
    if len(rows) > MAX_ACTIVE_RULES_FOR_DASHBOARD:
        raise ActiveRuleSetLimitError("active rule validation limit exceeded")
    for row in rows:
        _validated_summary(row)


def _validated_summary(row: RowMapping | Mapping[str, Any]) -> RuleSummary:
    try:
        definition = RuleDefinition.model_validate(row["definition"])
    except ValidationError:
        raise StoredRuleDefinitionError(row["id"]) from None
    if (
        definition.rule_key != row["rule_key"]
        or definition.version != row["version"]
        or definition.enabled is not row["enabled"]
        or definition.severity.value != row["severity"]
    ):
        raise StoredRuleDefinitionError(row["id"])
    return RuleSummary(
        id=row["id"],
        rule_key=definition.rule_key,
        version=definition.version,
        enabled=definition.enabled,
        severity=definition.severity.value,
        title=definition.title,
        description=definition.description,
        mitre_attack_ids=definition.mitre_attack_ids,
        condition=_condition_summary(definition),
    )


def _condition_summary(rule: RuleDefinition) -> RuleConditionSummary:
    condition = rule.condition
    if isinstance(condition, SingleCondition):
        return RuleConditionSummary(condition.type, (condition.event_type.value,))
    if isinstance(condition, ThresholdCondition):
        return RuleConditionSummary(
            condition.type,
            (condition.event_type.value,),
            threshold=condition.threshold,
            window_seconds=condition.window_seconds,
        )
    if isinstance(condition, DistinctCountCondition):
        return RuleConditionSummary(
            condition.type,
            (condition.event_type.value,),
            distinct_threshold=condition.distinct_threshold,
            minimum_events=condition.minimum_events,
            window_seconds=condition.window_seconds,
        )
    if isinstance(condition, SequenceCondition):
        return RuleConditionSummary(
            condition.type,
            tuple(step.event_type.value for step in condition.steps),
            repeat_steps=tuple(step.repeat_at_least for step in condition.steps),
            window_seconds=condition.window_seconds,
        )
    if isinstance(condition, FirstSeenCondition):
        return RuleConditionSummary(
            condition.type,
            (condition.event_type.value,),
            lookback_seconds=condition.lookback_seconds,
            require_prior_baseline_events=condition.require_prior_baseline_events,
        )
    assert_never(condition)
