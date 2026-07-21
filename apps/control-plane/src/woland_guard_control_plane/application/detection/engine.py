"""Deterministic event correlation and transactional incident persistence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from pydantic import JsonValue, ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.detection.rules import (
    DistinctCountCondition,
    FieldMatcher,
    FirstSeenCondition,
    RuleDefinition,
    SequenceCondition,
    SingleCondition,
    ThresholdCondition,
    canonical_rule,
)
from woland_guard_control_plane.infrastructure.database.models import (
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentStatus,
)

_MISSING = object()


class DetectionEngineError(RuntimeError):
    """A safe failure that causes the surrounding ingestion transaction to roll back."""


@dataclass(frozen=True, slots=True)
class DetectionMatch:
    correlation: dict[str, JsonValue]
    evidence: tuple[Event, ...]


@dataclass(frozen=True, slots=True)
class DetectionResult:
    matched_rules: int = 0
    created_incidents: int = 0
    linked_evidence: int = 0


def run_detection(session: Session, *, new_events: Sequence[Event]) -> DetectionResult:
    """Evaluate only newly inserted rows inside the caller's open transaction."""

    if not new_events:
        return DetectionResult()
    stored_rules = session.scalars(
        select(DetectionRuleVersion)
        .where(
            DetectionRuleVersion.is_active.is_(True),
            DetectionRuleVersion.enabled.is_(True),
        )
        .order_by(DetectionRuleVersion.rule_key)
    ).all()
    try:
        rules = [
            (stored, RuleDefinition.model_validate(stored.definition)) for stored in stored_rules
        ]
    except ValidationError as error:
        raise DetectionEngineError("an active rule definition is invalid") from error

    matched_rules = 0
    created_incidents = 0
    linked_evidence = 0
    for trigger in sorted(new_events, key=lambda event: (event.occurred_at, event.id)):
        for stored_rule, rule in rules:
            if not _can_trigger(rule, trigger):
                continue
            correlation = _correlation(rule, trigger)
            if correlation is None:
                continue
            correlation_hash = _correlation_hash(correlation)
            _acquire_correlation_lock(
                session,
                server_id=trigger.server_id,
                rule_version_id=stored_rule.id,
                correlation_hash=correlation_hash,
            )
            history = _load_history(session, rule=rule, trigger=trigger)
            match = evaluate_rule(rule, trigger=trigger, history=history)
            if match is None:
                continue
            created, linked = _persist_match(
                session,
                stored_rule=stored_rule,
                rule=rule,
                trigger=trigger,
                match=match,
                correlation_hash=correlation_hash,
            )
            matched_rules += 1
            created_incidents += int(created)
            linked_evidence += linked
    return DetectionResult(matched_rules, created_incidents, linked_evidence)


def evaluate_rule(
    rule: RuleDefinition,
    *,
    trigger: Event,
    history: Sequence[Event],
) -> DetectionMatch | None:
    """Evaluate one rule with an explicit, server-isolated event history."""

    if not rule.enabled or not _can_trigger(rule, trigger):
        return None
    correlation = _correlation(rule, trigger)
    if correlation is None:
        return None
    same_server = tuple(event for event in history if event.server_id == trigger.server_id)
    condition = rule.condition
    if isinstance(condition, SingleCondition):
        return DetectionMatch(correlation, (trigger,))
    if isinstance(condition, ThresholdCondition):
        return _evaluate_threshold(condition, trigger, same_server, correlation)
    if isinstance(condition, DistinctCountCondition):
        return _evaluate_distinct(condition, trigger, same_server, correlation)
    if isinstance(condition, SequenceCondition):
        return _evaluate_sequence(rule, condition, trigger, same_server, correlation)
    if isinstance(condition, FirstSeenCondition):
        return _evaluate_first_seen(condition, trigger, same_server, correlation)
    raise DetectionEngineError("unsupported condition type")


def _evaluate_threshold(
    condition: ThresholdCondition,
    trigger: Event,
    history: Sequence[Event],
    correlation: dict[str, JsonValue],
) -> DetectionMatch | None:
    group = _field_group(trigger, condition.group_by)
    if group is None:
        return None
    start = trigger.occurred_at - timedelta(seconds=condition.window_seconds)
    evidence = tuple(
        event
        for event in history
        if start <= event.occurred_at <= trigger.occurred_at
        and _matches_event(event, condition.event_type.value, condition.filters)
        and _field_group(event, condition.group_by) == group
    )
    if len(evidence) < condition.threshold:
        return None
    return DetectionMatch(correlation, _unique_events(evidence))


def _evaluate_distinct(
    condition: DistinctCountCondition,
    trigger: Event,
    history: Sequence[Event],
    correlation: dict[str, JsonValue],
) -> DetectionMatch | None:
    group = _field_group(trigger, condition.group_by)
    if group is None:
        return None
    start = trigger.occurred_at - timedelta(seconds=condition.window_seconds)
    evidence: list[Event] = []
    distinct_values: set[str] = set()
    for event in history:
        if not start <= event.occurred_at <= trigger.occurred_at:
            continue
        if not _matches_event(event, condition.event_type.value, condition.filters):
            continue
        if _field_group(event, condition.group_by) != group:
            continue
        value = _field_value(event, condition.distinct_field)
        if value is _MISSING:
            continue
        evidence.append(event)
        distinct_values.add(_canonical_value(cast(JsonValue, value)))
    if (
        len(evidence) < condition.minimum_events
        or len(distinct_values) < condition.distinct_threshold
    ):
        return None
    return DetectionMatch(correlation, _unique_events(evidence))


def _evaluate_sequence(
    rule: RuleDefinition,
    condition: SequenceCondition,
    trigger: Event,
    history: Sequence[Event],
    correlation: dict[str, JsonValue],
) -> DetectionMatch | None:
    start = trigger.occurred_at - timedelta(seconds=condition.window_seconds)
    candidates = [
        event
        for event in history
        if start <= event.occurred_at <= trigger.occurred_at
        and _field_group(event, rule.correlation_fields)
        == _field_group(trigger, rule.correlation_fields)
    ]
    selected: list[Event] = []
    upper_bound = trigger.occurred_at
    for reverse_index, step in enumerate(reversed(condition.steps)):
        step_candidates = [
            event
            for event in candidates
            if _matches_event(event, step.event_type.value, step.filters)
            and (
                event.occurred_at <= upper_bound
                if reverse_index == 0
                else event.occurred_at < upper_bound
            )
        ]
        if reverse_index == 0:
            if trigger not in step_candidates:
                return None
            chosen = [trigger]
            remaining = [event for event in step_candidates if event.id != trigger.id]
            chosen.extend(
                sorted(remaining, key=lambda event: (event.occurred_at, event.id), reverse=True)[
                    : step.repeat_at_least - 1
                ]
            )
        else:
            chosen = sorted(
                step_candidates,
                key=lambda event: (event.occurred_at, event.id),
                reverse=True,
            )[: step.repeat_at_least]
        if len(chosen) < step.repeat_at_least:
            return None
        selected.extend(chosen)
        upper_bound = min(event.occurred_at for event in chosen)
    return DetectionMatch(correlation, _unique_events(selected))


def _evaluate_first_seen(
    condition: FirstSeenCondition,
    trigger: Event,
    history: Sequence[Event],
    correlation: dict[str, JsonValue],
) -> DetectionMatch | None:
    value = _field_value(trigger, condition.value_field)
    scope = _field_group(trigger, condition.scope_fields)
    if value is _MISSING or scope is None:
        return None
    start = trigger.occurred_at - timedelta(seconds=condition.lookback_seconds)
    baseline = tuple(
        event
        for event in history
        if event.id != trigger.id
        and start <= event.occurred_at <= trigger.occurred_at
        and _matches_event(event, condition.event_type.value, condition.filters)
        and _field_group(event, condition.scope_fields) == scope
    )
    if len(baseline) < condition.require_prior_baseline_events:
        return None
    current_value = _canonical_value(cast(JsonValue, value))
    if any(
        _field_value(event, condition.value_field) is not _MISSING
        and _canonical_value(cast(JsonValue, _field_value(event, condition.value_field)))
        == current_value
        for event in baseline
    ):
        return None
    return DetectionMatch(correlation, _unique_events((*baseline, trigger)))


def _load_history(session: Session, *, rule: RuleDefinition, trigger: Event) -> tuple[Event, ...]:
    condition = rule.condition
    if isinstance(condition, SingleCondition):
        return (trigger,)
    if isinstance(condition, SequenceCondition):
        event_types = tuple(step.event_type.value for step in condition.steps)
        window_seconds = condition.window_seconds
    elif isinstance(condition, FirstSeenCondition):
        event_types = (condition.event_type.value,)
        window_seconds = condition.lookback_seconds
    else:
        event_types = (condition.event_type.value,)
        window_seconds = condition.window_seconds
    start = trigger.occurred_at - timedelta(seconds=window_seconds)
    return tuple(
        session.scalars(
            select(Event)
            .where(
                Event.server_id == trigger.server_id,
                Event.event_type.in_(event_types),
                Event.occurred_at >= start,
                Event.occurred_at <= trigger.occurred_at,
            )
            .order_by(Event.occurred_at, Event.id)
        ).all()
    )


def _can_trigger(rule: RuleDefinition, trigger: Event) -> bool:
    condition = rule.condition
    if isinstance(condition, SequenceCondition):
        last_step = condition.steps[-1]
        return _matches_event(trigger, last_step.event_type.value, last_step.filters)
    return _matches_event(trigger, condition.event_type.value, condition.filters)


def _matches_event(
    event: Event,
    event_type: str,
    filters: Mapping[str, FieldMatcher],
) -> bool:
    if event.event_type != event_type:
        return False
    for field_name, matcher in filters.items():
        value = _field_value(event, field_name)
        if value is _MISSING:
            return False
        if matcher.equals is not None and value != matcher.equals:
            return False
        if matcher.one_of is not None and value not in matcher.one_of:
            return False
    return True


def _correlation(rule: RuleDefinition, trigger: Event) -> dict[str, JsonValue] | None:
    values: dict[str, JsonValue] = {}
    for field_name in rule.correlation_fields:
        value = _field_value(trigger, field_name)
        if value is _MISSING:
            return None
        values[field_name] = cast(JsonValue, value)
    return values


def _field_group(event: Event, fields: Sequence[str]) -> tuple[str, ...] | None:
    values: list[str] = []
    for field_name in fields:
        value = _field_value(event, field_name)
        if value is _MISSING:
            return None
        values.append(_canonical_value(cast(JsonValue, value)))
    return tuple(values)


def _field_value(event: Event, path: str) -> object:
    payload: object = event.payload
    parts = path.split(".")
    if isinstance(payload, Mapping) and parts[0] not in payload:
        attributes = payload.get("attributes")
        if isinstance(attributes, Mapping) and parts[0] in attributes:
            payload = attributes
    current = payload
    for part in parts:
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return _MISSING if current is None else current


def _canonical_value(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _correlation_hash(correlation: dict[str, JsonValue]) -> str:
    return hashlib.sha256(_canonical_value(correlation).encode("utf-8")).hexdigest()


def _acquire_correlation_lock(
    session: Session,
    *,
    server_id: UUID,
    rule_version_id: UUID,
    correlation_hash: str,
) -> None:
    """Serialize history reads for one server/rule-version/correlation bucket."""

    lock_material = f"{server_id}:{rule_version_id}:{correlation_hash}".encode()
    lock_key = int.from_bytes(hashlib.sha256(lock_material).digest()[:8], "big", signed=True)
    session.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": lock_key})


def _unique_events(events: Sequence[Event]) -> tuple[Event, ...]:
    unique = {event.id: event for event in events}
    return tuple(sorted(unique.values(), key=lambda event: (event.occurred_at, event.id)))


def _persist_match(
    session: Session,
    *,
    stored_rule: DetectionRuleVersion,
    rule: RuleDefinition,
    trigger: Event,
    match: DetectionMatch,
    correlation_hash: str,
) -> tuple[bool, int]:
    incident = session.scalar(
        select(Incident).where(
            Incident.server_id == trigger.server_id,
            Incident.rule_version_id == stored_rule.id,
            Incident.rule_key == rule.rule_key,
            Incident.correlation_hash == correlation_hash,
            Incident.status.in_((IncidentStatus.NEW.value, IncidentStatus.INVESTIGATING.value)),
        )
    )
    evidence_times = [event.occurred_at for event in match.evidence]
    created = incident is None
    if incident is None:
        incident = Incident(
            server_id=trigger.server_id,
            rule_version_id=stored_rule.id,
            rule_key=rule.rule_key,
            rule_version=rule.version,
            severity=rule.severity.value,
            status=IncidentStatus.NEW.value,
            title=rule.title,
            explanation=rule.explanation,
            recommendation=rule.recommendation,
            correlation=match.correlation,
            correlation_hash=correlation_hash,
            rule_snapshot=canonical_rule(rule),
            first_seen_at=min(evidence_times),
            last_seen_at=max(evidence_times),
            event_count=len(match.evidence),
        )
        session.add(incident)
        session.flush()

    evidence_values = [
        {"incident_id": incident.id, "event_id": event.id} for event in match.evidence
    ]
    linked_ids = session.scalars(
        insert(IncidentEvent)
        .values(evidence_values)
        .on_conflict_do_nothing(constraint="pk_incident_events")
        .returning(IncidentEvent.event_id)
    ).all()
    incident.first_seen_at = min(incident.first_seen_at, min(evidence_times))
    incident.last_seen_at = max(incident.last_seen_at, max(evidence_times))
    incident.event_count = cast(
        int,
        session.scalar(
            select(func.count())
            .select_from(IncidentEvent)
            .where(IncidentEvent.incident_id == incident.id)
        ),
    )
    incident.updated_at = datetime.now(UTC)
    return created, len(linked_ids)
