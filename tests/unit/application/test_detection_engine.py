"""Deterministic unit tests for all Detection Engine condition types and defaults."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from woland_guard_control_plane.application.detection.engine import evaluate_rule
from woland_guard_control_plane.application.detection.rules import (
    RuleDefinition,
    load_rules_directory,
)
from woland_guard_control_plane.infrastructure.database.models import Event

RULES_DIR = Path(__file__).parents[3] / "detection-rules"
BASE_TIME = datetime(2026, 1, 1, 12, tzinfo=UTC)
SERVER_A = UUID("10000000-0000-4000-8000-000000000001")
SERVER_B = UUID("10000000-0000-4000-8000-000000000002")


@dataclass(frozen=True, slots=True)
class Scenario:
    trigger: Event
    history: tuple[Event, ...]


def _rules() -> dict[str, RuleDefinition]:
    return {rule.rule_key: rule for rule in load_rules_directory(RULES_DIR)}


def _event(
    event_type: str,
    seconds: int,
    *,
    server_id: UUID = SERVER_A,
    actor: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    attributes: dict[str, object] | None = None,
) -> Event:
    occurred_at = BASE_TIME + timedelta(seconds=seconds)
    return Event(
        id=uuid4(),
        server_id=server_id,
        agent_event_id=uuid4(),
        schema_version=1,
        source="journald",
        event_type=event_type,
        occurred_at=occurred_at,
        collected_at=occurred_at,
        persisted_at=occurred_at,
        payload={
            "schema_version": 1,
            "event_id": str(uuid4()),
            "occurred_at": occurred_at.isoformat(),
            "collected_at": occurred_at.isoformat(),
            "source": "journald",
            "event_type": event_type,
            "actor": actor,
            "source_ip": source_ip,
            "summary": "synthetic detection test",
            "attributes": attributes or {},
        },
    )


def _scenario(rule_key: str, *, positive: bool) -> Scenario:
    if rule_key == "ssh_bruteforce_by_ip":
        count = 8 if positive else 7
        history = tuple(
            _event("linux.ssh.authentication_failed", offset) for offset in range(-(count - 1), 1)
        )
    elif rule_key == "ssh_password_spray_by_ip":
        actors = [f"user-{index}" for index in range(5)] if positive else ["same-user"] * 5
        history = tuple(
            _event("linux.ssh.authentication_failed", index - 4, actor=actor)
            for index, actor in enumerate(actors)
        )
    elif rule_key == "ssh_success_after_failures":
        failures = tuple(
            _event("linux.ssh.authentication_failed", offset)
            for offset in ((-3, -2, -1) if positive else (1, 2, 3))
        )
        trigger = _event("linux.ssh.login_succeeded", 0)
        return Scenario(trigger, (*failures, trigger))
    elif rule_key == "ssh_login_from_new_ip":
        baseline_ip = "192.0.2.1"
        trigger_ip = "192.0.2.2" if positive else baseline_ip
        baseline = _event("linux.ssh.login_succeeded", -1, source_ip=baseline_ip)
        trigger = _event("linux.ssh.login_succeeded", 0, source_ip=trigger_ip)
        return Scenario(trigger, (baseline, trigger))
    elif rule_key == "ssh_root_login_success":
        trigger = _event(
            "linux.ssh.login_succeeded",
            0,
            actor="root" if positive else "alice",
        )
        return Scenario(trigger, (trigger,))
    elif rule_key == "sudo_auth_failures":
        count = 5 if positive else 4
        history = tuple(
            _event("linux.sudo.authentication_failed", offset, source_ip=None)
            for offset in range(-(count - 1), 1)
        )
    elif rule_key == "user_account_created":
        trigger = _event(
            "linux.account.user_created" if positive else "linux.ssh.login_succeeded",
            0,
            source_ip=None,
        )
        return Scenario(trigger, (trigger,))
    elif rule_key == "privileged_group_membership_changed":
        attributes: dict[str, object] = {"group": "sudo", "action": "added"}
        if not positive:
            attributes["group"] = "users"
        trigger = _event(
            "linux.account.privileged_group_changed",
            0,
            source_ip=None,
            attributes=attributes,
        )
        return Scenario(trigger, (trigger,))
    else:  # pragma: no cover - the shipped rule key set is asserted separately
        raise AssertionError(f"unknown test scenario: {rule_key}")
    return Scenario(history[-1], history)


@pytest.mark.parametrize("rule_key", sorted(_rules()))
def test_each_default_rule_has_positive_scenario(rule_key: str) -> None:
    """Every shipped journald rule produces a deterministic match for its exact default."""

    rule = _rules()[rule_key]
    scenario = _scenario(rule_key, positive=True)

    match = evaluate_rule(rule, trigger=scenario.trigger, history=scenario.history)

    assert match is not None
    assert scenario.trigger in match.evidence


@pytest.mark.parametrize("rule_key", sorted(_rules()))
def test_each_default_rule_has_negative_scenario(rule_key: str) -> None:
    """Every shipped rule also has a close non-matching synthetic scenario."""

    rule = _rules()[rule_key]
    scenario = _scenario(rule_key, positive=False)

    assert evaluate_rule(rule, trigger=scenario.trigger, history=scenario.history) is None


@pytest.mark.parametrize(
    ("rule_key", "condition_type"),
    [
        ("ssh_root_login_success", "single"),
        ("ssh_bruteforce_by_ip", "threshold"),
        ("ssh_password_spray_by_ip", "distinct_count"),
        ("ssh_success_after_failures", "sequence"),
        ("ssh_login_from_new_ip", "first_seen"),
    ],
)
def test_all_five_condition_types_match(rule_key: str, condition_type: str) -> None:
    """The five allowed condition implementations are each executable without expressions."""

    rule = _rules()[rule_key]
    scenario = _scenario(rule_key, positive=True)

    assert rule.condition.type == condition_type
    assert evaluate_rule(rule, trigger=scenario.trigger, history=scenario.history) is not None


@pytest.mark.parametrize("rule_key", sorted(_rules()))
def test_each_default_rule_rejects_missing_correlation_field(rule_key: str) -> None:
    """Null or absent mandatory correlation data never creates a match."""

    rule = _rules()[rule_key]
    scenario = _scenario(rule_key, positive=True)
    missing_field = rule.correlation_fields[0]
    payload = scenario.trigger.payload
    attributes = payload["attributes"]
    if missing_field in payload:
        payload[missing_field] = None
    elif isinstance(attributes, dict):
        attributes.pop(missing_field, None)

    assert evaluate_rule(rule, trigger=scenario.trigger, history=scenario.history) is None


@pytest.mark.parametrize(
    ("rule_key", "threshold", "event_type"),
    [
        ("ssh_bruteforce_by_ip", 8, "linux.ssh.authentication_failed"),
        ("sudo_auth_failures", 5, "linux.sudo.authentication_failed"),
    ],
)
def test_threshold_rules_are_below_then_match_at_exact_count(
    rule_key: str,
    threshold: int,
    event_type: str,
) -> None:
    """Threshold is inclusive at N and not satisfied by N minus one events."""

    rule = _rules()[rule_key]
    exact = tuple(_event(event_type, offset) for offset in range(-(threshold - 1), 1))

    assert evaluate_rule(rule, trigger=exact[-2], history=exact[:-1]) is None
    assert evaluate_rule(rule, trigger=exact[-1], history=exact) is not None


@pytest.mark.parametrize(
    ("rule_key", "event_type", "threshold", "window_seconds"),
    [
        ("ssh_bruteforce_by_ip", "linux.ssh.authentication_failed", 8, 300),
        ("sudo_auth_failures", "linux.sudo.authentication_failed", 5, 600),
    ],
)
def test_threshold_windows_include_exact_boundary_and_exclude_one_second_before(
    rule_key: str,
    event_type: str,
    threshold: int,
    window_seconds: int,
) -> None:
    """Threshold windows use trigger-window <= occurred_at <= trigger."""

    rule = _rules()[rule_key]
    trigger = _event(event_type, 0)
    recent = tuple(_event(event_type, -index) for index in range(1, threshold - 1))
    exact_boundary = _event(event_type, -window_seconds)
    outside = _event(event_type, -window_seconds - 1)

    assert (
        evaluate_rule(
            rule,
            trigger=trigger,
            history=(*recent, exact_boundary, trigger),
        )
        is not None
    )
    assert (
        evaluate_rule(
            rule,
            trigger=trigger,
            history=(*recent, outside, trigger),
        )
        is None
    )


def test_password_spray_requires_five_distinct_actors_and_minimum_five_events() -> None:
    """Repeated attempts for one actor never inflate distinct_count."""

    rule = _rules()["ssh_password_spray_by_ip"]
    same_actor = tuple(
        _event("linux.ssh.authentication_failed", offset, actor="same") for offset in range(-4, 1)
    )
    different_actors = tuple(
        _event("linux.ssh.authentication_failed", offset, actor=f"user-{offset}")
        for offset in range(-4, 1)
    )

    assert evaluate_rule(rule, trigger=same_actor[-1], history=same_actor) is None
    assert (
        evaluate_rule(
            rule,
            trigger=different_actors[-2],
            history=different_actors[:-1],
        )
        is None
    )
    assert (
        evaluate_rule(
            rule,
            trigger=different_actors[-1],
            history=different_actors,
        )
        is not None
    )
    different_actors[-1].payload["actor"] = None
    assert (
        evaluate_rule(
            rule,
            trigger=different_actors[-1],
            history=different_actors,
        )
        is None
    )


def test_password_spray_window_boundary_is_inclusive() -> None:
    """A distinct actor exactly 600 seconds before the trigger remains in the count."""

    rule = _rules()["ssh_password_spray_by_ip"]
    trigger = _event("linux.ssh.authentication_failed", 0, actor="user-5")
    recent = tuple(
        _event("linux.ssh.authentication_failed", -index, actor=f"user-{index}")
        for index in range(1, 4)
    )
    boundary = _event("linux.ssh.authentication_failed", -600, actor="user-4")
    outside = _event("linux.ssh.authentication_failed", -601, actor="user-4")

    assert evaluate_rule(rule, trigger=trigger, history=(*recent, boundary, trigger)) is not None
    assert evaluate_rule(rule, trigger=trigger, history=(*recent, outside, trigger)) is None


def test_sequence_requires_three_failures_strictly_before_success_in_same_group() -> None:
    """A success before failures or failures for another actor/IP cannot finish a sequence."""

    rule = _rules()["ssh_success_after_failures"]
    success = _event("linux.ssh.login_succeeded", 0)
    later_failures = tuple(_event("linux.ssh.authentication_failed", value) for value in (1, 2, 3))
    wrong_group = (
        _event("linux.ssh.authentication_failed", -3, actor="bob"),
        _event("linux.ssh.authentication_failed", -2, source_ip="192.0.2.99"),
        _event("linux.ssh.authentication_failed", -1, actor="bob"),
    )

    assert evaluate_rule(rule, trigger=success, history=(success, *later_failures)) is None
    assert evaluate_rule(rule, trigger=success, history=(*wrong_group, success)) is None


def test_sequence_window_boundary_is_inclusive_but_order_remains_strict() -> None:
    """The first failure may be exactly 900 seconds before a later success."""

    rule = _rules()["ssh_success_after_failures"]
    success = _event("linux.ssh.login_succeeded", 0)
    exact = tuple(_event("linux.ssh.authentication_failed", value) for value in (-900, -2, -1))
    outside = tuple(_event("linux.ssh.authentication_failed", value) for value in (-901, -2, -1))

    assert evaluate_rule(rule, trigger=success, history=(*exact, success)) is not None
    assert evaluate_rule(rule, trigger=success, history=(*outside, success)) is None


def test_first_seen_builds_baseline_then_matches_new_but_not_known_ip() -> None:
    """The first login is baseline-only; a new address matches and a known address does not."""

    rule = _rules()["ssh_login_from_new_ip"]
    first = _event("linux.ssh.login_succeeded", -1, source_ip="192.0.2.1")
    new_ip = _event("linux.ssh.login_succeeded", 0, source_ip="192.0.2.2")
    known_ip = _event("linux.ssh.login_succeeded", 0, source_ip="192.0.2.1")

    assert evaluate_rule(rule, trigger=first, history=(first,)) is None
    assert evaluate_rule(rule, trigger=new_ip, history=(first, new_ip)) is not None
    assert evaluate_rule(rule, trigger=known_ip, history=(first, known_ip)) is None
    new_ip.payload["source_ip"] = None
    assert evaluate_rule(rule, trigger=new_ip, history=(first, new_ip)) is None


def test_first_seen_lookback_includes_exact_boundary_and_excludes_older_baseline() -> None:
    """The baseline requirement uses the same inclusive occurred_at boundary."""

    rule = _rules()["ssh_login_from_new_ip"]
    trigger = _event("linux.ssh.login_succeeded", 0, source_ip="192.0.2.2")
    boundary = _event("linux.ssh.login_succeeded", -2_592_000, source_ip="192.0.2.1")
    outside = _event("linux.ssh.login_succeeded", -2_592_001, source_ip="192.0.2.1")

    assert evaluate_rule(rule, trigger=trigger, history=(boundary, trigger)) is not None
    assert evaluate_rule(rule, trigger=trigger, history=(outside, trigger)) is None


@pytest.mark.parametrize(
    "rule_key",
    [
        "ssh_bruteforce_by_ip",
        "ssh_password_spray_by_ip",
        "ssh_success_after_failures",
        "ssh_login_from_new_ip",
        "sudo_auth_failures",
    ],
)
def test_history_from_another_server_cannot_complete_windowed_rule(rule_key: str) -> None:
    """Each window and sequence is isolated by server_id even if correlation fields match."""

    rule = _rules()[rule_key]
    scenario = _scenario(rule_key, positive=True)
    cross_server_history = tuple(
        event
        if event is scenario.trigger
        else _event(
            event.event_type,
            int((event.occurred_at - BASE_TIME).total_seconds()),
            server_id=SERVER_B,
            actor=event.payload.get("actor"),
            source_ip=event.payload.get("source_ip"),
            attributes=event.payload.get("attributes"),
        )
        for event in scenario.history
    )

    assert (
        evaluate_rule(
            rule,
            trigger=scenario.trigger,
            history=cross_server_history,
        )
        is None
    )


def test_disabled_rule_is_not_evaluated() -> None:
    """An explicitly disabled active definition remains inert."""

    rule = _rules()["ssh_root_login_success"].model_copy(update={"enabled": False})
    scenario = _scenario("ssh_root_login_success", positive=True)

    assert evaluate_rule(rule, trigger=scenario.trigger, history=scenario.history) is None


@pytest.mark.parametrize(
    "rule_key",
    [
        "ssh_root_login_success",
        "user_account_created",
        "privileged_group_membership_changed",
    ],
)
def test_single_rules_have_exactly_one_event_threshold_and_no_history_window(
    rule_key: str,
) -> None:
    """For single rules, exact threshold is one trigger and no time window is defined."""

    rule = _rules()[rule_key]
    scenario = _scenario(rule_key, positive=True)
    unrelated_other_server = _event(
        "linux.ssh.authentication_failed",
        -1_000_000,
        server_id=SERVER_B,
    )

    assert evaluate_rule(rule, trigger=scenario.trigger, history=()) is not None
    assert (
        evaluate_rule(
            rule,
            trigger=scenario.trigger,
            history=(unrelated_other_server,),
        )
        is not None
    )
