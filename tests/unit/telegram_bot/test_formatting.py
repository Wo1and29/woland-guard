from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from woland_guard_control_plane.application.dashboard_overview import (
    DashboardOverview,
    IncidentOverviewCounts,
    ServerOverviewCounts,
)
from woland_guard_control_plane.application.incident_queries import DashboardIncidentSummary
from woland_guard_control_plane.application.ip_block_policy import BlockTargetRejectionReason
from woland_guard_control_plane.application.ip_blocks import DecideIpBlockStatus, IpBlockPlanSummary
from woland_guard_control_plane.application.outbox_worker import QueueStatistics
from woland_guard_control_plane.application.server_queries import ServerSummary
from woland_guard_control_plane.telegram_bot import formatting

MOMENT = datetime(2026, 8, 2, 9, 30, tzinfo=UTC)
INCIDENT_ID = UUID("11111111-1111-4111-8111-111111111111")
SERVER_ID = UUID("22222222-2222-4222-8222-222222222222")
PLAN_ID = UUID("33333333-3333-4333-8333-333333333333")
OPERATOR_ID = UUID("44444444-4444-4444-8444-444444444444")


def _server(**overrides: object) -> ServerSummary:
    values: dict[str, object] = {
        "id": SERVER_ID,
        "name": "prod-web-01",
        "hostname": "prod-web-01.internal",
        "description": None,
        "is_active": True,
        "last_event_at": MOMENT,
        "incident_count": 4,
        "active_incident_count": 2,
        "critical_active_incident_count": 1,
        "created_at": MOMENT,
        "updated_at": MOMENT,
    }
    values.update(overrides)
    return ServerSummary(**values)  # type: ignore[arg-type]


def _incident(**overrides: object) -> DashboardIncidentSummary:
    values: dict[str, object] = {
        "id": INCIDENT_ID,
        "server_id": SERVER_ID,
        "server_name": "prod-web-01",
        "rule_key": "ssh_bruteforce_by_ip",
        "rule_version": 1,
        "severity": "high",
        "status": "new",
        "title": "Перебор SSH-паролей с одного IP",
        "first_seen_at": MOMENT,
        "last_seen_at": MOMENT,
        "event_count": 8,
        "version": 1,
        "created_at": MOMENT,
        "updated_at": MOMENT,
    }
    values.update(overrides)
    return DashboardIncidentSummary(**values)  # type: ignore[arg-type]


def test_overview_reports_only_aggregate_counters() -> None:
    overview = DashboardOverview(
        servers=ServerOverviewCounts(total=3, active=2, inactive=1),
        incidents=IncidentOverviewCounts(active=5, critical_active=2),
        notifications=QueueStatistics(
            pending=1,
            processing=0,
            delivered=9,
            failed=0,
            ready=1,
            expired=0,
            oldest_pending_age_seconds=12,
        ),
        recent_incidents=(),
    )

    rendered = formatting.format_overview(overview)

    assert "Серверы: 3" in rendered
    assert "Открытых инцидентов: 5" in rendered
    assert "доставлены: 9" in rendered


def test_servers_render_allowlisted_fields_only() -> None:
    rendered = formatting.format_servers((_server(),), truncated=False)

    assert "prod-web-01" in rendered
    assert "prod-web-01.internal" in rendered
    assert "открытых инцидентов: 2" in rendered
    assert "Показаны не все записи" not in rendered


def test_truncation_is_announced_without_leaking_the_remainder() -> None:
    rendered = formatting.format_servers((_server(),), truncated=True)

    assert "Показаны не все записи" in rendered


def test_incident_list_includes_identifier_and_severity() -> None:
    rendered = formatting.format_incidents(
        (_incident(),),
        truncated=False,
        empty_text="пусто",
    )

    assert "[high]" in rendered
    assert str(INCIDENT_ID) in rendered
    assert "событий: 8" in rendered


def test_empty_incident_list_uses_the_caller_supplied_text() -> None:
    assert (
        formatting.format_incidents((), truncated=False, empty_text="Инцидентов нет.")
        == "Инцидентов нет."
    )


@pytest.mark.parametrize(
    "hostile",
    [
        "line\nbreak",
        "carriage\rreturn",
        "null\x00byte",
        "zero​width",
        "para separator",
    ],
)
def test_stored_values_never_carry_control_characters_into_a_reply(hostile: str) -> None:
    rendered = formatting.format_servers((_server(name=hostile),), truncated=False)

    for character in ("\n\n\n", "\r", "\x00", "​", " "):
        assert character not in rendered


def test_long_stored_values_are_bounded() -> None:
    rendered = formatting.safe_field("x" * 500)

    assert len(rendered) == formatting.FIELD_MAX_CHARS
    assert rendered.endswith("…")


def test_empty_and_missing_values_use_a_placeholder() -> None:
    assert formatting.safe_field(None) == "-"
    assert formatting.safe_field("   ") == "-"
    assert formatting.format_timestamp(None) == "-"


def test_whole_reply_is_bounded() -> None:
    many = tuple(_incident(title=f"инцидент {index}") for index in range(25))

    rendered = formatting.format_incidents(many, truncated=True, empty_text="пусто")

    assert len(rendered) <= formatting.MESSAGE_MAX_CHARS


def _plan(**overrides: object) -> IpBlockPlanSummary:
    values: dict[str, object] = {
        "plan_id": PLAN_ID,
        "incident_id": INCIDENT_ID,
        "server_id": SERVER_ID,
        "ip_address": "203.0.113.10",
        "status": "proposed",
        "command_argv": (
            "nft",
            "add",
            "element",
            "inet",
            "woland_guard",
            "blocked_v4",
            "{",
            "203.0.113.10",
            "}",
        ),
        "proposed_by_operator_id": OPERATOR_ID,
        "proposed_at": MOMENT,
        "expires_at": MOMENT,
        "proposal_request_id": "req-1",
        "decided_by_operator_id": None,
        "decided_at": None,
    }
    values.update(overrides)
    return IpBlockPlanSummary(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("reason", list(BlockTargetRejectionReason))
def test_every_block_rejection_reason_has_a_fixed_safe_text(
    reason: BlockTargetRejectionReason,
) -> None:
    rendered = formatting.format_block_rejection(reason)

    assert rendered
    assert "\n" not in rendered


def test_block_proposal_message_discloses_the_command_and_address() -> None:
    rendered = formatting.format_block_proposal_message(_plan())

    assert "203.0.113.10" in rendered
    assert str(INCIDENT_ID) in rendered
    assert "nft add element inet woland_guard blocked_v4 { 203.0.113.10 }" in rendered
    assert len(rendered) <= formatting.MESSAGE_MAX_CHARS


@pytest.mark.parametrize("status", list(DecideIpBlockStatus))
def test_every_decide_outcome_has_a_fixed_safe_text(status: DecideIpBlockStatus) -> None:
    rendered = formatting.format_block_decision_outcome(status)

    assert rendered


def test_approved_outcome_explicitly_states_nothing_was_executed() -> None:
    rendered = formatting.format_block_decision_outcome(DecideIpBlockStatus.APPROVED)

    assert "НЕ выполнена" in rendered
