"""Plain-text rendering of allowlisted fields for inbound Telegram replies.

Every reply is assembled from fixed catalog strings and explicit database columns.
Operator input is never echoed back, and stored values are bounded and stripped of
control characters before they reach the outgoing message.

Every renderer takes the resolved language explicitly rather than reading a global:
the language is a property of one conversation, and the poller handles several.
"""

from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Final

from woland_guard_control_plane.application.dashboard_overview import DashboardOverview
from woland_guard_control_plane.application.incident_queries import DashboardIncidentSummary
from woland_guard_control_plane.application.incident_workflow import TransitionOutcome
from woland_guard_control_plane.application.ip_block_policy import BlockTargetRejectionReason
from woland_guard_control_plane.application.ip_blocks import DecideIpBlockStatus, IpBlockPlanSummary
from woland_guard_control_plane.application.server_queries import ServerSummary
from woland_guard_control_plane.infrastructure.database.models import IncidentStatus
from woland_guard_control_plane.telegram_bot.i18n import tg

FIELD_MAX_CHARS: Final = 80
MESSAGE_MAX_CHARS: Final = 3_500
CALLBACK_ANSWER_MAX_CHARS: Final = 200
_PLACEHOLDER: Final = "-"

_STATUS_LABEL_KEYS: Final[dict[str, str]] = {
    IncidentStatus.NEW.value: "status.new",
    IncidentStatus.INVESTIGATING.value: "status.investigating",
    IncidentStatus.RESOLVED.value: "status.resolved",
    IncidentStatus.FALSE_POSITIVE.value: "status.false_positive",
}

_BLOCK_REJECTION_KEYS: Final[dict[BlockTargetRejectionReason, str]] = {
    BlockTargetRejectionReason.NOT_AN_ADDRESS: "ip_block.reject.not_an_address",
    BlockTargetRejectionReason.NOT_CANONICAL: "ip_block.reject.not_an_address",
    BlockTargetRejectionReason.NEVER_BLOCK: "ip_block.reject.never_block",
    BlockTargetRejectionReason.ALLOWLISTED: "ip_block.reject.allowlisted",
}

_DECIDE_OUTCOME_KEYS: Final[dict[DecideIpBlockStatus, str]] = {
    DecideIpBlockStatus.APPROVED: "ip_block.approved",
    DecideIpBlockStatus.REJECTED: "ip_block.rejected",
    DecideIpBlockStatus.PLAN_NOT_FOUND: "ip_block.plan_not_found",
    DecideIpBlockStatus.ALREADY_DECIDED: "ip_block.already_decided",
    DecideIpBlockStatus.EXPIRED: "ip_block.expired",
    DecideIpBlockStatus.SAME_OPERATOR: "ip_block.same_operator",
    DecideIpBlockStatus.NOW_BLOCKED: "ip_block.now_blocked",
}


def help_text(lang: str) -> str:
    return tg(lang, "help")


def unlinked_text(lang: str, *, telegram_user_id: int) -> str:
    return tg(lang, "unlinked").format(telegram_user_id=telegram_user_id)


def forbidden_text(lang: str) -> str:
    return tg(lang, "forbidden")


def unknown_command_text(lang: str) -> str:
    return tg(lang, "unknown_command")


def unavailable_text(lang: str) -> str:
    return tg(lang, "unavailable")


def language_usage_text(lang: str) -> str:
    return tg(lang, "language.usage")


def language_changed_text(lang: str) -> str:
    return tg(lang, "language.changed")


def callback_unlinked_text(lang: str) -> str:
    return tg(lang, "callback.unlinked")


def callback_forbidden_text(lang: str) -> str:
    return tg(lang, "callback.forbidden")


def callback_invalid_text(lang: str) -> str:
    return tg(lang, "callback.invalid")


def callback_rate_limited_text(lang: str) -> str:
    return tg(lang, "callback.rate_limited")


def reason_invalid_text(lang: str) -> str:
    return tg(lang, "reason.invalid")


def reason_expired_text(lang: str) -> str:
    return tg(lang, "reason.expired")


def incident_not_found_text(lang: str) -> str:
    return tg(lang, "incident.not_found")


def incident_stale_version_text(lang: str) -> str:
    return tg(lang, "incident.stale_version")


def incident_transition_not_allowed_text(lang: str) -> str:
    return tg(lang, "incident.transition_not_allowed")


def incidents_empty_text(lang: str) -> str:
    return tg(lang, "incidents.empty")


def critical_incidents_empty_text(lang: str) -> str:
    return tg(lang, "incidents.empty_critical")


def ip_block_disabled_text(lang: str) -> str:
    return tg(lang, "ip_block.disabled")


def ip_block_no_source_address_text(lang: str) -> str:
    return tg(lang, "ip_block.no_source_address")


def ip_block_proposed_text(lang: str) -> str:
    return tg(lang, "ip_block.proposed")


def ip_block_reused_text(lang: str) -> str:
    return tg(lang, "ip_block.reused")


def ip_block_plan_not_found_text(lang: str) -> str:
    return tg(lang, "ip_block.plan_not_found")


def ip_block_already_decided_text(lang: str) -> str:
    return tg(lang, "ip_block.already_decided")


def ip_block_expired_text(lang: str) -> str:
    return tg(lang, "ip_block.expired")


def ip_block_same_operator_text(lang: str) -> str:
    return tg(lang, "ip_block.same_operator")


def ip_block_now_blocked_text(lang: str) -> str:
    return tg(lang, "ip_block.now_blocked")


def ip_block_approved_text(lang: str) -> str:
    return tg(lang, "ip_block.approved")


def ip_block_rejected_text(lang: str) -> str:
    return tg(lang, "ip_block.rejected")


def format_reason_prompt(lang: str, target_status: IncidentStatus) -> str:
    """Ask for the terminal-status reason as a follow-up private message."""

    label = tg(lang, _STATUS_LABEL_KEYS[target_status.value])
    return tg(lang, "reason.prompt").format(label=label)


def format_block_rejection(lang: str, reason: BlockTargetRejectionReason) -> str:
    """Render one closed, fixed reason without ever reflecting the address."""

    return tg(lang, _BLOCK_REJECTION_KEYS[reason])


def format_block_proposal_message(lang: str, plan: IpBlockPlanSummary) -> str:
    """Render the follow-up message sent after a plan is created or reused.

    This is the one place the correlated address is disclosed in Telegram --
    only here, only to the operator who pressed the button, only in a private
    chat, and only after ``PROPOSE_IP_BLOCK`` was already checked (ADR-0015).
    """

    command_text = " ".join(plan.command_argv)
    lines = (
        tg(lang, "proposal.heading"),
        "",
        f"{tg(lang, 'proposal.address')} {plan.ip_address}",
        f"{tg(lang, 'proposal.incident')} {plan.incident_id}",
        f"{tg(lang, 'proposal.command')} {command_text}",
        f"{tg(lang, 'proposal.expires')} {format_timestamp(plan.expires_at)}",
        "",
        tg(lang, "proposal.approval_note"),
    )
    return _bounded("\n".join(lines))


def format_block_decision_outcome(lang: str, status: DecideIpBlockStatus) -> str:
    """Render one closed decision outcome; APPROVED always states nothing ran."""

    return tg(lang, _DECIDE_OUTCOME_KEYS[status])


def format_transition_outcome(
    lang: str,
    outcome: TransitionOutcome,
    *,
    target_status: IncidentStatus,
) -> str:
    """Render one bounded, single-purpose transition result for Telegram."""

    label = tg(lang, _STATUS_LABEL_KEYS[target_status.value])
    if outcome.http_status == 200:
        if outcome.replayed:
            return tg(lang, "incident.already_applied").format(label=label)
        return tg(lang, "incident.status_changed").format(label=label)
    if outcome.http_status == 404:
        return incident_not_found_text(lang)
    if outcome.conflict_type == "stale_version":
        return incident_stale_version_text(lang)
    if outcome.conflict_type == "transition_not_allowed":
        return incident_transition_not_allowed_text(lang)
    if outcome.conflict_type == "idempotency_key_reused":
        return tg(lang, "incident.in_progress")
    return tg(lang, "incident.transition_failed")


def safe_field(value: object, *, limit: int = FIELD_MAX_CHARS) -> str:
    """Return one bounded single-line representation without control characters."""

    if value is None:
        return _PLACEHOLDER
    text = str(value)
    cleaned = "".join(
        character
        for character in text
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
    ).strip()
    if not cleaned:
        return _PLACEHOLDER
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def format_timestamp(value: datetime | None) -> str:
    """Render one UTC timestamp at minute resolution."""

    if value is None:
        return _PLACEHOLDER
    return value.strftime("%Y-%m-%d %H:%M UTC")


def format_overview(lang: str, overview: DashboardOverview) -> str:
    """Render the aggregate counters shown by /status."""

    detail = tg(lang, "overview.servers_detail").format(
        active=overview.servers.active,
        inactive=overview.servers.inactive,
    )
    lines = [
        tg(lang, "overview.heading"),
        "",
        f"{tg(lang, 'overview.servers')} {overview.servers.total} ({detail})",
        f"{tg(lang, 'overview.open_incidents')} {overview.incidents.active}",
        f"{tg(lang, 'overview.critical')} {overview.incidents.critical_active}",
        "",
        tg(lang, "overview.queue"),
        f"  {tg(lang, 'overview.pending')} {overview.notifications.pending}",
        f"  {tg(lang, 'overview.processing')} {overview.notifications.processing}",
        f"  {tg(lang, 'overview.delivered')} {overview.notifications.delivered}",
        f"  {tg(lang, 'overview.failed')} {overview.notifications.failed}",
    ]
    return _bounded("\n".join(lines))


def format_servers(lang: str, servers: tuple[ServerSummary, ...], *, truncated: bool) -> str:
    """Render one bounded server list."""

    if not servers:
        return tg(lang, "servers.empty")
    lines = [tg(lang, "servers.heading"), ""]
    for server in servers:
        state = tg(lang, "servers.active" if server.is_active else "servers.inactive")
        lines.append(f"• {safe_field(server.name)} ({state})")
        lines.append(f"  {tg(lang, 'servers.host')} {safe_field(server.hostname)}")
        lines.append(f"  {tg(lang, 'servers.open_incidents')} {server.active_incident_count}")
        lines.append(f"  {tg(lang, 'servers.last_event')} {format_timestamp(server.last_event_at)}")
        lines.append("")
    if truncated:
        lines.append(tg(lang, "list.truncated"))
    return _bounded("\n".join(lines).strip())


def format_incidents(
    lang: str,
    incidents: tuple[DashboardIncidentSummary, ...],
    *,
    truncated: bool,
    empty_text: str,
) -> str:
    """Render one bounded incident list.

    The incident title follows the reply language when the rule that produced it
    carries a translation; historical incidents detected before the rules were
    bilingual fall back to their frozen Russian title (ADR-0017).
    """

    if not incidents:
        return empty_text
    lines = [tg(lang, "incidents.heading"), ""]
    for incident in incidents:
        title = incident.title_en if lang == "en" and incident.title_en else incident.title
        lines.append(f"• [{safe_field(incident.severity, limit=16)}] {safe_field(title)}")
        lines.append(f"  {tg(lang, 'incidents.server')} {safe_field(incident.server_name)}")
        lines.append(f"  {tg(lang, 'incidents.status')} {safe_field(incident.status, limit=32)}")
        lines.append(f"  {tg(lang, 'incidents.events')} {incident.event_count}")
        lines.append(f"  {tg(lang, 'incidents.last')} {format_timestamp(incident.last_seen_at)}")
        lines.append(f"  {tg(lang, 'incidents.id')} {incident.id}")
        lines.append("")
    if truncated:
        lines.append(tg(lang, "list.truncated"))
    return _bounded("\n".join(lines).strip())


def _bounded(text: str) -> str:
    if len(text) <= MESSAGE_MAX_CHARS:
        return text
    return text[: MESSAGE_MAX_CHARS - 1] + "…"
