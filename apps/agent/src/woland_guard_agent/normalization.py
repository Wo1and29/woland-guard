"""Explicit parsers that convert supported journald messages into safe events."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid5

from pydantic import JsonValue

from woland_guard_agent.sources.base import JournalRecord
from woland_guard_contracts import EventSource, NormalizedEventV1

EVENT_ID_NAMESPACE = UUID("f7d85d38-1e7c-4ea4-8c68-33a388f70c2a")

_ACCOUNT = r"[a-z_][a-z0-9_-]{0,31}"
_SSH_FAILED = re.compile(
    rf"^Failed (?P<method>[a-z0-9-]+) for "
    rf"(?P<invalid>invalid user )?(?P<actor>{_ACCOUNT}) from "
    r"(?P<source_ip>\S+)(?: port \d+)?(?: ssh\d+)?$",
    re.IGNORECASE,
)
_SSH_SUCCEEDED = re.compile(
    rf"^Accepted (?P<method>[a-z0-9-]+) for (?P<actor>{_ACCOUNT}) from "
    r"(?P<source_ip>\S+)(?: port \d+)?(?: ssh\d+)?$",
    re.IGNORECASE,
)
_SUDO_FAILURE = re.compile(
    rf"\bauthentication failure\b.*(?:^|[ ;])user=(?P<actor>{_ACCOUNT})(?:[ ;]|$)",
    re.IGNORECASE,
)
_USER_CREATED = re.compile(
    rf"\bnew user: name=(?P<actor>{_ACCOUNT}), UID=(?P<uid>\d+), "
    r"GID=(?P<gid>\d+)(?:,|$)",
    re.IGNORECASE,
)
_USERMOD_GROUP = re.compile(
    rf"^(?P<action>add|remove) '(?P<actor>{_ACCOUNT})' "
    r"(?P<direction>to|from) group '(?P<group>sudo|adm|wheel)'$",
    re.IGNORECASE,
)
_GPASSWD_GROUP = re.compile(
    rf"^user (?P<actor>{_ACCOUNT}) (?P<action>added|removed) by "
    rf"{_ACCOUNT} (?P<direction>to|from) group (?P<group>sudo|adm|wheel)$",
    re.IGNORECASE,
)
# BEGIN EDIT/LIST/END EDIT bracket an interactive session and fire even when the
# user cancels without saving; only REPLACE (crontab installed, interactively or
# via `crontab file`) and DELETE (`crontab -r`) mean the table actually changed.
_CRON_CHANGED = re.compile(
    rf"^\((?P<actor>{_ACCOUNT})\) (?P<action>REPLACE|DELETE) \({_ACCOUNT}\)$"
)

# The catalog entry systemd assigns to "a unit stop job has finished, successfully
# or not" -- verified against systemd's own catalog source (catalog/systemd.catalog.in),
# not against a live journalctl, since this environment has no running systemd.
_UNIT_STOPPED_MESSAGE_ID = "9d1aaa27d60140bd96365438aad20286"
# A fixed allowlist, not "any unit": a normal host stops and restarts many timer-
# triggered oneshot units every day, and reporting every one would both flood the
# spool and bury the units that actually matter for security.
_CRITICAL_UNITS = frozenset(
    {
        "ssh.service",
        "rsyslog.service",
        "systemd-journald.service",
        "cron.service",
        "auditd.service",
    }
)


@dataclass(frozen=True, slots=True)
class ParsedSecurityEvent:
    event_type: str
    summary: str
    actor: str | None = None
    source_ip: IPv4Address | IPv6Address | None = None
    attributes: dict[str, JsonValue] | None = None


def normalize_record(
    record: JournalRecord,
    *,
    source: EventSource = EventSource.JOURNALD,
    collected_at: datetime | None = None,
) -> NormalizedEventV1 | None:
    """Return only a recognized security event; unknown messages are ignored.

    The parsers below read ``MESSAGE`` and the syslog identifier, never the
    transport, so every adapter that can supply those two fields reuses the same
    allowlist unchanged (ADR-0019).
    """

    parsed = _parse_supported_message(record.fields)
    if parsed is None:
        return None

    collection_time = (collected_at or datetime.now(UTC)).astimezone(UTC)
    occurred_at = _occurred_at(record.fields, fallback=collection_time)
    if collection_time < occurred_at:
        collection_time = occurred_at

    return NormalizedEventV1(
        event_id=uuid5(EVENT_ID_NAMESPACE, record.cursor),
        occurred_at=occurred_at,
        collected_at=collection_time,
        source=source,
        event_type=parsed.event_type,
        actor=parsed.actor,
        source_ip=parsed.source_ip,
        summary=parsed.summary,
        attributes=parsed.attributes or {},
    )


_FILE_CHANGES = frozenset({"content", "permissions", "metadata", "appeared", "disappeared"})
_FILE_MONITORING = frozenset({"content", "metadata"})


def _parse_supported_message(fields: Mapping[str, object]) -> ParsedSecurityEvent | None:
    if "NGINX_STATUS" in fields:
        return _parse_nginx_request(fields)
    if "FILE_INTEGRITY_PATH" in fields:
        return _parse_file_integrity(fields)

    message = fields.get("MESSAGE")
    if not isinstance(message, str) or "\x00" in message:
        return None
    identifier = _identifier(fields)

    if identifier == "sshd":
        failed = _SSH_FAILED.fullmatch(message)
        if failed is not None:
            source_ip = _validated_ip(failed.group("source_ip"))
            if source_ip is None:
                return None
            return ParsedSecurityEvent(
                event_type="linux.ssh.authentication_failed",
                summary="SSH authentication failed",
                actor=failed.group("actor").lower(),
                source_ip=source_ip,
                attributes={
                    "authentication_method": failed.group("method").lower(),
                    "invalid_user": failed.group("invalid") is not None,
                },
            )

        succeeded = _SSH_SUCCEEDED.fullmatch(message)
        if succeeded is not None:
            source_ip = _validated_ip(succeeded.group("source_ip"))
            if source_ip is None:
                return None
            return ParsedSecurityEvent(
                event_type="linux.ssh.login_succeeded",
                summary="SSH login succeeded",
                actor=succeeded.group("actor").lower(),
                source_ip=source_ip,
                attributes={"authentication_method": succeeded.group("method").lower()},
            )

    if identifier == "sudo":
        sudo_failure = _SUDO_FAILURE.search(message)
        if sudo_failure is not None:
            return ParsedSecurityEvent(
                event_type="linux.sudo.authentication_failed",
                summary="Sudo authentication failed",
                actor=sudo_failure.group("actor").lower(),
            )

    if identifier == "useradd":
        user_created = _USER_CREATED.search(message)
        if user_created is not None:
            return ParsedSecurityEvent(
                event_type="linux.account.user_created",
                summary="Local user account created",
                actor=user_created.group("actor").lower(),
                attributes={
                    "uid": user_created.group("uid"),
                    "gid": user_created.group("gid"),
                },
            )

    if identifier in {"usermod", "gpasswd"}:
        group_change = _USERMOD_GROUP if identifier == "usermod" else _GPASSWD_GROUP
        matched_change = group_change.fullmatch(message)
        if matched_change is not None:
            raw_action = matched_change.group("action").lower()
            action = "added" if raw_action in {"add", "added"} else "removed"
            return ParsedSecurityEvent(
                event_type="linux.account.privileged_group_changed",
                summary="Privileged group membership changed",
                actor=matched_change.group("actor").lower(),
                attributes={
                    "group": matched_change.group("group").lower(),
                    "action": action,
                },
            )

    if identifier == "crontab":
        cron_changed = _CRON_CHANGED.fullmatch(message)
        if cron_changed is not None:
            return ParsedSecurityEvent(
                event_type="linux.cron.job_changed",
                summary="Crontab modified",
                actor=cron_changed.group("actor").lower(),
                attributes={"action": cron_changed.group("action").lower()},
            )

    if identifier == "systemd":
        return _systemd_unit_stopped(fields)

    return None


def _systemd_unit_stopped(fields: Mapping[str, object]) -> ParsedSecurityEvent | None:
    if fields.get("MESSAGE_ID") != _UNIT_STOPPED_MESSAGE_ID:
        return None
    unit = fields.get("UNIT")
    if not isinstance(unit, str) or unit not in _CRITICAL_UNITS:
        return None
    return ParsedSecurityEvent(
        event_type="linux.systemd.unit_stopped",
        summary="Security-relevant systemd unit stopped",
        attributes={"unit": unit},
    )


def _parse_nginx_request(fields: Mapping[str, object]) -> ParsedSecurityEvent | None:
    """Build a request event from the closed set the adapter already validated.

    The adapter dropped the query string, the referer and the user agent before
    this point, so there is nothing here to redact (ADR-0020 §1, §3).

    Only failed requests become events. A successful one is not consumed by any
    rule, and on a live web server it outnumbers every other event source by
    orders of magnitude, so shipping it would fill the spool and the events
    table with rows nothing ever reads (ADR-0020 §7).
    """

    status = fields.get("NGINX_STATUS")
    method = fields.get("NGINX_METHOD")
    path = fields.get("NGINX_PATH")
    address = fields.get("NGINX_REMOTE_ADDR")
    if not isinstance(status, int) or not isinstance(method, str):
        return None
    if not isinstance(path, str) or not isinstance(address, str):
        return None

    source_ip = _validated_ip(address)
    if source_ip is None:
        return None

    if status < 400:
        return None

    return ParsedSecurityEvent(
        event_type="web.nginx.request_failed",
        summary="HTTP request failed",
        source_ip=source_ip,
        attributes={"status": status, "method": method, "path": path},
    )


def _parse_file_integrity(fields: Mapping[str, object]) -> ParsedSecurityEvent | None:
    """Report that a watched path changed, never what it now contains.

    The source compared digests locally; neither the content, a diff, nor the
    hash itself reaches this point, so there is nothing here to redact
    (ADR-0022 §4). The path is the one the operator configured, never a name
    discovered on disk (ADR-0022 §6).
    """

    path = fields.get("FILE_INTEGRITY_PATH")
    change = fields.get("FILE_INTEGRITY_CHANGE")
    monitoring = fields.get("FILE_INTEGRITY_MONITORING")
    if not isinstance(path, str) or "\x00" in path or not path.isprintable():
        return None
    if change not in _FILE_CHANGES or monitoring not in _FILE_MONITORING:
        return None

    return ParsedSecurityEvent(
        event_type="linux.file.changed",
        summary="Watched system file changed",
        attributes={"path": path, "change": change, "monitoring": monitoring},
    )


def _identifier(fields: Mapping[str, object]) -> str | None:
    for name in ("SYSLOG_IDENTIFIER", "_COMM"):
        value = fields.get(name)
        if isinstance(value, str) and "\x00" not in value:
            return value.lower()
    return None


def _validated_ip(value: str) -> IPv4Address | IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _occurred_at(fields: Mapping[str, object], *, fallback: datetime) -> datetime:
    raw = fields.get("__REALTIME_TIMESTAMP")

    if isinstance(raw, str) and raw.isdecimal():
        try:
            return datetime.fromtimestamp(int(raw) / 1_000_000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return fallback
    if isinstance(raw, int) and raw >= 0:
        try:
            return datetime.fromtimestamp(raw / 1_000_000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return fallback
    return fallback
