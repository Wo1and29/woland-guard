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


@dataclass(frozen=True, slots=True)
class ParsedSecurityEvent:
    event_type: str
    summary: str
    actor: str | None = None
    source_ip: IPv4Address | IPv6Address | None = None
    attributes: dict[str, JsonValue] | None = None


def normalize_journald_record(
    record: JournalRecord,
    *,
    collected_at: datetime | None = None,
) -> NormalizedEventV1 | None:
    """Return only a recognized security event; unknown messages are ignored."""

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
        source=EventSource.JOURNALD,
        event_type=parsed.event_type,
        actor=parsed.actor,
        source_ip=parsed.source_ip,
        summary=parsed.summary,
        attributes=parsed.attributes or {},
    )


def _parse_supported_message(fields: Mapping[str, object]) -> ParsedSecurityEvent | None:
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

    return None


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
