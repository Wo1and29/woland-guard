"""Single source of truth for journald fields read and transmitted by the agent."""

JOURNALD_FIELD_ALLOWLIST: dict[str, str] = {
    "PRIORITY": "priority",
    "SYSLOG_IDENTIFIER": "syslog_identifier",
    "_SYSTEMD_UNIT": "systemd_unit",
    "_TRANSPORT": "transport",
    "_UID": "uid",
    "_GID": "gid",
    "_COMM": "process_name",
}

JOURNALD_OUTPUT_FIELDS: tuple[str, ...] = (
    "MESSAGE",
    *JOURNALD_FIELD_ALLOWLIST,
)
