"""Single source of truth for journald fields read and transmitted by the agent."""

JOURNALD_FIELD_ALLOWLIST: dict[str, str] = {
    "PRIORITY": "priority",
    "SYSLOG_IDENTIFIER": "syslog_identifier",
    "_SYSTEMD_UNIT": "systemd_unit",
    "_TRANSPORT": "transport",
    "_UID": "uid",
    "_GID": "gid",
    "_COMM": "process_name",
    # Set by PID1 on its own catalog messages, not by the process the message is
    # about: MESSAGE_ID names the catalog entry (e.g. "a unit stop job finished"),
    # UNIT names which unit it finished for.
    "MESSAGE_ID": "message_id",
    "UNIT": "unit",
}

JOURNALD_OUTPUT_FIELDS: tuple[str, ...] = (
    "MESSAGE",
    *JOURNALD_FIELD_ALLOWLIST,
)
