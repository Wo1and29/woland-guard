"""Safe local spool administration commands."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from woland_guard_agent.cli import main
from woland_guard_agent.spool import SQLiteSpool
from woland_guard_contracts import NormalizedEventV1

EVENT_ID = UUID("00000000-0000-0000-0000-000000000099")


def test_spool_status_and_filtered_list_do_not_require_or_print_token_or_payload(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, spool = configured_spool(tmp_path)
    event = queued_event()
    spool.enqueue_with_cursor(source_name="journald", cursor="s=cli;i=1", event=event)
    spool.quarantine(event.event_id, status="quarantined", error_code="invalid_event")
    spool.record_diagnostic("journal_gap")

    status_result = main(["spool-status", "--config", str(config)])
    list_result = main(
        [
            "spool-list",
            "--config",
            str(config),
            "--status",
            "quarantined",
        ]
    )

    output = capsys.readouterr().err

    assert status_result == 0
    assert list_result == 0
    assert str(EVENT_ID) in output
    assert "journal_gap" in output
    assert "sensitive-payload" not in output
    assert "token-does-not-exist" not in output


def test_spool_requeue_and_delete_require_exact_event_confirmation(tmp_path: Path) -> None:
    config, spool = configured_spool(tmp_path)
    event = queued_event()
    spool.enqueue_with_cursor(source_name="journald", cursor="s=cli;i=2", event=event)
    spool.quarantine(event.event_id, status="quarantined", error_code="invalid_event")

    assert main(["spool-requeue", "--config", str(config), str(EVENT_ID)]) == 0
    assert spool.list_events(status="pending")[0].event_id == EVENT_ID
    assert (
        main(
            [
                "spool-delete",
                "--config",
                str(config),
                str(EVENT_ID),
                "--confirm",
                "different-value",
            ]
        )
        == 4
    )
    assert spool.contains(EVENT_ID)
    assert (
        main(
            [
                "spool-delete",
                "--config",
                str(config),
                str(EVENT_ID),
                "--confirm",
                str(EVENT_ID),
            ]
        )
        == 0
    )
    assert not spool.contains(EVENT_ID)


def configured_spool(tmp_path: Path) -> tuple[Path, SQLiteSpool]:
    spool_path = tmp_path / "state" / "spool.sqlite3"
    config = tmp_path / "agent.yaml"
    config.write_text(
        "\n".join(
            (
                "schema_version: 1",
                "source: journald",
                "http:",
                "  base_url: https://control.invalid",
                f"  token_file: {tmp_path / 'token-does-not-exist'}",
                "spool:",
                f"  path: {spool_path}",
                "  max_events: 10",
            )
        ),
        encoding="utf-8",
    )
    spool = SQLiteSpool(spool_path, max_events=10)
    spool.initialize()
    return config, spool


def queued_event() -> NormalizedEventV1:
    return NormalizedEventV1(
        event_id=EVENT_ID,
        occurred_at=datetime(2024, 1, 1, tzinfo=UTC),
        collected_at=datetime(2024, 1, 1, tzinfo=UTC),
        event_type="linux.ssh.authentication_failed",
        summary="sensitive-payload",
    )
