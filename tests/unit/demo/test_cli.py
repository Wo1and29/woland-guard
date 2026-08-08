"""Safe demo CLI behavior and exit-code tests."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest

from woland_guard_control_plane.demo import cli
from woland_guard_control_plane.demo.client import (
    DemoAuthenticationError,
    DemoProtocolError,
    DemoRejectedEventsError,
    DemoSendSummary,
    DemoTemporaryTransportError,
    UnsafeDemoOriginError,
)
from woland_guard_control_plane.demo.contracts import canonical_manifest_bytes
from woland_guard_control_plane.demo.scenarios import build_manifest, list_scenarios

RUN_ID = "44444444-4444-4444-8444-444444444444"
ANCHOR = "2026-07-29T12:00:00Z"


def test_list_scenarios_is_offline_stable_and_safe(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["list-scenarios"])

    output = capsys.readouterr().out
    assert len(output.splitlines()) == 52
    assert "wgak_" not in output
    assert "positive" in output
    assert "boundary_exact" in output


def test_generate_fixture_manifest_and_validate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = (tmp_path / "manifest.json").resolve()
    scenario = list_scenarios()[0].scenario_id

    cli.main(
        [
            "generate",
            "--scenario",
            scenario,
            "--output",
            str(output),
            "--fixture-inputs",
            "--run-id",
            RUN_ID,
            "--anchor-utc",
            ANCHOR,
        ]
    )
    cli.main(["validate", "--manifest", str(output)])

    captured = capsys.readouterr()
    assert output.exists()
    assert scenario in captured.out
    assert "valid=true" in captured.out


def test_explicit_inputs_require_hidden_fixture_mode(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as captured:
        cli.main(
            [
                "generate",
                "--scenario",
                list_scenarios()[0].scenario_id,
                "--output",
                str((tmp_path / "manifest.json").resolve()),
                "--run-id",
                RUN_ID,
            ]
        )

    assert captured.value.code == cli.EXIT_INVALID


def test_generate_refuses_overwrite_without_flag(tmp_path: Path) -> None:
    output = (tmp_path / "manifest.json").resolve()
    args = [
        "generate",
        "--scenario",
        list_scenarios()[0].scenario_id,
        "--output",
        str(output),
        "--fixture-inputs",
        "--run-id",
        RUN_ID,
        "--anchor-utc",
        ANCHOR,
    ]
    cli.main(args)

    with pytest.raises(SystemExit) as captured:
        cli.main(args)

    assert captured.value.code == cli.EXIT_INVALID


def test_generate_all_writes_exact_catalog(tmp_path: Path) -> None:
    output = tmp_path.resolve()

    cli.main(
        [
            "generate",
            "--scenario",
            "all",
            "--output",
            str(output),
            "--fixture-inputs",
            "--run-id",
            RUN_ID,
            "--anchor-utc",
            ANCHOR,
        ]
    )

    assert len(tuple(output.glob("*.json"))) == 52


@pytest.mark.parametrize(
    ("error", "exit_code"),
    [
        (UnsafeDemoOriginError("static"), cli.EXIT_UNSAFE_ORIGIN),
        (DemoAuthenticationError("static"), cli.EXIT_AUTHENTICATION),
        (DemoRejectedEventsError("static"), cli.EXIT_REJECTED),
        (DemoTemporaryTransportError("static"), cli.EXIT_TEMPORARY),
        (DemoProtocolError("static"), cli.EXIT_PROTOCOL),
    ],
)
def test_send_failures_use_distinct_safe_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    exit_code: int,
) -> None:
    monkeypatch.setattr(cli, "_send", lambda _arguments: (_ for _ in ()).throw(error))

    with pytest.raises(SystemExit) as captured:
        cli.main(
            [
                "send",
                "--manifest",
                "manifest.json",
                "--origin",
                "http://localhost:8000",
                "--api-key-file",
                "agent.key",
            ]
        )

    rendered = capsys.readouterr()
    assert captured.value.code == exit_code
    assert "static" not in rendered.err
    assert "Traceback" not in rendered.err


def test_successful_send_prints_only_ingestion_counts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "load_manifest", lambda _path: object())
    monkeypatch.setattr(cli, "validate_catalog_manifest", lambda manifest: manifest)
    monkeypatch.setattr(cli, "load_api_credential", lambda _path: object())

    class FakeClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def send(self, _manifest: object, *, max_clock_skew_seconds: int) -> DemoSendSummary:
            assert max_clock_skew_seconds == 300
            return DemoSendSummary("synthetic_rule.positive.v1", 1, 4, 2)

    monkeypatch.setattr(cli, "DemoIngestionClient", FakeClient)

    cli.main(
        [
            "send",
            "--manifest",
            "manifest.json",
            "--origin",
            "http://localhost:8000",
            "--api-key-file",
            "agent.key",
        ]
    )

    output = capsys.readouterr().out
    assert "accepted=4" in output
    assert "duplicate=2" in output
    assert "incident" not in output.casefold()


def test_validate_and_send_reject_catalog_mutation_before_credential_or_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = build_manifest(
        "ssh_bruteforce_by_ip.positive.v1",
        run_id=UUID(RUN_ID),
        anchor_utc=datetime(2026, 7, 29, 12, tzinfo=UTC),
    )
    document = json.loads(canonical_manifest_bytes(manifest))
    document["expected_outcomes"]["incidents"][0]["title"] = "cli-catalog-canary"
    path = (tmp_path / "mutated.json").resolve()
    path.write_bytes(
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    credential_reads = 0
    client_constructions = 0

    def read_credential(_path: Path) -> object:
        nonlocal credential_reads
        credential_reads += 1
        return object()

    def construct_client(**_kwargs: object) -> object:
        nonlocal client_constructions
        client_constructions += 1
        return object()

    monkeypatch.setattr(cli, "load_api_credential", read_credential)
    monkeypatch.setattr(cli, "DemoIngestionClient", construct_client)

    with pytest.raises(SystemExit) as validate_exit:
        cli.main(["validate", "--manifest", str(path)])
    with pytest.raises(SystemExit) as send_exit:
        cli.main(
            [
                "send",
                "--manifest",
                str(path),
                "--origin",
                "http://127.0.0.1:8000",
                "--api-key-file",
                str((tmp_path / "credential.key").resolve()),
            ]
        )

    rendered = capsys.readouterr()
    assert validate_exit.value.code == cli.EXIT_INVALID
    assert send_exit.value.code == cli.EXIT_INVALID
    assert credential_reads == 0
    assert client_constructions == 0
    assert "cli-catalog-canary" not in rendered.out
    assert "cli-catalog-canary" not in rendered.err
    assert "wgak_" not in rendered.out
    assert "wgak_" not in rendered.err


def test_cli_has_no_plaintext_api_key_argument() -> None:
    parser = cli.build_parser()
    help_text = parser.format_help()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    send_parser = cast(argparse.ArgumentParser, subparsers.choices["send"])

    assert "--api-key " not in help_text
    assert "--api-key-file" in send_parser.format_help()


def test_fixture_timestamp_parser_accepts_only_utc() -> None:
    assert cli._parse_utc(ANCHOR) == datetime(2026, 7, 29, 12, tzinfo=UTC)
    with pytest.raises(argparse.ArgumentTypeError):
        cli._parse_utc("2026-07-29T15:00:00+03:00")
    with pytest.raises(argparse.ArgumentTypeError):
        cli._parse_utc("2026-07-29T12:00:00")
