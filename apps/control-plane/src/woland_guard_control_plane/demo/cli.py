"""Safe local CLI for generating and sending synthetic demo manifests."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from woland_guard_control_plane.demo.client import (
    DemoAuthenticationError,
    DemoClockSkewError,
    DemoCredentialError,
    DemoIngestionClient,
    DemoOrigin,
    DemoProtocolError,
    DemoRejectedEventsError,
    DemoTemporaryTransportError,
    UnsafeDemoOriginError,
    load_api_credential,
)
from woland_guard_control_plane.demo.contracts import (
    DemoArtifactError,
    DemoManifestError,
    load_manifest,
    validate_manifest_output_directory,
    write_manifest,
)
from woland_guard_control_plane.demo.scenarios import (
    ScenarioDefinition,
    build_manifest,
    list_scenarios,
    validate_catalog_manifest,
)

EXIT_INVALID = 2
EXIT_UNSAFE_ORIGIN = 3
EXIT_AUTHENTICATION = 4
EXIT_REJECTED = 5
EXIT_TEMPORARY = 6
EXIT_PROTOCOL = 7


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="woland-guard-demo")
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate", help="generate canonical synthetic manifests")
    generate.add_argument("--scenario", required=True)
    generate.add_argument("--output", type=Path, required=True)
    generate.add_argument("--overwrite", action="store_true")
    generate.add_argument("--fixture-inputs", action="store_true", help=argparse.SUPPRESS)
    generate.add_argument("--run-id", type=UUID, help=argparse.SUPPRESS)
    generate.add_argument("--anchor-utc", type=_parse_utc, help=argparse.SUPPRESS)

    send = commands.add_parser("send", help="send an existing manifest to loopback ingestion")
    send.add_argument("--manifest", type=Path, required=True)
    send.add_argument("--origin", required=True)
    send.add_argument("--api-key-file", type=Path, required=True)
    send.add_argument("--max-clock-skew-seconds", type=int, default=300)

    validate = commands.add_parser("validate", help="validate one canonical manifest offline")
    validate.add_argument("--manifest", type=Path, required=True)
    commands.add_parser("list-scenarios", help="list stable synthetic scenario identifiers")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "list-scenarios":
            _list_scenarios()
        elif arguments.command == "generate":
            _generate(arguments)
        elif arguments.command == "validate":
            manifest = validate_catalog_manifest(load_manifest(arguments.manifest))
            print(f"scenario_id={manifest.scenario_id} valid=true")
        else:
            _send(arguments)
    except UnsafeDemoOriginError:
        print("Demo origin was rejected by the loopback-only policy.", file=sys.stderr)
        raise SystemExit(EXIT_UNSAFE_ORIGIN) from None
    except DemoAuthenticationError:
        print("Demo API authentication failed.", file=sys.stderr)
        raise SystemExit(EXIT_AUTHENTICATION) from None
    except DemoRejectedEventsError:
        print("Demo events were rejected by the ingestion API.", file=sys.stderr)
        raise SystemExit(EXIT_REJECTED) from None
    except (DemoTemporaryTransportError, DemoClockSkewError):
        print("Demo delivery is temporarily unavailable.", file=sys.stderr)
        raise SystemExit(EXIT_TEMPORARY) from None
    except DemoProtocolError:
        print("Demo ingestion returned an invalid protocol result.", file=sys.stderr)
        raise SystemExit(EXIT_PROTOCOL) from None
    except (DemoManifestError, DemoArtifactError, DemoCredentialError, ValueError):
        print("Demo input failed the safe validation policy.", file=sys.stderr)
        raise SystemExit(EXIT_INVALID) from None


def _list_scenarios() -> None:
    for definition in list_scenarios():
        print(
            f"scenario_id={definition.scenario_id} rule_key={definition.rule_key} "
            f"case_type={definition.case_type.value} description={definition.description}"
        )


def _generate(arguments: argparse.Namespace) -> None:
    explicit = arguments.run_id is not None or arguments.anchor_utc is not None
    if explicit and not arguments.fixture_inputs:
        raise DemoManifestError("explicit deterministic inputs require fixture mode")
    if arguments.fixture_inputs and (arguments.run_id is None or arguments.anchor_utc is None):
        raise DemoManifestError("fixture mode requires both deterministic inputs")
    run_id = arguments.run_id or uuid4()
    anchor = arguments.anchor_utc or datetime.now(UTC)
    definitions = list_scenarios()
    if arguments.scenario == "all":
        _generate_all(
            arguments.output,
            definitions=definitions,
            run_id=run_id,
            anchor=anchor,
            overwrite=arguments.overwrite,
        )
        print(f"generated={len(definitions)}")
        return
    manifest = build_manifest(arguments.scenario, run_id=run_id, anchor_utc=anchor)
    write_manifest(arguments.output, manifest, overwrite=arguments.overwrite)
    print(f"scenario_id={manifest.scenario_id} generated=1")


def _generate_all(
    output: Path,
    *,
    definitions: Sequence[ScenarioDefinition],
    run_id: UUID,
    anchor: datetime,
    overwrite: bool,
) -> None:
    validate_manifest_output_directory(output)
    manifests = [
        build_manifest(definition.scenario_id, run_id=run_id, anchor_utc=anchor)
        for definition in definitions
    ]
    targets = [output / f"{manifest.scenario_id}.json" for manifest in manifests]
    if not overwrite and any(target.exists() or target.is_symlink() for target in targets):
        raise DemoArtifactError("one or more manifest outputs already exist")
    for target, manifest in zip(targets, manifests, strict=True):
        write_manifest(target, manifest, overwrite=overwrite)


def _send(arguments: argparse.Namespace) -> None:
    manifest = validate_catalog_manifest(load_manifest(arguments.manifest))
    origin = DemoOrigin.parse(arguments.origin)
    credential = load_api_credential(arguments.api_key_file)
    with DemoIngestionClient(origin=origin, credential=credential) as client:
        summary = client.send(
            manifest,
            max_clock_skew_seconds=arguments.max_clock_skew_seconds,
        )
    print(
        f"scenario_id={summary.scenario_id} batches={summary.batches} "
        f"accepted={summary.accepted} duplicate={summary.duplicates} "
        f"rejected={summary.rejected}"
    )


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError("invalid UTC timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise argparse.ArgumentTypeError("timestamp must be timezone-aware UTC")
    return parsed.astimezone(UTC)
