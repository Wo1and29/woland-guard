"""Authoritative 8B full-stack state machine over an already tracked-only checkout."""

from __future__ import annotations

import argparse
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from scripts.demo_e2e.backup_restore import DemoBackupError, create_backup, restore_and_verify
from scripts.demo_e2e.browser import BrowserWorkflowEvidence, run_browser_workflow
from scripts.demo_e2e.commands import cooperative_signal_handlers, raise_if_shutdown_requested
from scripts.demo_e2e.contracts import (
    DemoE2EError,
    DemoRunIdentity,
    RecoveryArtifactKind,
    RecoveryPhase,
)
from scripts.demo_e2e.ownership import ComposeDemoEnvironment
from scripts.demo_e2e.pipeline import (
    DemoProvisioning,
    PipelineExpectations,
    PipelineSnapshot,
    build_all_manifests,
    build_worker_settings,
    create_session_factory,
    database_schema_fingerprint,
    database_snapshot,
    deliver_outbox,
    provision_demo,
    send_manifests,
    verify_exact_rules,
    verify_ingestion,
    verify_replay,
)
from scripts.demo_e2e.recovery import (
    RecoveryLedgerStore,
    create_private_ledger_directory,
)
from woland_guard_control_plane.demo.contracts import DemoManifest, load_manifest, write_manifest
from woland_guard_control_plane.demo.scenarios import validate_catalog_manifest

logger = logging.getLogger("woland_guard.demo_e2e")


@dataclass(frozen=True, slots=True)
class AutomatedVerificationResult:
    source_head: str
    scenario_count: int
    accepted_events: int
    replayed_events: int
    delivered_notifications: int
    browser: BrowserWorkflowEvidence
    final_snapshot: PipelineSnapshot


def run_automated_verification(
    project_root: Path,
    *,
    source_head: str,
    identity: DemoRunIdentity | None = None,
    ledger: RecoveryLedgerStore | None = None,
) -> AutomatedVerificationResult:
    root = project_root.resolve(strict=True)
    run_identity = identity or DemoRunIdentity.create()
    owned_ledger_directory: Path | None = None
    if ledger is None:
        owned_ledger_directory = create_private_ledger_directory(
            run_identity, Path(tempfile.gettempdir())
        )
        ledger = RecoveryLedgerStore.create(owned_ledger_directory / "recovery.json", run_identity)
    elif ledger.identity != run_identity:
        raise DemoE2EError("full-stack recovery identity does not match the run")
    environment = ComposeDemoEnvironment(
        project_root=root,
        identity=run_identity,
        ledger=ledger,
    )
    engine = None
    backup = None
    provisioning: DemoProvisioning | None = None
    primary_error: Exception | None = None
    phase = "compose_foundation"
    try:
        raise_if_shutdown_requested()
        environment.start_foundation()
        phase = "schema_verification"
        ledger.set_phase(RecoveryPhase.SCHEMA_VERIFICATION)
        environment.verify_schema()
        database = environment.database_configuration()
        session_factory, engine = create_session_factory(database)
        phase = "rule_verification"
        ledger.set_phase(RecoveryPhase.RULE_VERIFICATION)
        verify_exact_rules(session_factory, root)
        phase = "provisioning"
        ledger.set_phase(RecoveryPhase.PROVISIONING)
        provisioning = provision_demo(session_factory, run_identity)
        phase = "control_plane_readiness"
        origin = environment.start_control_plane()
        phase = "manifest_materialization"
        ledger.set_phase(RecoveryPhase.MANIFESTS)
        manifests = _materialize_manifests(build_all_manifests(), ledger=ledger)
        expectations = PipelineExpectations.from_manifests(manifests)
        phase = "initial_ingestion"
        ledger.set_phase(RecoveryPhase.INGESTION)
        first = send_manifests(
            origin=origin,
            credential=provisioning.agent_token,
            manifests=manifests,
        )
        accepted = sum(summary.accepted for summary in first)
        duplicates = sum(summary.duplicates for summary in first)
        if accepted != expectations.event_count or duplicates != 0:
            raise DemoE2EError("initial ingestion summary did not match canonical expectations")
        phase = "persistence_verification"
        verify_ingestion(
            session_factory,
            provisioning=provisioning,
            expectations=expectations,
        )
        phase = "outbox_delivery"
        ledger.set_phase(RecoveryPhase.OUTBOX)
        delivery = deliver_outbox(
            session_factory,
            settings=build_worker_settings(database),
            provisioning=provisioning,
            expectations=expectations,
        )
        phase = "browser_workflow"
        ledger.set_phase(RecoveryPhase.BROWSER)
        browser = run_browser_workflow(
            database=database,
            session_factory=session_factory,
            provisioning=provisioning,
            ledger=ledger,
        )
        phase = "manifest_replay"
        ledger.set_phase(RecoveryPhase.REPLAY)
        before_replay = database_snapshot(session_factory, provisioning)
        replay = send_manifests(
            origin=origin,
            credential=provisioning.agent_token,
            manifests=manifests,
        )
        replay_accepted = sum(summary.accepted for summary in replay)
        replayed = sum(summary.duplicates for summary in replay)
        if replay_accepted != 0 or replayed != expectations.event_count:
            raise DemoE2EError("manifest replay summary did not match idempotent ingestion")
        phase = "replay_verification"
        final_snapshot = verify_replay(
            session_factory,
            provisioning=provisioning,
            expectations=expectations,
            before=before_replay,
        )
        schema_fingerprint = database_schema_fingerprint(session_factory)
        phase = "control_plane_shutdown"
        environment.stop_control_plane()
        engine.dispose()
        engine = None
        phase = "backup"
        ledger.set_phase(RecoveryPhase.BACKUP)
        backup = create_backup(environment, forbidden_plaintext=provisioning.secrets)
        ledger.add_artifact(RecoveryArtifactKind.BACKUP, backup.path.parent)
        phase = "restore_verification"
        ledger.set_phase(RecoveryPhase.RESTORE)
        restore_and_verify(
            project_root=root,
            identity=run_identity,
            ledger=ledger,
            backup=backup,
            expected_snapshot=final_snapshot,
            expected_schema=schema_fingerprint,
            provisioning=provisioning,
        )
        return AutomatedVerificationResult(
            source_head=source_head,
            scenario_count=len(manifests),
            accepted_events=accepted,
            replayed_events=replayed,
            delivered_notifications=delivery.request_count,
            browser=browser,
            final_snapshot=final_snapshot,
        )
    except Exception as error:
        primary_error = error
        if phase == "restore_verification" and isinstance(error, DemoBackupError):
            phase = f"restore_verification_{error.phase}"
        raise DemoE2EError(f"full-stack demo verification failed during {phase}") from None
    finally:
        cleanup_failed = False
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                cleanup_failed = True
        if backup is not None:
            try:
                backup_path = backup.path.parent
                backup.cleanup()
                ledger.remove_artifact(RecoveryArtifactKind.BACKUP, backup_path)
            except Exception:
                cleanup_failed = True
        try:
            environment.stop()
        except Exception:
            cleanup_failed = True
        if not cleanup_failed and not ledger.ledger.resources and not ledger.ledger.artifacts:
            try:
                ledger.finish()
                if owned_ledger_directory is not None:
                    owned_ledger_directory.rmdir()
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            message = (
                "full-stack demo cleanup failed after verification failure"
                if primary_error is not None
                else "full-stack demo cleanup failed"
            )
            raise DemoE2EError(message) from None


def _materialize_manifests(
    manifests: tuple[DemoManifest, ...],
    *,
    ledger: RecoveryLedgerStore,
) -> tuple[DemoManifest, ...]:
    root = Path(tempfile.mkdtemp(prefix="wg8b-manifests-"))
    ledger.add_artifact(RecoveryArtifactKind.MANIFESTS, root)
    try:
        paths: list[Path] = []
        for ordinal, manifest in enumerate(manifests):
            path = root / f"scenario-{ordinal:02d}.json"
            write_manifest(path, validate_catalog_manifest(manifest))
            paths.append(path)
        loaded = tuple(validate_catalog_manifest(load_manifest(path)) for path in paths)
    finally:
        shutil.rmtree(root)
        ledger.remove_artifact(RecoveryArtifactKind.MANIFESTS, root)
    if root.exists():
        raise DemoE2EError("temporary manifest cleanup failed")
    return loaded


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the isolated Woland Guard 8B verifier")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    return parser


def main() -> None:
    arguments = _build_parser().parse_args()
    if len(arguments.source_head) != 40 or any(
        character not in "0123456789abcdef" for character in arguments.source_head
    ):
        raise SystemExit("clean-install source revision is invalid")
    try:
        with cooperative_signal_handlers():
            identity = DemoRunIdentity.from_run_id(arguments.run_id)
            ledger = RecoveryLedgerStore.open(arguments.ledger)
            result = run_automated_verification(
                arguments.project_root,
                source_head=arguments.source_head,
                identity=identity,
                ledger=ledger,
            )
    except DemoE2EError:
        print("8B verification failed safely.")
        raise SystemExit(1) from None
    print(
        " ".join(
            (
                "8B verification passed:",
                f"scenarios={result.scenario_count}",
                f"accepted={result.accepted_events}",
                f"duplicates={result.replayed_events}",
                f"delivered={result.delivered_notifications}",
            )
        )
    )


if __name__ == "__main__":
    main()
