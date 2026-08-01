"""Interactive, synthetic-only 8B demo over the same isolated pipeline."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from playwright.sync_api import Browser, BrowserContext, Playwright, sync_playwright
from tests.browser.guards import PageRequestGuard, safe_browser_operation
from tests.browser.harness import (
    ApplicationProcess,
    EphemeralDatabaseConfiguration,
    TemporaryTlsMaterial,
)

from scripts.demo_e2e.commands import cooperative_signal_handlers, shutdown_requested
from scripts.demo_e2e.contracts import DemoE2EError, DemoRunIdentity, RecoveryArtifactKind
from scripts.demo_e2e.ownership import ComposeDemoEnvironment
from scripts.demo_e2e.pipeline import (
    DemoProvisioning,
    PipelineExpectations,
    build_human_manifests,
    build_worker_settings,
    create_session_factory,
    deliver_outbox,
    provision_demo,
    send_manifests,
    verify_exact_rules,
    verify_ingestion,
)
from scripts.demo_e2e.recovery import RecoveryLedgerStore, create_private_ledger_directory


class HumanDemoError(DemoE2EError):
    """The interactive demo failed without exposing credentials or browser call logs."""


@dataclass(slots=True)
class HumanCredentialFile:
    path: Path = field(repr=False)

    def __repr__(self) -> str:
        return "HumanCredentialFile(path=<redacted>)"

    def cleanup(self) -> None:
        if not self.path.exists():
            return
        metadata = self.path.lstat()
        reparse = bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
        if not stat.S_ISREG(metadata.st_mode) or reparse:
            raise HumanDemoError("human demo credential cleanup identity changed")
        self.path.unlink()
        if self.path.exists():
            raise HumanDemoError("human demo credential cleanup failed")


def write_human_credentials(
    output: Path,
    *,
    origin: str,
    provisioning: DemoProvisioning,
) -> HumanCredentialFile:
    if not output.is_absolute() or output.exists():
        raise HumanDemoError("human demo credential output must be a new absolute file")
    parent = output.parent.resolve(strict=True)
    if output.parent != parent or not parent.is_dir():
        raise HumanDemoError("human demo credential output parent is unsafe")
    payload = {
        "dashboard_origin": origin,
        "analyst": {
            "username": provisioning.analyst.username,
            "operator_api_key": provisioning.analyst.token.reveal(),
        },
        "admin": {
            "username": provisioning.admin.username,
            "operator_api_key": provisioning.admin.token.reveal(),
        },
        "viewer": {
            "username": provisioning.viewer.username,
            "operator_api_key": provisioning.viewer.token.reveal(),
        },
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
    # Without O_BINARY, Windows text-mode os.write() would rewrite "\n" to "\r\n".
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(output, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            created_identity = (opened.st_dev, opened.st_ino)
            written = 0
            while written < len(encoded):
                count = os.write(descriptor, encoded[written:])
                if count <= 0:
                    raise OSError("short credential write")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.name == "posix":
            os.chmod(output, 0o600)
    except OSError:
        if created_identity is not None:
            try:
                metadata = output.lstat()
            except FileNotFoundError:
                pass
            else:
                reparse = bool(
                    getattr(metadata, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                )
                if (
                    (metadata.st_dev, metadata.st_ino) == created_identity
                    and stat.S_ISREG(metadata.st_mode)
                    and not reparse
                ):
                    output.unlink()
        raise HumanDemoError("human demo credential output failed safely") from None
    return HumanCredentialFile(path=output)


def run_human_demo(
    project_root: Path,
    *,
    credential_output: Path,
    wait_for_shutdown: Callable[[str], str] = input,
) -> None:
    root = project_root.resolve(strict=True)
    identity = DemoRunIdentity.create()
    ledger_directory = create_private_ledger_directory(identity, Path(tempfile.gettempdir()))
    ledger = RecoveryLedgerStore.create(ledger_directory / "recovery.json", identity)
    environment = ComposeDemoEnvironment(project_root=root, identity=identity, ledger=ledger)
    engine = None
    credentials: HumanCredentialFile | None = None
    tls: TemporaryTlsMaterial | None = None
    application: ApplicationProcess | None = None
    playwright: Playwright | None = None
    browser: Browser | None = None
    context: BrowserContext | None = None
    tls_artifact_root: Path | None = None
    provisioning: DemoProvisioning | None = None
    primary_error = False
    try:
        environment.start_foundation()
        environment.verify_schema()
        database = environment.database_configuration()
        session_factory, engine = create_session_factory(database)
        verify_exact_rules(session_factory, root)
        provisioning = provision_demo(session_factory, identity)
        origin = environment.start_control_plane()
        manifests = build_human_manifests()
        expectations = PipelineExpectations.from_manifests(manifests)
        summaries = send_manifests(
            origin=origin,
            credential=provisioning.agent_token,
            manifests=manifests,
        )
        if (
            sum(summary.accepted for summary in summaries) != expectations.event_count
            or sum(summary.duplicates for summary in summaries) != 0
        ):
            raise HumanDemoError("human demo ingestion outcome was unexpected")
        verify_ingestion(
            session_factory,
            provisioning=provisioning,
            expectations=expectations,
        )
        deliver_outbox(
            session_factory,
            settings=build_worker_settings(database),
            provisioning=provisioning,
            expectations=expectations,
        )
        tls = TemporaryTlsMaterial().start()
        if tls.ca_path is None:
            raise HumanDemoError("human demo TLS artifact is unavailable")
        tls_artifact_root = tls.ca_path.parent
        ledger.add_artifact(RecoveryArtifactKind.TLS, tls_artifact_root)
        application = ApplicationProcess(
            database=EphemeralDatabaseConfiguration(
                host=database.host,
                port=database.port,
                database=database.database,
                username=database.username,
                password=database.password.reveal(),
            ),
            tls=tls,
        )
        application.start()
        credentials = write_human_credentials(
            credential_output,
            origin=application.origin,
            provisioning=provisioning,
        )
        ledger.add_artifact(RecoveryArtifactKind.CREDENTIALS, credentials.path)
        playwright = sync_playwright().start()
        browser = safe_browser_operation(
            lambda: playwright.chromium.launch(channel="chromium", headless=False)
        )
        context = safe_browser_operation(
            lambda: browser.new_context(
                accept_downloads=False,
                ignore_https_errors=True,
                service_workers="block",
                viewport={"width": 1440, "height": 900},
            )
        )
        guard = PageRequestGuard(application.origin)
        guard.install(context)
        page = safe_browser_operation(context.new_page)
        guard.attach_page(page)
        safe_browser_operation(lambda: page.goto(f"{application.origin}/dashboard/login"))
        print("Synthetic 8B human demo is ready.")
        print("Credentials were written to the explicitly requested private file.")
        print("Press Enter in this terminal to remove all demo resources.")
        _wait_for_human_shutdown(wait_for_shutdown)
        guard.assert_clean()
    except (KeyboardInterrupt, EOFError):
        pass
    except Exception:
        primary_error = True
        raise HumanDemoError("human demo failed safely") from None
    finally:
        cleanup_failed = False
        if application is not None and provisioning is not None:
            try:
                if any(
                    secret in line for secret in provisioning.secrets for line in application.logs
                ):
                    cleanup_failed = True
            except Exception:
                cleanup_failed = True
        for cleanup in (
            None if context is None else context.close,
            None if browser is None else browser.close,
            None if playwright is None else playwright.stop,
            None if application is None else application.stop,
            None if engine is None else engine.dispose,
            environment.stop,
        ):
            if cleanup is None:
                continue
            try:
                cleanup()
            except Exception:
                cleanup_failed = True
        if tls is not None:
            try:
                tls.stop()
                if tls_artifact_root is not None:
                    ledger.remove_artifact(RecoveryArtifactKind.TLS, tls_artifact_root)
            except Exception:
                cleanup_failed = True
        if credentials is not None:
            try:
                credential_path = credentials.path
                credentials.cleanup()
                ledger.remove_artifact(RecoveryArtifactKind.CREDENTIALS, credential_path)
            except Exception:
                cleanup_failed = True
        if not cleanup_failed and not ledger.ledger.resources and not ledger.ledger.artifacts:
            try:
                ledger.finish()
                ledger_directory.rmdir()
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            message = (
                "human demo cleanup failed after runtime failure"
                if primary_error
                else "human demo cleanup failed safely"
            )
            raise HumanDemoError(message) from None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an interactive synthetic Woland Guard demo")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--credential-output", type=Path, required=True)
    return parser


def main() -> None:
    arguments = _build_parser().parse_args()
    try:
        with cooperative_signal_handlers():
            run_human_demo(
                arguments.project_root,
                credential_output=arguments.credential_output,
            )
    except HumanDemoError:
        print("Human demo failed safely.")
        raise SystemExit(1) from None


def _wait_for_human_shutdown(wait_for_shutdown: Callable[[str], str]) -> None:
    completed = threading.Event()

    def _wait() -> None:
        try:
            wait_for_shutdown("")
        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            completed.set()

    worker = threading.Thread(target=_wait, name="wg8b-human-input", daemon=True)
    worker.start()
    while not completed.wait(timeout=0.1):
        if shutdown_requested():
            return
        time.sleep(0)


if __name__ == "__main__":
    main()
