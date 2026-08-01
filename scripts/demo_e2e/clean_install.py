"""Outer tracked-only checkout bootstrap using isolated dependency/browser state."""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path

from scripts.demo_e2e.archive import create_clean_checkout, remove_clean_checkout
from scripts.demo_e2e.commands import (
    CommandRunner,
    DemoCommandError,
    cooperative_signal_handlers,
)
from scripts.demo_e2e.contracts import (
    CleanCheckoutMetadata,
    DemoE2EError,
    DemoRunIdentity,
    RecoveryArtifactKind,
)
from scripts.demo_e2e.recovery import RecoveryLedgerStore, create_private_ledger_directory


class CleanInstallError(DemoE2EError):
    """The tracked-only bootstrap failed without leaking command context."""

    __slots__ = ("ledger_path",)

    def __init__(self, message: str, *, ledger_path: Path | None = None) -> None:
        super().__init__(message)
        self.ledger_path = ledger_path


def verify_clean_install(source_root: Path) -> str:
    uv = shutil.which("uv")
    if uv is None:
        raise CleanInstallError("uv executable is unavailable")
    metadata: CleanCheckoutMetadata | None = None
    ledger: RecoveryLedgerStore | None = None
    ledger_directory: Path | None = None
    identity = DemoRunIdentity.create()
    runner = CommandRunner()
    completed = False
    try:
        metadata = create_clean_checkout(source_root)
        state_root = metadata.checkout_root.parent
        ledger_directory = create_private_ledger_directory(identity, Path(tempfile.gettempdir()))
        ledger = RecoveryLedgerStore.create(ledger_directory / "recovery.json", identity)
        ledger.add_artifact(RecoveryArtifactKind.CHECKOUT, state_root)
        child_temp = state_root / "temp"
        child_home = state_root / "home"
        child_temp.mkdir(mode=0o700)
        child_home.mkdir(mode=0o700)
        environment = {
            "COMPOSE_ANSI": "never",
            "HOME": str(child_home),
            "NO_PROXY": "127.0.0.1,localhost",
            "UV_PROJECT_ENVIRONMENT": str(state_root / "venv"),
            "UV_CACHE_DIR": str(state_root / "uv-cache"),
            "UV_NO_PROGRESS": "1",
            "PLAYWRIGHT_BROWSERS_PATH": str(state_root / "playwright-browsers"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if os.name == "nt":
            environment.update({"TEMP": str(child_temp), "TMP": str(child_temp)})
        else:
            environment["TMPDIR"] = str(child_temp)
        runner.run(
            [uv, "sync", "--locked", "--all-packages"],
            cwd=metadata.checkout_root,
            environment=environment,
            timeout_seconds=600,
            output_limit=16 * 1_048_576,
        )
        runner.run(
            [uv, "run", "--no-sync", "playwright", "install", "--no-shell", "chromium"],
            cwd=metadata.checkout_root,
            environment=environment,
            timeout_seconds=900,
            output_limit=16 * 1_048_576,
        )
        result = runner.run(
            [
                uv,
                "run",
                "--no-sync",
                "python",
                "-m",
                "scripts.demo_e2e.orchestrator",
                "--project-root",
                str(metadata.checkout_root),
                "--source-head",
                metadata.source_head,
                "--run-id",
                identity.run_id,
                "--ledger",
                str(ledger.path),
            ],
            cwd=metadata.checkout_root,
            environment=environment,
            timeout_seconds=1_800,
            output_limit=4 * 1_048_576,
        )
        completed = True
        return result.text().strip()
    except (DemoE2EError, DemoCommandError):
        ledger_path = None if ledger is None else ledger.path
        raise CleanInstallError(
            "tracked-only clean-install verification failed safely",
            ledger_path=ledger_path,
        ) from None
    finally:
        if metadata is not None and ledger is None:
            remove_clean_checkout(metadata)
        elif metadata is not None and ledger is not None:
            if ledger.path.exists():
                ledger = RecoveryLedgerStore.open(ledger.path)
            may_remove = completed or not ledger.ledger.resources
            if may_remove:
                state_root = metadata.checkout_root.parent
                remove_clean_checkout(metadata)
                ledger.remove_artifact(RecoveryArtifactKind.CHECKOUT, state_root)
                if not ledger.ledger.resources and not ledger.ledger.artifacts:
                    ledger.finish()
                    if ledger_directory is not None:
                        ledger_directory.rmdir()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify Woland Guard from git archive HEAD")
    parser.add_argument("--source-root", type=Path, required=True)
    return parser


def main() -> None:
    arguments = _build_parser().parse_args()
    try:
        with cooperative_signal_handlers():
            summary = verify_clean_install(arguments.source_root)
    except CleanInstallError as error:
        print("Clean-install verification failed safely.")
        if error.ledger_path is not None and error.ledger_path.exists():
            print(f"Recovery ledger: {error.ledger_path}")
        raise SystemExit(1) from None
    print(summary)


if __name__ == "__main__":
    main()
