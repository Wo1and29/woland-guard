from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts.demo_e2e.contracts import (
    DemoRunIdentity,
    RecoveryArtifactKind,
    RecoveryResource,
    RecoveryResourceKind,
)
from scripts.demo_e2e.recovery import DemoRecoveryError, RecoveryLedgerStore


def _store(tmp_path: Path) -> RecoveryLedgerStore:
    directory = tmp_path / "private-ledger"
    directory.mkdir(mode=0o700)
    return RecoveryLedgerStore.create(
        directory / "recovery.json",
        DemoRunIdentity.from_run_id("0123456789abcdef"),
    )


def test_ledger_is_canonical_versioned_private_and_contains_no_secret_fields(
    tmp_path: Path,
) -> None:
    canary = "synthetic-ledger-credential-canary"
    store = _store(tmp_path)
    content = store.path.read_bytes()

    assert content.endswith(b"\n")
    assert content == store.path.read_bytes()
    assert canary.encode() not in content
    assert all(
        forbidden not in content
        for forbidden in (b"password", b"api_key", b"token", b"comment", b"environment")
    )
    assert RecoveryLedgerStore.open(store.path).ledger == store.ledger
    if os.name == "posix":
        assert store.path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.replace(b'"schema_version":1', b'"schema_version":1,"extra":1'),
        lambda value: value.replace(b'"artifacts":[]', b'"artifacts":[],"artifacts":[]'),
        lambda _value: b"{not-json}\n",
        lambda value: value.replace(b'"run_id":"0123456789abcdef"', b'"run_id":"wrong"'),
    ],
)
def test_ledger_rejects_extra_duplicate_corrupt_and_invalid_identity(
    tmp_path: Path, mutation: Callable[[bytes], bytes]
) -> None:
    store = _store(tmp_path)
    store.path.write_bytes(mutation(store.path.read_bytes()))

    with pytest.raises(DemoRecoveryError):
        RecoveryLedgerStore.open(store.path)


def test_ledger_rejects_symlink_or_reparse_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    link_parent = tmp_path / "private-link"
    link_parent.mkdir(mode=0o700)
    link = link_parent / "recovery.json"
    if os.name != "nt":
        link.symlink_to(store.path)
    else:
        shutil.copyfile(store.path, link)
        original_lstat = Path.lstat

        def reparse_lstat(path: Path) -> object:
            metadata = original_lstat(path)
            if path == link:
                values = {
                    name: getattr(metadata, name)
                    for name in dir(metadata)
                    if name.startswith("st_")
                }
                values["st_file_attributes"] = 0x400
                return SimpleNamespace(**values)
            return metadata

        monkeypatch.setattr(Path, "lstat", reparse_lstat)

    with pytest.raises(DemoRecoveryError):
        RecoveryLedgerStore.open(link)


def test_ledger_tracks_exact_resources_and_is_removed_only_when_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)
    resource = RecoveryResource(
        project_name=store.ledger.main_project_name,
        kind=RecoveryResourceKind.CONTAINER,
        resource_id="a" * 64,
    )
    artifact = tmp_path / "wg8b-manifests-synthetic"
    artifact.mkdir()
    store.replace_project_resources(store.ledger.main_project_name, (resource,))
    store.add_artifact(RecoveryArtifactKind.MANIFESTS, artifact)

    with pytest.raises(DemoRecoveryError, match="owns resources"):
        store.finish()
    assert store.path.exists()

    store.remove_resource(resource)
    store.remove_artifact(RecoveryArtifactKind.MANIFESTS, artifact)
    store.finish()
    assert not store.path.exists()


def test_ledger_rejects_noncanonical_json_even_when_schema_is_valid(tmp_path: Path) -> None:
    store = _store(tmp_path)
    document = json.loads(store.path.read_text(encoding="utf-8"))
    store.path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    with pytest.raises(DemoRecoveryError, match="canonical"):
        RecoveryLedgerStore.open(store.path)
