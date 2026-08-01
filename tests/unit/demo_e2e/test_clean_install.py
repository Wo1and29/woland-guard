from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from scripts.demo_e2e import clean_install as clean_install_module
from scripts.demo_e2e.clean_install import CleanInstallError
from scripts.demo_e2e.commands import DemoCommandError
from scripts.demo_e2e.contracts import CleanCheckoutMetadata


class _FailingRunner:
    def run(self, *_args: object, **_kwargs: object) -> None:
        raise DemoCommandError("static command failure")


def test_clean_install_removes_exact_checkout_after_dependency_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "wg8b-clean-synthetic" / "checkout"
    checkout.mkdir(parents=True)
    metadata = CleanCheckoutMetadata(source_head="a" * 40, checkout_root=checkout)
    removed: list[CleanCheckoutMetadata] = []
    monkeypatch.setattr(shutil, "which", lambda _name: "uv")
    monkeypatch.setattr(clean_install_module, "create_clean_checkout", lambda _root: metadata)
    monkeypatch.setattr(clean_install_module, "CommandRunner", _FailingRunner)
    monkeypatch.setattr(clean_install_module, "remove_clean_checkout", removed.append)

    with pytest.raises(CleanInstallError):
        clean_install_module.verify_clean_install(tmp_path)

    assert removed == [metadata]
