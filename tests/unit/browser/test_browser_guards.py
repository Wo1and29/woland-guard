from __future__ import annotations

from pathlib import Path

import pytest
from playwright.sync_api import Error as PlaywrightError
from tests.browser.guards import (
    BrowserOperationError,
    SecretValue,
    assert_secret_absent,
    audit_browser_artifacts,
    safe_browser_operation,
)


def test_secret_value_is_redacted_in_nested_representations() -> None:
    secret = SecretValue("browser-credential-canary")
    assert "browser-credential-canary" not in repr(secret)
    assert "browser-credential-canary" not in str(secret)
    assert "browser-credential-canary" not in repr([secret])
    assert "browser-credential-canary" not in repr({"credential": secret})


def test_playwright_error_is_replaced_by_static_browser_error() -> None:
    def fail() -> None:
        raise PlaywrightError("browser-credential-canary")

    with pytest.raises(BrowserOperationError) as captured:
        safe_browser_operation(fail)
    assert str(captured.value) == "browser operation failed"
    assert captured.value.__cause__ is None
    assert "browser-credential-canary" not in repr(captured.value)


def test_secret_absence_failure_does_not_echo_the_secret() -> None:
    secret = SecretValue("browser-credential-canary")
    with pytest.raises(AssertionError) as captured:
        assert_secret_absent(secret, ["prefix browser-credential-canary suffix"])
    assert "browser-credential-canary" not in str(captured.value)


def test_artifact_audit_detects_and_does_not_echo_secret(tmp_path: Path) -> None:
    secret = SecretValue("browser-credential-canary")
    artifact = tmp_path / "probe.bin"
    artifact.write_bytes(b"browser-credential-canary")
    with pytest.raises(AssertionError) as captured:
        audit_browser_artifacts(tmp_path, [secret])
    assert "browser-credential-canary" not in str(captured.value)


def test_artifact_audit_rejects_trace_video_har_and_zip(tmp_path: Path) -> None:
    for suffix in (".har", ".trace", ".webm", ".zip"):
        artifact = tmp_path / f"artifact{suffix}"
        artifact.write_bytes(b"synthetic")
        with pytest.raises(AssertionError, match="forbidden browser artifact"):
            audit_browser_artifacts(tmp_path, [])
        artifact.unlink()
