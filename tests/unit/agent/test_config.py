"""YAML, HTTPS and token-file security tests."""

import logging
import os
from pathlib import Path

import pytest

from woland_guard_agent.cli import main
from woland_guard_agent.config import (
    AgentConfigurationError,
    SecretToken,
    load_agent_settings,
    load_secret_token,
)
from woland_guard_agent.platform_support import UnsupportedPlatformError, require_ubuntu_2404

SYNTHETIC_TOKEN = "wgak_fixture-public.fixture-secret"  # noqa: S105


def test_valid_yaml_references_token_file_without_containing_token(tmp_path: Path) -> None:
    token_path = private_token_file(tmp_path)
    config_path = write_config(tmp_path, token_path=token_path)

    settings = load_agent_settings(config_path)
    token = load_secret_token(settings.http.token_file)

    assert settings.source == "journald"
    assert settings.http.batch_size == 100
    assert SYNTHETIC_TOKEN not in config_path.read_text(encoding="utf-8")
    assert repr(token) == "SecretToken(<redacted>)"


def test_missing_token_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(AgentConfigurationError, match="token_file is unavailable"):
        load_secret_token(tmp_path / "missing.token")


def test_malformed_token_file_is_rejected_without_echoing_secret(tmp_path: Path) -> None:
    token_path = tmp_path / "agent.token"
    malformed = "not-a-valid-secret-value"
    token_path.write_text(malformed, encoding="utf-8")
    token_path.chmod(0o600)

    with pytest.raises(AgentConfigurationError) as captured:
        load_secret_token(token_path)

    assert malformed not in str(captured.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode are checked on Linux")
def test_group_readable_token_file_is_rejected(tmp_path: Path) -> None:
    token_path = tmp_path / "agent.token"
    token_path.write_text(SYNTHETIC_TOKEN, encoding="utf-8")
    token_path.chmod(0o640)

    with pytest.raises(AgentConfigurationError, match="0600 or stricter"):
        load_secret_token(token_path)


@pytest.mark.skipif(
    os.name == "nt",
    reason="creating symlinks is not reliably permitted on Windows",
)
def test_token_symlink_is_rejected(tmp_path: Path) -> None:
    target = private_token_file(tmp_path)
    link = tmp_path / "linked.token"
    link.symlink_to(target)

    with pytest.raises(AgentConfigurationError, match="symbolic link"):
        load_secret_token(link)


def test_plaintext_yaml_token_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "unsafe.yaml"
    config.write_text(
        """
schema_version: 1
source: journald
http:
  base_url: https://control-plane.invalid
  token_file: /tmp/token
  token: must-not-be-accepted
spool:
  path: /tmp/spool.sqlite3
  max_events: 10
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(AgentConfigurationError) as captured:
        load_agent_settings(config)

    assert "must-not-be-accepted" not in str(captured.value)
    assert "http.token" in str(captured.value)


def test_plain_http_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "plain-http.yaml"
    config.write_text(
        """
schema_version: 1
source: journald
http:
  base_url: http://control-plane.invalid
  token_file: /tmp/token
spool:
  path: /tmp/spool.sqlite3
  max_events: 10
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(AgentConfigurationError, match="fields: http"):
        load_agent_settings(config)


def test_token_is_redacted_from_repr_logs_and_exceptions(caplog: pytest.LogCaptureFixture) -> None:
    token = SecretToken(SYNTHETIC_TOKEN)

    with caplog.at_level(logging.INFO):
        logging.getLogger("agent-test").info("token=%r", token)
    error = RuntimeError(token)

    assert SYNTHETIC_TOKEN not in repr(token)
    assert SYNTHETIC_TOKEN not in str(token)
    assert SYNTHETIC_TOKEN not in caplog.text
    assert SYNTHETIC_TOKEN not in str(error)


def test_only_ubuntu_2404_is_accepted(tmp_path: Path) -> None:
    supported = tmp_path / "supported-release"
    supported.write_text('ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")
    unsupported = tmp_path / "unsupported-release"
    unsupported.write_text('ID=debian\nVERSION_ID="12"\n', encoding="utf-8")

    require_ubuntu_2404(supported)
    with pytest.raises(UnsupportedPlatformError, match="only Ubuntu Server 24.04"):
        require_ubuntu_2404(unsupported)


def test_check_config_command_validates_yaml_and_token_file(tmp_path: Path) -> None:
    token_path = private_token_file(tmp_path)
    config_path = write_config(tmp_path, token_path=token_path)

    exit_code = main(["check-config", "--config", str(config_path)])

    assert exit_code == 0


def test_check_config_command_rejects_missing_token(tmp_path: Path) -> None:
    config_path = write_config(tmp_path, token_path=tmp_path / "missing.token")

    exit_code = main(["check-config", "--config", str(config_path)])

    assert exit_code == 2


def private_token_file(tmp_path: Path) -> Path:
    path = tmp_path / "agent.token"
    path.write_text(SYNTHETIC_TOKEN, encoding="utf-8")
    path.chmod(0o600)
    return path


def write_config(tmp_path: Path, *, token_path: Path) -> Path:
    path = tmp_path / "agent.yaml"
    path.write_text(
        f"""
schema_version: 1
source: journald
http:
  base_url: https://control-plane.invalid
  token_file: {token_path.as_posix()}
  connect_timeout_seconds: 5
  read_timeout_seconds: 15
  batch_size: 100
spool:
  path: {(tmp_path / "spool.sqlite3").as_posix()}
  max_events: 10
retry:
  base_seconds: 1
  maximum_seconds: 10
  authentication_seconds: 300
delivery_poll_seconds: 1
log_level: INFO
""".strip(),
        encoding="utf-8",
    )
    return path
