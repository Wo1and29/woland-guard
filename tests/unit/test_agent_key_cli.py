"""Unit tests for non-reflective agent-key lifecycle CLI output."""

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from woland_guard_control_plane import cli
from woland_guard_control_plane.application.agent_key_management import (
    AgentKeyManagementError,
    IssuedAgentApiKey,
    RevokedAgentApiKey,
)

_SERVER_ID = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
_KEY_ID = UUID("11111111-2222-4333-8444-555555555555")


class FakeSessionFactory:
    @contextmanager
    def begin(self) -> Iterator[Session]:
        yield Mock(spec=Session)


def test_issue_command_prints_one_time_token_without_digest(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token = "wgak_public.synthetic-one-time-secret"  # noqa: S105 - synthetic test credential
    issued = IssuedAgentApiKey(
        server_id=_SERVER_ID,
        key_id=_KEY_ID,
        public_id="public",
        label="rotation",
        created_at=datetime(2026, 9, 20, 18, 0, tzinfo=UTC),
        token=token,
    )
    monkeypatch.setattr(cli, "get_session_factory", FakeSessionFactory)
    monkeypatch.setattr(cli, "issue_agent_api_key", lambda *_args, **_kwargs: issued)
    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "issue-agent-key", "--server", "existing-server"],
    )

    cli.main()

    output = capsys.readouterr().out
    assert output.count(token) == 1
    assert f"server_id={_SERVER_ID}" in output
    assert f"key_id={_KEY_ID}" in output
    assert "label=rotation" in output
    assert "secret_hash" not in output
    assert "digest" not in output


def test_revoke_command_reports_first_and_repeated_calls_without_secret(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = RevokedAgentApiKey(
        server_id=_SERVER_ID,
        key_id=_KEY_ID,
        public_id="public",
        revoked_at=datetime(2026, 9, 20, 18, 0, tzinfo=UTC),
        changed=False,
    )
    monkeypatch.setattr(cli, "get_session_factory", FakeSessionFactory)
    monkeypatch.setattr(cli, "revoke_agent_api_key", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "revoke-agent-key", "public"],
    )

    cli.main()

    output = capsys.readouterr().out
    assert "revoked=already" in output
    assert "token=" not in output
    assert "secret" not in output
    assert "hash" not in output


def test_lifecycle_error_is_not_reflected_to_cli_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "synthetic-secret-error-canary"
    monkeypatch.setattr(cli, "get_session_factory", FakeSessionFactory)

    def reject(*_args: object, **_kwargs: object) -> None:
        raise AgentKeyManagementError(canary)

    monkeypatch.setattr(cli, "revoke_agent_api_key", reject)
    monkeypatch.setattr(
        sys,
        "argv",
        ["woland-guard-admin", "revoke-agent-key", "unknown_public"],
    )

    with pytest.raises(SystemExit) as captured:
        cli.main()

    output = capsys.readouterr()
    assert captured.value.code == 2
    assert canary not in output.out
    assert canary not in output.err
    assert "token=" not in output.out
