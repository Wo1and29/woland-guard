"""Unit contracts for opaque Dashboard session and CSRF tokens."""

from dataclasses import fields
from uuid import uuid4

import pytest

from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.application.web_sessions import (
    AuthenticatedWebSession,
    generate_web_token,
    verify_csrf_tokens,
    web_token_digest,
)
from woland_guard_control_plane.infrastructure.database.models import (
    OperatorAuthMethodType,
    OperatorRole,
)


def test_generated_session_and_csrf_tokens_are_independent_and_digest_only() -> None:
    session_token = generate_web_token()
    csrf_token = generate_web_token()

    assert session_token != csrf_token
    assert len(session_token) == len(csrf_token) == 43
    assert len(web_token_digest(session_token) or b"") == 32
    assert verify_csrf_tokens(
        cookie_token=csrf_token,
        form_token=csrf_token,
        expected_digest=web_token_digest(csrf_token),
    )


@pytest.mark.parametrize(
    ("cookie_token", "form_token"),
    [("", ""), ("not-a-token", "not-a-token"), (generate_web_token(), generate_web_token())],
)
def test_csrf_rejects_malformed_or_mismatched_tokens(
    cookie_token: str,
    form_token: str,
) -> None:
    assert not verify_csrf_tokens(
        cookie_token=cookie_token,
        form_token=form_token,
        expected_digest=web_token_digest(form_token),
    )


def test_web_session_dto_contains_no_plaintext_token_field() -> None:
    principal = OperatorPrincipal(
        operator_id=uuid4(),
        username="synthetic-operator",
        role=OperatorRole.ANALYST,
        auth_method_type=OperatorAuthMethodType.WEB_SESSION,
        auth_method_id=uuid4(),
    )
    authenticated = AuthenticatedWebSession(
        principal=principal,
        session_id=principal.auth_method_id,
        csrf_token_digest=b"x" * 32,
    )

    assert {item.name for item in fields(authenticated)} == {
        "principal",
        "session_id",
        "csrf_token_digest",
    }
    assert "b'x" not in repr(authenticated)
