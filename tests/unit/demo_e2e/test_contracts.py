from __future__ import annotations

import pytest
from scripts.demo_e2e.contracts import DemoE2EError, DemoRunIdentity, SecretValue


def test_run_identity_is_closed_and_exact() -> None:
    identity = DemoRunIdentity.from_run_id("0123456789abcdef")

    assert identity.project_name == "wg8b-0123456789abcdef"
    assert identity.restore_project_name == "wg8b-0123456789abcdef-restore"
    assert identity.ownership_label == "wg8b-0123456789abcdef"


@pytest.mark.parametrize(
    "value",
    ["", "ABCDEF0123456789", "0123", "0123456789abcdef00", "../0123456789abcdef"],
)
def test_run_identity_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(DemoE2EError, match="identity is invalid"):
        DemoRunIdentity.from_run_id(value)


def test_secret_value_redacts_nested_and_direct_representations() -> None:
    secret = SecretValue("synthetic-credential-canary")

    assert repr(secret) == "SecretValue(<redacted>)"
    assert str(secret) == "<redacted>"
    assert "synthetic-credential-canary" not in repr([secret])
    assert secret.reveal() == "synthetic-credential-canary"
