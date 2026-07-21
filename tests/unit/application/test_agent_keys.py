"""Tests for one-time agent key generation and verification."""

import pytest

from woland_guard_control_plane.application.agent_keys import (
    SECRET_HASH_SIZE,
    generate_agent_api_key,
    parse_agent_api_key_public_id,
    verify_agent_api_key,
)


def test_generated_key_verifies_and_exposes_only_digest_for_storage() -> None:
    """Generated key material can be verified from its persisted digest."""

    material = generate_agent_api_key()

    assert len(material.secret_hash) == SECRET_HASH_SIZE
    assert material.token.startswith(f"wgak_{material.public_id}.")
    assert verify_agent_api_key(
        material.token,
        expected_public_id=material.public_id,
        expected_secret_hash=material.secret_hash,
    )


def test_tampered_key_is_rejected() -> None:
    """Changing the random secret invalidates the credential."""

    material = generate_agent_api_key()

    assert not verify_agent_api_key(
        f"{material.token}changed",
        expected_public_id=material.public_id,
        expected_secret_hash=material.secret_hash,
    )


def test_wrong_public_id_is_rejected() -> None:
    """A valid secret cannot authenticate under another public identifier."""

    material = generate_agent_api_key()

    assert not verify_agent_api_key(
        material.token,
        expected_public_id=f"wrong-{material.public_id}",
        expected_secret_hash=material.secret_hash,
    )


@pytest.mark.parametrize("malformed_token", ["", "not-an-agent-key", "wgak_."])
def test_malformed_token_is_rejected(malformed_token: str) -> None:
    """Malformed input is rejected without raising an exception."""

    material = generate_agent_api_key()

    assert not verify_agent_api_key(
        malformed_token,
        expected_public_id=material.public_id,
        expected_secret_hash=material.secret_hash,
    )


@pytest.mark.parametrize("invalid_hash_length", [31, 33])
def test_unexpected_digest_length_is_rejected(invalid_hash_length: int) -> None:
    """Verification refuses persisted digests that violate the database invariant."""

    material = generate_agent_api_key()

    assert not verify_agent_api_key(
        material.token,
        expected_public_id=material.public_id,
        expected_secret_hash=b"x" * invalid_hash_length,
    )


@pytest.mark.parametrize("separator_count", [0, 2])
def test_missing_or_extra_separator_is_rejected(separator_count: int) -> None:
    """The token body must contain exactly one public-id/secret separator."""

    material = generate_agent_api_key()
    public_part, secret = material.token.split(".", maxsplit=1)
    malformed_token = public_part + ("." * separator_count) + secret

    assert not verify_agent_api_key(
        malformed_token,
        expected_public_id=material.public_id,
        expected_secret_hash=material.secret_hash,
    )


def test_public_id_is_extracted_only_from_valid_token_shape() -> None:
    """Database lookup receives only a public ID from a structurally valid token."""

    material = generate_agent_api_key()

    assert parse_agent_api_key_public_id(material.token) == material.public_id
    assert parse_agent_api_key_public_id("not-an-agent-key") is None
    assert parse_agent_api_key_public_id(f"{material.token}.extra") is None


def test_secret_material_is_hidden_from_repr() -> None:
    """Accidental dataclass logging does not include the plaintext token or digest."""

    material = generate_agent_api_key()
    representation = repr(material)

    assert material.token not in representation
    assert repr(material.secret_hash) not in representation
