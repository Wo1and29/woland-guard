"""Tests for one-time operator key generation and constant-time verification."""

import pytest

from woland_guard_control_plane.application.operator_keys import (
    PUBLIC_ID_LENGTH,
    SECRET_HASH_SIZE,
    generate_operator_api_key,
    parse_operator_api_key_public_id,
    verify_operator_api_key,
)


def test_generated_operator_key_verifies_and_only_digest_is_persistable() -> None:
    material = generate_operator_api_key()

    assert len(material.public_id) == PUBLIC_ID_LENGTH
    assert len(material.secret_hash) == SECRET_HASH_SIZE
    assert material.token.startswith(f"wgok_{material.public_id}.")
    assert verify_operator_api_key(
        material.token,
        expected_public_id=material.public_id,
        expected_secret_hash=material.secret_hash,
    )


def test_wrong_secret_and_public_id_are_rejected() -> None:
    material = generate_operator_api_key()
    replacement = "A" if material.token[-1] != "A" else "B"
    tampered_token = f"{material.token[:-1]}{replacement}"

    assert not verify_operator_api_key(
        tampered_token,
        expected_public_id=material.public_id,
        expected_secret_hash=material.secret_hash,
    )
    assert not verify_operator_api_key(
        material.token,
        expected_public_id="x" * PUBLIC_ID_LENGTH,
        expected_secret_hash=material.secret_hash,
    )


@pytest.mark.parametrize(
    "malformed_token",
    [
        "",
        "not-an-operator-key",
        "wgok_.",
        "wgok_public.secret.extra",
        "wgak_public.secret",
        "wgok_short.secret",
    ],
)
def test_malformed_operator_token_is_rejected(malformed_token: str) -> None:
    material = generate_operator_api_key()

    assert parse_operator_api_key_public_id(malformed_token) is None
    assert not verify_operator_api_key(
        malformed_token,
        expected_public_id=material.public_id,
        expected_secret_hash=material.secret_hash,
    )


@pytest.mark.parametrize("invalid_hash_length", [0, 31, 33])
def test_operator_verifier_rejects_invalid_expected_digest_length(
    invalid_hash_length: int,
) -> None:
    material = generate_operator_api_key()

    assert not verify_operator_api_key(
        material.token,
        expected_public_id=material.public_id,
        expected_secret_hash=b"x" * invalid_hash_length,
    )


def test_parser_returns_only_the_generated_public_identifier() -> None:
    material = generate_operator_api_key()

    assert parse_operator_api_key_public_id(material.token) == material.public_id


def test_operator_key_material_repr_hides_token_and_digest() -> None:
    material = generate_operator_api_key()
    representation = repr(material)

    assert material.token not in representation
    assert repr(material.secret_hash) not in representation
