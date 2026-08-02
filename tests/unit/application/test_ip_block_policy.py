"""Unit tests for the never-execute IP block target policy."""

from unittest.mock import Mock

import pytest
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.ip_block_policy import (
    BlockTargetRejectionReason,
    build_nft_block_command,
    classify_block_target,
)

_NEVER_BLOCK_ADDRESSES = (
    "127.0.0.1",
    "10.0.0.5",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.1.1",
    "100.64.0.1",
    "192.0.2.10",  # TEST-NET-1, also used by the demo scenario generator
    "198.51.100.10",
    "203.0.113.10",  # TEST-NET-3
    "224.0.0.1",
    "255.255.255.255",
    "0.0.0.0",  # noqa: S104
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "ff02::1",
    "2001:db8::1",
    "2001::1",
    "2002::1",
)


@pytest.mark.parametrize("raw_address", _NEVER_BLOCK_ADDRESSES)
def test_never_block_addresses_are_rejected_without_touching_the_database(
    raw_address: str,
) -> None:
    session = Mock(spec=Session)

    decision = classify_block_target(session, raw_address=raw_address)

    assert decision.allowed is False
    assert decision.rejection_reason is BlockTargetRejectionReason.NEVER_BLOCK
    session.scalar.assert_not_called()


@pytest.mark.parametrize(
    "raw_address",
    [
        "",
        "not-an-address",
        "999.999.999.999",
        "203.0.113.5.1",
        "0203.0.113.5",  # leading zero octet is rejected by ipaddress itself
    ],
)
def test_unparseable_values_are_rejected_as_not_an_address(raw_address: str) -> None:
    session = Mock(spec=Session)

    decision = classify_block_target(session, raw_address=raw_address)

    assert decision.allowed is False
    assert decision.address is None
    assert decision.rejection_reason is BlockTargetRejectionReason.NOT_AN_ADDRESS
    session.scalar.assert_not_called()


@pytest.mark.parametrize(
    "raw_address",
    [
        "::ffff:203.0.113.5",  # IPv4-mapped IPv6 normalizes to a different string
        "fe80::1%eth0",  # scope id
    ],
)
def test_non_canonical_forms_are_rejected_without_normalizing_them(raw_address: str) -> None:
    session = Mock(spec=Session)

    decision = classify_block_target(session, raw_address=raw_address)

    assert decision.allowed is False
    assert decision.rejection_reason is BlockTargetRejectionReason.NOT_CANONICAL
    session.scalar.assert_not_called()


def test_allowlisted_public_address_is_rejected() -> None:
    session = Mock(spec=Session)
    session.scalar.return_value = "some-allowlist-entry-id"

    decision = classify_block_target(session, raw_address="8.8.8.8")

    assert decision.allowed is False
    assert decision.rejection_reason is BlockTargetRejectionReason.ALLOWLISTED
    session.scalar.assert_called_once()


def test_non_allowlisted_public_address_is_allowed() -> None:
    session = Mock(spec=Session)
    session.scalar.return_value = None

    decision = classify_block_target(session, raw_address="8.8.8.8")

    assert decision.allowed is True
    assert decision.rejection_reason is None
    assert str(decision.address) == "8.8.8.8"


def test_build_nft_block_command_selects_the_set_by_address_family() -> None:
    session = Mock(spec=Session)
    session.scalar.return_value = None
    v4 = classify_block_target(session, raw_address="8.8.8.8").address
    v6 = classify_block_target(session, raw_address="2606:4700:4700::1111").address
    assert v4 is not None
    assert v6 is not None

    argv_v4 = build_nft_block_command(
        v4, table="woland_guard", set_v4="blocked_v4", set_v6="blocked_v6"
    )
    argv_v6 = build_nft_block_command(
        v6, table="woland_guard", set_v4="blocked_v4", set_v6="blocked_v6"
    )

    assert argv_v4 == (
        "nft",
        "add",
        "element",
        "inet",
        "woland_guard",
        "blocked_v4",
        "{",
        "8.8.8.8",
        "}",
    )
    assert argv_v6[5] == "blocked_v6"
    assert all(" " not in token for token in argv_v4)
    assert all(" " not in token for token in argv_v6)


def test_build_nft_block_command_rejects_malformed_identifiers() -> None:
    session = Mock(spec=Session)
    session.scalar.return_value = None
    address = classify_block_target(session, raw_address="8.8.8.8").address
    assert address is not None

    with pytest.raises(ValueError, match="nftables identifier"):
        build_nft_block_command(
            address, table="Woland Guard", set_v4="blocked_v4", set_v6="blocked_v6"
        )
