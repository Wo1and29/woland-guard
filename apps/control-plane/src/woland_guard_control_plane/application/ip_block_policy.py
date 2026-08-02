"""Closed policy for whether one source IP address may be proposed for blocking.

This is the single place that decides whether an address is eligible for an
``ip_block_plans`` row. It never executes anything -- it only classifies an
address as blockable or not, and if not, why. The reasons are a closed
enumeration so a caller can render a fixed, safe message without reflecting
the address or any database content back to the requester.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.infrastructure.database.models import IpBlockAllowlistEntry

BlockableAddress = IPv4Address | IPv6Address

# Every entry is explicit and commented rather than derived from `ipaddress`
# properties such as `is_private` or `is_reserved`: those properties have
# changed which ranges they cover between Python versions, and a security
# allowlist needs to be readable and individually testable in review. The
# `is_*` properties are still checked in `_is_never_block` as a second,
# independent layer -- belt and suspenders, not a replacement.
_NEVER_BLOCK_NETWORKS: Final[tuple[IPv4Network | IPv6Network, ...]] = (
    ip_network("0.0.0.0/8"),  # "this network" -- RFC 791 source-only
    ip_network("10.0.0.0/8"),  # RFC 1918 private
    ip_network("100.64.0.0/10"),  # RFC 6598 carrier-grade NAT
    ip_network("127.0.0.0/8"),  # loopback
    ip_network("169.254.0.0/16"),  # link-local
    ip_network("172.16.0.0/12"),  # RFC 1918 private
    ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ip_network("192.0.2.0/24"),  # TEST-NET-1 documentation
    ip_network("192.168.0.0/16"),  # RFC 1918 private
    ip_network("198.18.0.0/15"),  # benchmarking
    ip_network("198.51.100.0/24"),  # TEST-NET-2 documentation
    ip_network("203.0.113.0/24"),  # TEST-NET-3 documentation
    ip_network("224.0.0.0/4"),  # multicast
    ip_network("240.0.0.0/4"),  # reserved
    ip_network("255.255.255.255/32"),  # limited broadcast
    ip_network("::/128"),  # unspecified
    ip_network("::1/128"),  # loopback
    ip_network("fc00::/7"),  # unique local addresses (ULA)
    ip_network("fe80::/10"),  # link-local
    ip_network("ff00::/8"),  # multicast
    ip_network("2001::/32"),  # Teredo tunneling
    ip_network("2002::/16"),  # 6to4
    ip_network("2001:db8::/32"),  # documentation
)

_NFT_IDENTIFIER_PATTERN: Final = r"^[a-z][a-z0-9_]{0,31}$"


class BlockTargetRejectionReason(StrEnum):
    """Closed set of reasons an address may not be proposed for blocking."""

    NOT_AN_ADDRESS = "not_an_address"
    NOT_CANONICAL = "not_canonical"
    NEVER_BLOCK = "never_block"
    ALLOWLISTED = "allowlisted"


@dataclass(frozen=True, slots=True)
class BlockTargetDecision:
    """The outcome of classifying one address, never echoing raw input back."""

    allowed: bool
    address: BlockableAddress | None
    rejection_reason: BlockTargetRejectionReason | None


def classify_block_target(session: Session, *, raw_address: str) -> BlockTargetDecision:
    """Decide whether one address value is eligible for an IP block plan.

    ``raw_address`` is treated as fully untrusted regardless of where it came
    from -- it is parsed, required to be in canonical form, checked against the
    hardcoded never-block set, and finally checked against the allowlist.
    """

    parsed = _parse_canonical_address(raw_address)
    if parsed is None:
        return BlockTargetDecision(False, None, BlockTargetRejectionReason.NOT_AN_ADDRESS)
    if _has_scope_id(parsed) or str(parsed) != raw_address:
        return BlockTargetDecision(False, None, BlockTargetRejectionReason.NOT_CANONICAL)
    if _is_never_block(parsed):
        return BlockTargetDecision(False, parsed, BlockTargetRejectionReason.NEVER_BLOCK)
    if _is_allowlisted(session, parsed):
        return BlockTargetDecision(False, parsed, BlockTargetRejectionReason.ALLOWLISTED)
    return BlockTargetDecision(True, parsed, None)


def build_nft_block_command(
    address: BlockableAddress,
    *,
    table: str,
    set_v4: str,
    set_v6: str,
) -> tuple[str, ...]:
    """Build the fixed argv that would add one address to an nftables set.

    The table and both set names are configuration values, not user input, but
    are still validated here: this function is the only place the argv is
    assembled, and every token in the result must be free of whitespace so the
    displayed command cannot be misread as more than one shell word.
    """

    for identifier in (table, set_v4, set_v6):
        if re.fullmatch(_NFT_IDENTIFIER_PATTERN, identifier) is None:
            raise ValueError("nftables identifier is outside the allowed pattern")
    set_name = set_v4 if isinstance(address, IPv4Address) else set_v6
    return ("nft", "add", "element", "inet", table, set_name, "{", str(address), "}")


def _parse_canonical_address(raw_address: str) -> BlockableAddress | None:
    if not 1 <= len(raw_address) <= 45:
        return None
    try:
        return ip_address(raw_address)
    except ValueError:
        return None


def _has_scope_id(address: BlockableAddress) -> bool:
    return isinstance(address, IPv6Address) and address.scope_id is not None


def _is_never_block(address: BlockableAddress) -> bool:
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address.is_private
    ):
        return True
    return any(address in network for network in _NEVER_BLOCK_NETWORKS)


def _is_allowlisted(session: Session, address: BlockableAddress) -> bool:
    return (
        session.scalar(
            select(IpBlockAllowlistEntry.id).where(
                IpBlockAllowlistEntry.revoked_at.is_(None),
                IpBlockAllowlistEntry.cidr.op(">>=")(str(address)),
            )
        )
        is not None
    )
