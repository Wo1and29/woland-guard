"""The one supported-language contract shared by every operator-facing surface.

Both the Dashboard (cookie-driven) and the Telegram bot (per-operator preference
plus the client's own language tag) resolve to this same closed set, so neither
surface has to depend on the other for the primitive.
"""

from __future__ import annotations

from typing import Literal

Language = Literal["ru", "en"]
SUPPORTED_LANGUAGES: tuple[Language, ...] = ("ru", "en")
DEFAULT_LANGUAGE: Language = "ru"


def normalize_language(value: str | None) -> Language:
    """Map any untrusted value onto the closed set, never raising."""

    if value == "ru":
        return "ru"
    if value == "en":
        return "en"
    return DEFAULT_LANGUAGE


def language_from_client_tag(value: str | None) -> Language | None:
    """Read an IETF language tag such as ``en-GB`` supplied by a client.

    Returns ``None`` rather than the default when the tag names a language we do
    not serve, so a caller can fall through to its own next-best source instead
    of silently treating "unknown" as Russian.
    """

    if not value:
        return None
    primary = value.split("-", 1)[0].casefold()
    if primary in SUPPORTED_LANGUAGES:
        return normalize_language(primary)
    return None
