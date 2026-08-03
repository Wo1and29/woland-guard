"""Catalog-wide invariants for the bilingual Telegram strings."""

from __future__ import annotations

import pytest

from woland_guard_control_plane.language import (
    SUPPORTED_LANGUAGES,
    language_from_client_tag,
    normalize_language,
)
from woland_guard_control_plane.telegram_bot.formatting import CALLBACK_ANSWER_MAX_CHARS
from woland_guard_control_plane.telegram_bot.i18n import catalog_keys, tg


@pytest.mark.parametrize("key", catalog_keys())
def test_every_key_is_translated_into_every_supported_language(key: str) -> None:
    """A missing translation would silently render Russian to an English operator."""

    for language in SUPPORTED_LANGUAGES:
        rendered = tg(language, key)
        assert rendered
        assert rendered != key


@pytest.mark.parametrize("key", [key for key in catalog_keys() if key.startswith("callback.")])
def test_callback_answers_fit_the_api_limit_in_both_languages(key: str) -> None:
    """answerCallbackQuery truncates past 200 characters, silently losing meaning."""

    for language in SUPPORTED_LANGUAGES:
        assert len(tg(language, key)) <= CALLBACK_ANSWER_MAX_CHARS


@pytest.mark.parametrize("key", [key for key in catalog_keys() if key.startswith("ip_block.")])
def test_ip_block_answers_fit_the_api_limit_in_both_languages(key: str) -> None:
    """These are delivered as callback answers too, including the longest strings."""

    for language in SUPPORTED_LANGUAGES:
        assert len(tg(language, key)) <= CALLBACK_ANSWER_MAX_CHARS


def test_unknown_key_renders_as_itself_rather_than_raising() -> None:
    assert tg("en", "no.such.key") == "no.such.key"


def test_unsupported_language_falls_back_to_the_default() -> None:
    assert tg("de", "callback.invalid") == tg("ru", "callback.invalid")


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("en", "en"),
        ("en-GB", "en"),
        ("EN-us", "en"),
        ("ru", "ru"),
        ("ru-RU", "ru"),
    ],
)
def test_client_language_tags_resolve_to_a_served_language(tag: str, expected: str) -> None:
    assert language_from_client_tag(tag) == expected


@pytest.mark.parametrize("tag", [None, "", "de", "fr-CA", "zz"])
def test_unserved_client_tags_resolve_to_none_not_to_the_default(tag: str | None) -> None:
    """None lets the caller fall through to its own next source instead of
    silently treating an unknown language as Russian."""

    assert language_from_client_tag(tag) is None


def test_normalize_language_closes_over_untrusted_values() -> None:
    assert normalize_language("en") == "en"
    assert normalize_language("de") == "ru"
    assert normalize_language(None) == "ru"
