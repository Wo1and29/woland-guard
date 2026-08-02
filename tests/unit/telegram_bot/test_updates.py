from __future__ import annotations

import json

import pytest

from woland_guard_control_plane.infrastructure.telegram.updates import (
    TELEGRAM_MESSAGE_TEXT_MAX_CHARS,
    TELEGRAM_UPDATE_BATCH_MAX,
    TelegramUpdateError,
    parse_update_response,
)


def _message_update(update_id: int, **overrides: object) -> dict[str, object]:
    message: dict[str, object] = {
        "message_id": 10,
        "from": {"id": 4242, "is_bot": False},
        "chat": {"id": 4242, "type": "private"},
        "text": "/status",
    }
    message.update(overrides)
    return {"update_id": update_id, "message": message}


def _body(*updates: dict[str, object]) -> bytes:
    return json.dumps({"ok": True, "result": list(updates)}).encode("utf-8")


def test_parses_allowlisted_fields_and_orders_by_update_id() -> None:
    updates = parse_update_response(_body(_message_update(7), _message_update(3)))

    assert [update.update_id for update in updates] == [3, 7]
    first = updates[0].message
    assert first is not None
    assert first.sender is not None
    assert first.sender.id == 4242
    assert first.chat.type == "private"
    assert first.is_private is True
    assert first.text == "/status"


def test_ignores_unknown_provider_fields_instead_of_failing_closed() -> None:
    payload = _message_update(1)
    payload["some_future_update_kind"] = {"nested": True}
    assert isinstance(payload["message"], dict)
    payload["message"]["future_field"] = "ignored"

    updates = parse_update_response(_body(payload))

    assert len(updates) == 1
    message = updates[0].message
    assert message is not None
    assert not hasattr(message, "future_field")


def test_group_chat_is_parsed_but_not_marked_private() -> None:
    updates = parse_update_response(_body(_message_update(1, chat={"id": -100, "type": "group"})))

    message = updates[0].message
    assert message is not None
    assert message.is_private is False


def test_message_without_text_is_accepted_with_none_text() -> None:
    payload = _message_update(1)
    assert isinstance(payload["message"], dict)
    del payload["message"]["text"]

    updates = parse_update_response(_body(payload))

    message = updates[0].message
    assert message is not None
    assert message.text is None


@pytest.mark.parametrize(
    "payload",
    [
        b"not json at all",
        b"",
        json.dumps({"ok": False, "description": "unauthorized"}).encode(),
        json.dumps({"ok": True, "result": [{"update_id": -1}]}).encode(),
        json.dumps(
            {"ok": True, "result": [_message_update(1, **{"from": {"id": 0, "is_bot": False}})]}
        ).encode(),
    ],
)
def test_rejects_malformed_or_unsuccessful_responses(payload: bytes) -> None:
    with pytest.raises(TelegramUpdateError):
        parse_update_response(payload)


def test_rejects_batch_beyond_the_bounded_limit() -> None:
    oversized = [_message_update(index) for index in range(TELEGRAM_UPDATE_BATCH_MAX + 1)]

    with pytest.raises(TelegramUpdateError):
        parse_update_response(_body(*oversized))


def test_rejects_text_beyond_the_bounded_length() -> None:
    payload = _message_update(1, text="x" * (TELEGRAM_MESSAGE_TEXT_MAX_CHARS + 1))

    with pytest.raises(TelegramUpdateError):
        parse_update_response(_body(payload))


def test_error_never_reflects_the_provider_body() -> None:
    canary = "provider-controlled-canary-value"

    with pytest.raises(TelegramUpdateError) as captured:
        parse_update_response(json.dumps({"ok": False, "description": canary}).encode())

    assert canary not in str(captured.value)
