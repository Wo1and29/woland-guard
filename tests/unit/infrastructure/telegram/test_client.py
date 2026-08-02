"""Fixed-origin HTTP and logging security regressions for Telegram delivery."""

import logging
import socket
from collections.abc import Iterator
from types import TracebackType
from typing import Self, cast

import httpx2
import pytest
from tests.support.fake_telegram_bot_api import FakeTelegramBotApiTransport

from woland_guard_control_plane.infrastructure.telegram.client import (
    TELEGRAM_API_ORIGIN,
    TelegramBotApiClient,
    TelegramHttpTimeouts,
    TelegramTransportError,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import TelegramToken

CANARY_TOKEN = "canary-token-value"  # noqa: S105
CANARY_CHAT_ID = 4_001_002_003


def _client(transport: httpx2.BaseTransport) -> TelegramBotApiClient:
    return TelegramBotApiClient._for_test(
        timeouts=TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1),
        transport=transport,
    )


def test_request_uses_canonical_origin_path_and_plain_text_body() -> None:
    fake_api = FakeTelegramBotApiTransport()
    response = _client(fake_api).send_message(
        token=TelegramToken(CANARY_TOKEN),
        chat_id=CANARY_CHAT_ID,
        text="Safe plain text",
        timeout_seconds=4,
    )

    assert TELEGRAM_API_ORIGIN == "https://api.telegram.org"
    assert fake_api.requests == [{"chat_id": CANARY_CHAT_ID, "text": "Safe plain text"}]
    assert response.status_code == 200


def test_get_updates_uses_canonical_origin_and_bounded_parameters() -> None:
    fake_api = FakeTelegramBotApiTransport(
        allowed_methods=("getUpdates",),
        response_chunks=(b'{"ok":true,"result":[]}',),
    )

    response = _client(fake_api).get_updates(
        token=TelegramToken(CANARY_TOKEN),
        offset=41,
        limit=25,
        long_poll_seconds=0,
        allowed_updates=("message",),
        timeout_seconds=4,
    )

    assert fake_api.methods == ["getUpdates"]
    assert fake_api.requests == [
        {"offset": 41, "limit": 25, "timeout": 0, "allowed_updates": ["message"]}
    ]
    assert response.status_code == 200


@pytest.mark.parametrize(
    "overrides",
    [
        {"offset": -1},
        {"limit": 0},
        {"limit": 101},
        {"long_poll_seconds": -1},
        {"allowed_updates": ()},
        {"allowed_updates": ("",)},
        {"allowed_updates": ("x" * 33,)},
        {"allowed_updates": ("сообщение",)},
    ],
)
def test_get_updates_rejects_out_of_contract_parameters(overrides: dict[str, object]) -> None:
    request: dict[str, object] = {
        "offset": 0,
        "limit": 25,
        "long_poll_seconds": 0,
        "allowed_updates": ("message",),
    }
    request.update(overrides)
    fake_api = FakeTelegramBotApiTransport(allowed_methods=("getUpdates",))

    with pytest.raises(ValueError, match="Telegram update request parameters are invalid"):
        _client(fake_api).get_updates(
            token=TelegramToken(CANARY_TOKEN),
            timeout_seconds=4,
            **request,  # type: ignore[arg-type]
        )
    assert fake_api.requests == []


def test_get_updates_response_limit_rejects_oversized_body() -> None:
    fake_api = FakeTelegramBotApiTransport(
        allowed_methods=("getUpdates",),
        response_chunks=(b"x" * 32_768, b"y" * 32_768, b"z"),
    )

    with pytest.raises(TelegramTransportError):
        _client(fake_api).get_updates(
            token=TelegramToken(CANARY_TOKEN),
            offset=0,
            limit=25,
            long_poll_seconds=0,
            allowed_updates=("message",),
            timeout_seconds=4,
        )


@pytest.mark.parametrize("root_level", [logging.INFO, logging.DEBUG])
def test_get_updates_logging_never_exposes_the_token(
    root_level: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    records: list[logging.LogRecord] = []
    original_factory = logging.getLogRecordFactory()

    def record_factory(*args: object, **kwargs: object) -> logging.LogRecord:
        record = original_factory(*args, **kwargs)
        records.append(record)
        return record

    logging.getLogger().setLevel(root_level)
    logging.setLogRecordFactory(record_factory)
    try:
        _client(
            FakeTelegramBotApiTransport(
                allowed_methods=("getUpdates",),
                response_chunks=(b'{"ok":true,"result":[]}',),
            )
        ).get_updates(
            token=TelegramToken(CANARY_TOKEN),
            offset=0,
            limit=25,
            long_poll_seconds=0,
            allowed_updates=("message",),
            timeout_seconds=4,
        )
    finally:
        logging.setLogRecordFactory(original_factory)

    rendered_records = " ".join(
        f"{record.name} {record.msg!r} {record.args!r} {record.__dict__!r}" for record in records
    )
    output = capsys.readouterr()
    assert CANARY_TOKEN not in rendered_records
    assert CANARY_TOKEN not in output.out
    assert CANARY_TOKEN not in output.err
    assert not any(
        record.name == "httpx2" or record.name.startswith("httpcore2") for record in records
    )


@pytest.mark.parametrize("root_level", [logging.INFO, logging.DEBUG])
def test_http_library_logging_never_exposes_canaries(
    root_level: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    records: list[logging.LogRecord] = []
    original_factory = logging.getLogRecordFactory()

    def record_factory(*args: object, **kwargs: object) -> logging.LogRecord:
        record = original_factory(*args, **kwargs)
        records.append(record)
        return record

    logging.getLogger().setLevel(root_level)
    logging.setLogRecordFactory(record_factory)
    try:
        _client(FakeTelegramBotApiTransport()).send_message(
            token=TelegramToken(CANARY_TOKEN),
            chat_id=CANARY_CHAT_ID,
            text="Safe plain text",
            timeout_seconds=4,
        )
    finally:
        logging.setLogRecordFactory(original_factory)

    rendered_records = " ".join(
        f"{record.name} {record.msg!r} {record.args!r} {record.__dict__!r}" for record in records
    )
    output = capsys.readouterr()
    for canary in (CANARY_TOKEN, str(CANARY_CHAT_ID)):
        assert canary not in rendered_records
        assert canary not in output.out
        assert canary not in output.err
    assert not any(
        record.name == "httpx2" or record.name.startswith("httpcore2") for record in records
    )


def test_environment_proxy_and_ca_variables_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ):
        monkeypatch.setenv(name, "synthetic-invalid-environment-value")
    fake_api = FakeTelegramBotApiTransport()
    _client(fake_api).send_message(
        token=TelegramToken(CANARY_TOKEN),
        chat_id=CANARY_CHAT_ID,
        text="Safe plain text",
        timeout_seconds=4,
    )
    assert len(fake_api.requests) == 1


def test_production_factory_disables_env_redirects_and_transport_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_options: dict[str, object] = {}
    transport_options: dict[str, object] = {}

    class FakeResponse:
        status_code = 200

        def __enter__(self) -> Self:
            return self

        def __exit__(
            self,
            _exception_type: type[BaseException] | None,
            _exception: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            return None

        def iter_bytes(self) -> Iterator[bytes]:
            yield b'{"ok":true}'

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            client_options.update(kwargs)

        def __enter__(self) -> Self:
            return self

        def __exit__(
            self,
            _exception_type: type[BaseException] | None,
            _exception: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            return None

        def stream(self, *_args: object, **_kwargs: object) -> FakeResponse:
            return FakeResponse()

    def fake_transport(**kwargs: object) -> object:
        transport_options.update(kwargs)
        return object()

    monkeypatch.setattr(httpx2, "Client", FakeClient)
    monkeypatch.setattr(httpx2, "HTTPTransport", fake_transport)
    client = TelegramBotApiClient.production(
        timeouts=TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1)
    )
    client.send_message(
        token=TelegramToken(CANARY_TOKEN),
        chat_id=CANARY_CHAT_ID,
        text="Safe plain text",
        timeout_seconds=4,
    )

    assert client_options["trust_env"] is False
    assert client_options["verify"] is True
    assert client_options["follow_redirects"] is False
    assert transport_options == {"retries": 0, "verify": True}


def test_dependency_injected_fake_performs_no_network_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    fake_api = FakeTelegramBotApiTransport()
    _client(fake_api).send_message(
        token=TelegramToken(CANARY_TOKEN),
        chat_id=CANARY_CHAT_ID,
        text="Safe plain text",
        timeout_seconds=4,
    )
    assert len(fake_api.requests) == 1


def test_streaming_response_limit_rejects_oversized_body() -> None:
    fake_api = FakeTelegramBotApiTransport(
        response_chunks=(b"x" * 32_768, b"y" * 32_768, b"z"),
    )
    client = _client(fake_api)

    with pytest.raises(TelegramTransportError):
        client.send_message(
            token=TelegramToken(CANARY_TOKEN),
            chat_id=CANARY_CHAT_ID,
            text="Safe plain text",
            timeout_seconds=4,
        )


INVALID_TIMEOUT_VALUES = (
    pytest.param(True, id="bool"),
    pytest.param("1", id="string"),
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative"),
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="positive-infinity"),
    pytest.param(float("-inf"), id="negative-infinity"),
)


def _timeouts_with_phase_value(phase: str, value: object) -> TelegramHttpTimeouts:
    typed_value = cast(float, value)
    if phase == "connect":
        return TelegramHttpTimeouts(connect=typed_value, read=1, write=1, pool=1)
    if phase == "read":
        return TelegramHttpTimeouts(connect=1, read=typed_value, write=1, pool=1)
    if phase == "write":
        return TelegramHttpTimeouts(connect=1, read=1, write=typed_value, pool=1)
    if phase == "pool":
        return TelegramHttpTimeouts(connect=1, read=1, write=1, pool=typed_value)
    raise AssertionError("unsupported timeout phase in test")


@pytest.mark.parametrize("phase", ["connect", "read", "write", "pool"])
@pytest.mark.parametrize("value", INVALID_TIMEOUT_VALUES)
def test_each_http_timeout_phase_rejects_invalid_or_non_finite_values(
    phase: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="Telegram HTTP timeout configuration is invalid"):
        _timeouts_with_phase_value(phase, value).validate_for(4)


@pytest.mark.parametrize("overall_budget", INVALID_TIMEOUT_VALUES)
def test_overall_http_timeout_budget_rejects_invalid_or_non_finite_values(
    overall_budget: object,
) -> None:
    timeouts = TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1)

    with pytest.raises(ValueError, match="Telegram HTTP timeout configuration is invalid"):
        timeouts.validate_for(cast(float, overall_budget))


def test_http_timeout_phase_sum_equal_to_budget_is_valid() -> None:
    TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1).validate_for(4)


def test_http_timeout_phase_sum_above_budget_is_invalid() -> None:
    with pytest.raises(ValueError, match="Telegram HTTP timeout configuration is invalid"):
        TelegramHttpTimeouts(connect=1, read=1, write=1, pool=1).validate_for(3.99)
