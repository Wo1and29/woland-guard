"""Structured logging tests that prevent token and payload disclosure."""

import json
import logging

from woland_guard_agent.config import SecretToken
from woland_guard_agent.logging import JsonFormatter


def test_json_formatter_keeps_secret_wrapper_redacted() -> None:
    plaintext = "wgak_logging.synthetic-secret"
    token = SecretToken(plaintext)
    record = logging.LogRecord(
        name="woland_guard_agent.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="credential=%r",
        args=(token,),
        exc_info=None,
    )

    rendered = JsonFormatter().format(record)
    document = json.loads(rendered)

    assert plaintext not in rendered
    assert document["message"] == "credential=SecretToken(<redacted>)"
    assert set(document) == {"timestamp", "level", "logger", "message"}
