"""Minimal structured logging that excludes credentials and event payloads."""

import json
import logging
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    """Serialize only controlled log metadata as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(document, ensure_ascii=True, separators=(",", ":"))


def configure_logging(level: str) -> None:
    """Configure one safe stderr handler and suppress verbose HTTP internals."""

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
