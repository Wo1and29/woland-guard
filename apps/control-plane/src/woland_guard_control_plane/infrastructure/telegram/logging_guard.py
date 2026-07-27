"""Process-local suppression for HTTP libraries whose URLs contain bot tokens."""

import logging

_SENSITIVE_NAMESPACES = ("httpx2", "httpcore2")
_DISABLED_LEVEL = logging.CRITICAL + 1


def suppress_sensitive_http_logging() -> None:
    """Contain current and future library loggers independently of the root level."""

    for namespace in _SENSITIVE_NAMESPACES:
        _contain(logging.getLogger(namespace))
    for name, candidate in logging.Logger.manager.loggerDict.items():
        if isinstance(candidate, logging.Logger) and any(
            name.startswith(f"{namespace}.") for namespace in _SENSITIVE_NAMESPACES
        ):
            _contain(candidate)


def _contain(target: logging.Logger) -> None:
    target.setLevel(_DISABLED_LEVEL)
    target.propagate = False
    target.handlers.clear()
    target.addHandler(logging.NullHandler())
