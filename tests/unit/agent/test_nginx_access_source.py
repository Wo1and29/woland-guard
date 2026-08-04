"""Behaviour of the nginx combined-format access log adapter (ADR-0020)."""

from __future__ import annotations

from pathlib import Path
from threading import Event

from woland_guard_agent.normalization import normalize_record
from woland_guard_agent.sources import JournalRecord
from woland_guard_agent.sources.nginx_access import (
    MAX_PATH_CHARS,
    REDACTED_PATH,
    NginxAccessSource,
    safe_path,
)
from woland_guard_contracts import EventSource

STAMP = "04/Aug/2026:12:34:56 +0000"


def line(
    *,
    address: str = "198.51.100.7",
    method: str = "GET",
    target: str = "/admin",
    status: int = 404,
    user_agent: str = "curl/8.0",
) -> str:
    return f'{address} - - [{STAMP}] "{method} {target} HTTP/1.1" {status} 153 "-" "{user_agent}"'


def write(path: Path, *lines: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for entry in lines:
            handle.write(entry + "\n")


def drain(path: Path) -> list[JournalRecord]:
    source = NginxAccessSource(path)
    return list(source.backlog(after_cursor=None, stop_event=Event(), initial_limit=None))


def test_failed_and_completed_requests_get_distinct_event_types(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    write(log, line(status=404), line(status=200, target="/"), line(status=500))

    events = [normalize_record(r, source=EventSource.NGINX_ACCESS) for r in drain(log)]
    recognised = [event for event in events if event is not None]

    assert [event.event_type for event in recognised] == [
        "web.nginx.request_failed",
        "web.nginx.request_completed",
        "web.nginx.request_failed",
    ]
    assert all(event.source is EventSource.NGINX_ACCESS for event in recognised)


def test_query_string_never_reaches_the_event(tmp_path: Path) -> None:
    """The parameter holding a secret cannot be recognised by name."""

    synthetic_marker = "reset-token-canary-value"
    log = tmp_path / "access.log"
    write(log, line(target=f"/reset?token={synthetic_marker}&next=/dashboard"))

    record = drain(log)[0]
    event = normalize_record(record, source=EventSource.NGINX_ACCESS)

    assert event is not None
    serialised = event.model_dump_json()
    assert synthetic_marker not in serialised
    assert "token=" not in serialised
    assert event.attributes["path"] == "/reset"


def test_referer_and_user_agent_are_not_extracted_at_all(tmp_path: Path) -> None:
    """Neither field is needed by the rules, so the parser does not read them."""

    log = tmp_path / "access.log"
    marker = "fingerprintable-agent-string"
    write(log, line(user_agent=marker))

    record = drain(log)[0]
    event = normalize_record(record, source=EventSource.NGINX_ACCESS)

    assert event is not None
    assert marker not in event.model_dump_json()
    assert set(event.attributes) == {"status", "method", "path"}


def test_source_ip_and_status_are_preserved_for_grouping(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    write(log, line(address="203.0.113.9", status=401))

    event = normalize_record(drain(log)[0], source=EventSource.NGINX_ACCESS)

    assert event is not None
    assert str(event.source_ip) == "203.0.113.9"
    assert event.attributes["status"] == 401
    assert event.attributes["method"] == "GET"


def test_lines_in_an_unknown_log_format_are_skipped_not_guessed(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    write(
        log,
        "this is not a combined log line",
        '198.51.100.7 - - [bad stamp] "GET / HTTP/1.1" 200 1 "-" "-"',
        line(),
    )

    assert len(drain(log)) == 1


def test_invalid_address_or_status_is_rejected(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    write(
        log,
        line(address="not-an-ip"),
        line(status=999),
        line(method="BREW"),
        line(),
    )

    assert len(drain(log)) == 1


def test_overlong_path_is_truncated_rather_than_sent_whole() -> None:
    truncated = safe_path("/" + "a" * (MAX_PATH_CHARS * 2))

    assert len(truncated) == MAX_PATH_CHARS
    assert truncated.endswith("...")


def test_unprintable_path_is_replaced_not_partially_copied() -> None:
    assert safe_path("/admin\x01\x02") == REDACTED_PATH
    assert safe_path("/каталог") == REDACTED_PATH


def test_query_is_dropped_even_without_a_path() -> None:
    assert safe_path("/?token=abc") == "/"
    assert safe_path("/a?b?c") == "/a"


def test_ipv6_client_is_accepted(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    write(log, line(address="2001:db8::1"))

    event = normalize_record(drain(log)[0], source=EventSource.NGINX_ACCESS)

    assert event is not None
    assert str(event.source_ip) == "2001:db8::1"


def test_timestamp_offset_is_honoured(tmp_path: Path) -> None:
    """nginx writes a local time plus offset; the event must be UTC-correct."""

    log = tmp_path / "access.log"
    write(log, '198.51.100.7 - - [04/Aug/2026:15:00:00 +0300] "GET / HTTP/1.1" 200 1 "-" "-"')

    event = normalize_record(drain(log)[0], source=EventSource.NGINX_ACCESS)

    assert event is not None
    assert event.occurred_at.hour == 12, "15:00 +0300 is 12:00 UTC"
