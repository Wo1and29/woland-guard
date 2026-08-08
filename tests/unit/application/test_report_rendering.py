"""Weekly report formats, tested without PostgreSQL (ADR-0023)."""

from __future__ import annotations

import sys
from datetime import UTC, date, datetime
from typing import cast

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from woland_guard_control_plane import cli
from woland_guard_control_plane.application.report_rendering import (
    LIMITATIONS,
    escape_cell,
    render_html,
    render_markdown,
)
from woland_guard_control_plane.application.weekly_report import (
    ReportPeriod,
    ReportPeriodError,
    WeeklyReport,
    build_weekly_report,
    week_ending,
)


def sample(**overrides: object) -> WeeklyReport:
    defaults: dict[str, object] = {
        "period": week_ending(date(2026, 8, 7)),
        "generated_at": datetime(2026, 8, 7, 6, 30, tzinfo=UTC),
        "servers_total": 3,
        "servers_active": 2,
        "servers_inactive": 1,
        "opened_by_severity": (("critical", 1), ("high", 4), ("medium", 0), ("low", 2)),
        "opened_by_rule": (("ssh_bruteforce_by_ip", 4), ("system_file_changed", 3)),
        "transitions_to_status": (
            ("investigating", 5),
            ("resolved", 3),
            ("false_positive", 1),
        ),
        "open_now_by_severity": (("critical", 1), ("high", 2), ("medium", 0), ("low", 0)),
        "events_by_source": (("journald", 1200), ("nginx_access", 340)),
    }
    return WeeklyReport(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_period_is_seven_days_and_excludes_its_end() -> None:
    """Two consecutive reports must not both count the boundary."""

    period = week_ending(date(2026, 8, 7))

    assert period.start == datetime(2026, 7, 31, tzinfo=UTC)
    assert period.end == datetime(2026, 8, 7, tzinfo=UTC)
    assert period.days == 7
    assert week_ending(date(2026, 7, 31)).end == period.start


def test_markdown_states_the_window_and_every_total() -> None:
    rendered = render_markdown(sample())

    assert "2026-07-31 00:00 UTC — 2026-08-07 00:00 UTC" in rendered
    assert "Всего открыто: **7**" in rendered
    assert "Всего в работе: **3**" in rendered
    assert "Всего: **1540**" in rendered


def test_measured_zero_is_printed_rather_than_omitted() -> None:
    """A missing severity would read as 'not measured' instead of 'none found'."""

    rendered = render_markdown(sample())

    assert "| Средний | 0 |" in rendered


def test_both_formats_carry_the_limitations_section() -> None:
    """A report a client reads must not look like a clean bill of health."""

    markdown = render_markdown(sample())
    html = render_html(sample())

    for limitation in LIMITATIONS:
        assert limitation in markdown
        assert limitation in html
    assert "journal_gap" in markdown
    assert "journal_gap" in html


def test_empty_period_says_so_instead_of_rendering_an_empty_table() -> None:
    rendered = render_markdown(sample(opened_by_rule=(), events_by_source=()))

    assert "не сработало ни одно правило" in rendered
    assert "не принято ни одного события" in rendered


def test_html_is_a_complete_printable_document() -> None:
    rendered = render_html(sample())

    assert rendered.startswith("<!doctype html>")
    assert '<html lang="ru">' in rendered
    assert "@page" in rendered, "print layout is the whole point of the HTML format"
    assert "ssh_bruteforce_by_ip" in rendered


def test_neither_format_contains_an_address_or_a_payload() -> None:
    """The report is the first artifact designed to leave the perimeter."""

    for rendered in (render_markdown(sample()), render_html(sample())):
        assert "192.0.2" not in rendered
        assert "source_ip" not in rendered
        assert "payload" not in rendered
        assert "correlation" not in rendered


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a|b", "a\\|b"),
        ("a\nb", "a b"),
        ("a\r\nb", "a  b"),
        ("a\\b", "a\\\\b"),
        ("plain", "plain"),
    ],
)
def test_a_value_cannot_escape_its_markdown_table_cell(raw: str, expected: str) -> None:
    assert escape_cell(raw) == expected


def test_html_escapes_a_value_that_would_otherwise_be_markup() -> None:
    """Nothing produces such a rule key today; the escaping is what keeps it safe."""

    rendered = render_html(sample(opened_by_rule=(("<script>alert(1)</script>", 1),)))

    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_markdown_escapes_a_rule_name_containing_a_table_separator() -> None:
    rendered = render_markdown(sample(opened_by_rule=(("evil|name", 1),)))

    assert "| evil\\|name | 1 |" in rendered


def test_a_period_that_ends_before_it_starts_is_rejected_before_any_query() -> None:
    """The guard runs first, so an unusable period never reaches PostgreSQL."""

    reversed_period = ReportPeriod(
        start=datetime(2026, 8, 7, tzinfo=UTC),
        end=datetime(2026, 7, 31, tzinfo=UTC),
    )

    def unusable_session() -> Session:
        raise AssertionError("the period guard must run before the session is touched")

    with pytest.raises(ReportPeriodError, match="must end after"):
        build_weekly_report(
            cast(Session, unusable_session),
            period=reversed_period,
            now=datetime(2026, 8, 7, tzinfo=UTC),
        )


def test_weekly_report_cli_reports_a_database_failure_without_a_stack_trace(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The operator is redirecting stdout; a traceback would land in the report."""

    marker = "synthetic-internal-table-name"

    def failing_factory() -> object:
        raise OperationalError(f"select from {marker}", {}, Exception(marker))

    monkeypatch.setattr(
        sys, "argv", ["woland-guard-admin", "weekly-report", "--week-ending", "2026-08-07"]
    )
    monkeypatch.setattr(cli, "get_session_factory", failing_factory)

    with pytest.raises(SystemExit) as raised:
        cli.main()

    captured = capsys.readouterr()
    assert raised.value.code == 1
    assert "Не удалось собрать отчёт" in captured.err
    assert marker not in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""
