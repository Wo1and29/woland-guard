"""Markdown and print-ready HTML for one weekly report (ADR-0023).

Deliberately free of SQLAlchemy: the formats are testable without PostgreSQL,
and nothing here can widen what the report contains beyond what the query layer
already decided to collect.
"""

from __future__ import annotations

from jinja2 import Environment, StrictUndefined, select_autoescape

from woland_guard_control_plane.application.weekly_report import WeeklyReport

_SEVERITY_TITLES = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
}
_STATUS_TITLES = {
    "investigating": "В работе",
    "resolved": "Закрыт",
    "false_positive": "Ложное срабатывание",
}
_SOURCE_TITLES = {
    "journald": "journald",
    "syslog_file": "файл syslog",
    "nginx_access": "access log Nginx",
    "file_integrity": "целостность файлов",
}

# Printed inside every report. The point is that a report a client reads must not
# look like a statement that nothing is wrong (ADR-0023 §8).
LIMITATIONS = (
    "Счётчики отражают только то, что агент успел доставить: разрыв в журнале "
    "(диагностика journal_gap на стороне агента) в этот отчёт не попадает.",
    "Отсутствие инцидентов не означает отсутствия атак — оно означает, что "
    "ни одно из настроенных правил не сработало.",
    "Инциденты отнесены к периоду по моменту открытия, события — по моменту на хосте. "
    "Событие, доставленное с задержкой, попадёт в отчёт своей недели, а порождённый им "
    "инцидент — в отчёт недели доставки.",
    "Открытые инциденты посчитаны на момент формирования отчёта, а не на конец периода: "
    "система хранит текущий статус, а не историю состояний на произвольную дату.",
    "Доступность серверов не проверяется и не выводится: отчёт показывает только "
    "зафиксированные факты.",
)


def render_markdown(report: WeeklyReport) -> str:
    """Render the report as Markdown, escaping every value as a table cell."""

    lines = [
        "# Еженедельный отчёт Woland Guard",
        "",
        f"- Период: **{_stamp(report.period.start)} — {_stamp(report.period.end)}** "
        f"({report.period.days} суток, UTC, конец периода не включён)",
        f"- Отчёт сформирован: {_stamp(report.generated_at)}",
        "",
        "## Наблюдаемые серверы",
        "",
        f"Всего: **{report.servers_total}**, из них активных: {report.servers_active}, "
        f"неактивных: {report.servers_inactive}.",
        "",
        "## Инциденты, открытые за период",
        "",
        f"Всего открыто: **{report.opened_total}**.",
        "",
        *_markdown_table(
            ("Серьёзность", "Открыто"),
            [
                (_SEVERITY_TITLES.get(name, name), count)
                for name, count in report.opened_by_severity
            ],
        ),
        "",
        "### По правилам",
        "",
        *(
            _markdown_table(("Правило", "Инцидентов"), list(report.opened_by_rule))
            if report.opened_by_rule
            else ["За период не сработало ни одно правило."]
        ),
        "",
        "## Изменения статусов за период",
        "",
        *_markdown_table(
            ("Новый статус", "Переходов"),
            [
                (_STATUS_TITLES.get(name, name), count)
                for name, count in report.transitions_to_status
            ],
        ),
        "",
        "## Открытые инциденты на момент формирования",
        "",
        f"Всего в работе: **{report.open_now_total}**.",
        "",
        *_markdown_table(
            ("Серьёзность", "В работе"),
            [
                (_SEVERITY_TITLES.get(name, name), count)
                for name, count in report.open_now_by_severity
            ],
        ),
        "",
        "## Принятые события за период",
        "",
        f"Всего: **{report.events_total}**.",
        "",
        *(
            _markdown_table(
                ("Источник", "События"),
                [
                    (_SOURCE_TITLES.get(name, name), count)
                    for name, count in report.events_by_source
                ],
            )
            if report.events_by_source
            else ["За период не принято ни одного события."]
        ),
        "",
        "## Как читать этот отчёт",
        "",
        *(f"- {item}" for item in LIMITATIONS),
        "",
    ]
    return "\n".join(lines)


def render_html(report: WeeklyReport) -> str:
    """Render the same data as HTML laid out for printing to PDF from a browser."""

    environment = Environment(
        autoescape=select_autoescape(default_for_string=True, default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = environment.from_string(_HTML_TEMPLATE)
    return template.render(
        report=report,
        period_start=_stamp(report.period.start),
        period_end=_stamp(report.period.end),
        generated_at=_stamp(report.generated_at),
        opened_by_severity=_titled(report.opened_by_severity, _SEVERITY_TITLES),
        open_now_by_severity=_titled(report.open_now_by_severity, _SEVERITY_TITLES),
        transitions=_titled(report.transitions_to_status, _STATUS_TITLES),
        events_by_source=_titled(report.events_by_source, _SOURCE_TITLES),
        limitations=LIMITATIONS,
    )


def _titled(
    rows: tuple[tuple[str, int], ...],
    titles: dict[str, str],
) -> tuple[tuple[str, int], ...]:
    return tuple((titles.get(name, name), count) for name, count in rows)


def _stamp(value: object) -> str:
    """Format a timestamp without a locale, so two reports are comparable."""

    return f"{value:%Y-%m-%d %H:%M} UTC"


def _markdown_table(header: tuple[str, str], rows: list[tuple[str, int]]) -> list[str]:
    return [
        f"| {escape_cell(header[0])} | {escape_cell(header[1])} |",
        "|---|---:|",
        *(f"| {escape_cell(name)} | {count} |" for name, count in rows),
    ]


def escape_cell(value: str) -> str:
    """Keep a value inside its Markdown table cell.

    Today every value is an integer or a member of a closed set, so there is
    nothing to escape. This exists so that stays true when a server name or a
    rule title is added to the report later (ADR-0023 §4).
    """

    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


_HTML_TEMPLATE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Еженедельный отчёт Woland Guard — {{ period_start }}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  body { font: 11pt/1.5 "DejaVu Sans", Arial, sans-serif; color: #111; max-width: 720px; }
  h1 { font-size: 18pt; margin: 0 0 4pt; }
  h2 { font-size: 13pt; margin: 18pt 0 6pt; border-bottom: 1px solid #ccc; padding-bottom: 3pt; }
  h3 { font-size: 11pt; margin: 12pt 0 4pt; }
  table { border-collapse: collapse; width: 100%; margin: 6pt 0; }
  th, td { border: 1px solid #ccc; padding: 4pt 8pt; text-align: left; }
  td.count, th.count { text-align: right; width: 7em; }
  .meta { color: #555; font-size: 10pt; margin: 0 0 12pt; }
  .total { font-weight: 600; }
  .limits { font-size: 9.5pt; color: #333; }
  tr, table, h2 { page-break-inside: avoid; }
</style>
</head>
<body>
<h1>Еженедельный отчёт Woland Guard</h1>
<p class="meta">
  Период: <strong>{{ period_start }} — {{ period_end }}</strong>
  ({{ report.period.days }} суток, UTC, конец периода не включён)<br>
  Отчёт сформирован: {{ generated_at }}
</p>

<h2>Наблюдаемые серверы</h2>
<p>
  Всего: <span class="total">{{ report.servers_total }}</span>,
  активных: {{ report.servers_active }}, неактивных: {{ report.servers_inactive }}.
</p>

<h2>Инциденты, открытые за период</h2>
<p>Всего открыто: <span class="total">{{ report.opened_total }}</span>.</p>
<table>
  <tr><th>Серьёзность</th><th class="count">Открыто</th></tr>
  {% for name, count in opened_by_severity %}
  <tr><td>{{ name }}</td><td class="count">{{ count }}</td></tr>
  {% endfor %}
</table>

<h3>По правилам</h3>
{% if report.opened_by_rule %}
<table>
  <tr><th>Правило</th><th class="count">Инцидентов</th></tr>
  {% for name, count in report.opened_by_rule %}
  <tr><td>{{ name }}</td><td class="count">{{ count }}</td></tr>
  {% endfor %}
</table>
{% else %}
<p>За период не сработало ни одно правило.</p>
{% endif %}

<h2>Изменения статусов за период</h2>
<table>
  <tr><th>Новый статус</th><th class="count">Переходов</th></tr>
  {% for name, count in transitions %}
  <tr><td>{{ name }}</td><td class="count">{{ count }}</td></tr>
  {% endfor %}
</table>

<h2>Открытые инциденты на момент формирования</h2>
<p>Всего в работе: <span class="total">{{ report.open_now_total }}</span>.</p>
<table>
  <tr><th>Серьёзность</th><th class="count">В работе</th></tr>
  {% for name, count in open_now_by_severity %}
  <tr><td>{{ name }}</td><td class="count">{{ count }}</td></tr>
  {% endfor %}
</table>

<h2>Принятые события за период</h2>
<p>Всего: <span class="total">{{ report.events_total }}</span>.</p>
{% if events_by_source %}
<table>
  <tr><th>Источник</th><th class="count">События</th></tr>
  {% for name, count in events_by_source %}
  <tr><td>{{ name }}</td><td class="count">{{ count }}</td></tr>
  {% endfor %}
</table>
{% else %}
<p>За период не принято ни одного события.</p>
{% endif %}

<h2>Как читать этот отчёт</h2>
<ul class="limits">
  {% for item in limitations %}
  <li>{{ item }}</li>
  {% endfor %}
</ul>
</body>
</html>
"""
