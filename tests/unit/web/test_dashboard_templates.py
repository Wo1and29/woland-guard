"""Static security and responsive acceptance for Dashboard 7B assets."""

from pathlib import Path

WEB_ROOT = (
    Path(__file__).parents[3]
    / "apps"
    / "control-plane"
    / "src"
    / "woland_guard_control_plane"
    / "web"
)
TEMPLATES = WEB_ROOT / "templates"
CSS = WEB_ROOT / "static" / "dashboard.css"


def test_templates_have_no_unsafe_rendering_or_external_resources() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(TEMPLATES.rglob("*.html"))
    ).casefold()
    for forbidden in (
        "|safe",
        "<script",
        " style=",
        "http://",
        "https://",
        "//cdn",
        # A data: URI is same-origin to a human but not to "img-src 'self'", and its
        # percent-encoded body hides a plain "http://" from the checks above.
        "data:",
    ):
        assert forbidden not in combined


def test_data_pages_use_shared_layout() -> None:
    for relative_path in (
        "dashboard/overview.html",
        "servers/list.html",
        "servers/detail.html",
        "incidents/list.html",
        "incidents/detail.html",
        "rules/list.html",
        "audit/list.html",
    ):
        content = (TEMPLATES / relative_path).read_text(encoding="utf-8")
        assert '{% extends "base_dashboard.html" %}' in content


def test_incident_mutation_forms_are_plain_html_and_csrf_protected() -> None:
    content = (TEMPLATES / "incidents" / "detail.html").read_text(encoding="utf-8")
    assert 'action="{{ paths.incidents }}/{{ incident.summary.id }}/transitions"' in content
    assert 'action="{{ paths.incidents }}/{{ incident.summary.id }}/comments"' in content
    assert content.count('name="_csrf"') == 2
    assert content.count('name="idempotency_key"') == 2
    assert content.count('accept-charset="UTF-8"') == 2
    assert "|safe" not in content


def test_evidence_template_contains_only_the_projection_allowlist() -> None:
    content = (TEMPLATES / "incidents" / "detail.html").read_text(encoding="utf-8")
    for field in (
        "event_id",
        "event_type",
        "source",
        "occurred_at",
        "collected_at",
        "linked_at",
    ):
        assert f"item.{field}" in content
    for forbidden in ("payload", "attributes", "correlation", "actor", "source_ip"):
        assert forbidden not in content.casefold()


def test_css_is_local_csp_compatible_and_has_responsive_rules() -> None:
    css = CSS.read_text(encoding="utf-8").casefold()
    for forbidden in ("@import", "url(", "sourcemappingurl", "javascript:"):
        assert forbidden not in css
    assert "@media (max-width: 48rem)" in css
    assert "overflow-x: auto" in css
