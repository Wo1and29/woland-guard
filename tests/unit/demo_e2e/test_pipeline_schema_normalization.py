from __future__ import annotations

import pytest
from scripts.demo_e2e.pipeline import _normalize_pg_expression_text


@pytest.mark.parametrize(
    ("live_catalog_text", "restored_catalog_text"),
    [
        (
            "CHECK (((role)::text = ANY ((ARRAY['viewer'::character varying, "
            "'analyst'::character varying, 'admin'::character varying])::text[])))",
            "CHECK (((role)::text = ANY (ARRAY[('viewer'::character varying)::text, "
            "('analyst'::character varying)::text, ('admin'::character varying)::text])))",
        ),
        (
            "status::text = ANY (ARRAY['new'::character varying, "
            "'investigating'::character varying]::text[])",
            "status::text = ANY (ARRAY[('new'::character varying)::text, "
            "('investigating'::character varying)::text])",
        ),
    ],
)
def test_normalize_collapses_dump_restore_cast_placement(
    live_catalog_text: str, restored_catalog_text: str
) -> None:
    assert _normalize_pg_expression_text(live_catalog_text) == _normalize_pg_expression_text(
        restored_catalog_text
    )


@pytest.mark.parametrize(
    ("original", "mutated"),
    [
        ("CHECK ((value > 0))", "CHECK ((value >= 0))"),
        ("status::text = 'pending'::text", "status::text = 'processing'::text"),
    ],
)
def test_normalize_still_detects_a_genuinely_different_expression(
    original: str, mutated: str
) -> None:
    assert _normalize_pg_expression_text(original) != _normalize_pg_expression_text(mutated)
