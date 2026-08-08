"""_safe_next must never resolve to an off-site redirect.

CodeQL (py/url-redirection) flagged the original startswith("/") and not
startswith("//") check: browsers normalize backslashes to forward slashes and
strip tabs/newlines before resolving a redirect, so "/\\evil.com" or
"/\tevil.com" both become "//evil.com" client-side and escape that check.
"""

import pytest
from starlette.requests import Request

from woland_guard_control_plane.web.routes.lang import _safe_next

SAFE = ["/incidents", "/", "/incidents?status=open&severity=high"]
UNSAFE = [
    None,
    "",
    "//evil.example",
    "///evil.example",
    "/\\evil.example",
    "/\tevil.example",
    "/\nevil.example",
    "/\r/evil.example",
    "http://evil.example",
    "/@evil.example",
]


def _request(root_path: str = "") -> Request:
    return Request(scope={"type": "http", "root_path": root_path})


@pytest.mark.parametrize("next_path", SAFE)
def test_safe_next_allows_same_origin_relative_paths(next_path: str) -> None:
    assert _safe_next(_request(), next_path) == next_path


@pytest.mark.parametrize("next_path", UNSAFE)
def test_safe_next_falls_back_for_every_known_bypass(next_path: str | None) -> None:
    assert _safe_next(_request(), next_path) == "/"


def test_safe_next_falls_back_under_root_path() -> None:
    assert _safe_next(_request(root_path="/woland-guard"), None) == "/woland-guard/"
