"""Unauthenticated UI-language toggle with no side effects beyond one cookie."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.responses import RedirectResponse
from starlette.responses import Response

from woland_guard_control_plane.web.i18n import Language
from woland_guard_control_plane.web.security import LANG_COOKIE_NAME, set_secure_cookie

router = APIRouter()


@router.get("/lang/{lang}", name="dashboard_set_language", response_model=None)
def set_language(
    request: Request,
    lang: Language,
    next_path: Annotated[str | None, Query(alias="next")] = None,
) -> Response:
    response = RedirectResponse(_safe_next(request, next_path), status_code=303)
    set_secure_cookie(response, name=LANG_COOKIE_NAME, value=lang, max_age=31_536_000)
    return response


def _safe_next(request: Request, next_path: str | None) -> str:
    """Only ever redirect to a same-origin relative path, never off-site."""

    root = request.scope.get("root_path", "").rstrip("/")
    if next_path and next_path.startswith("/") and not next_path.startswith("//"):
        return next_path
    return f"{root}/"
