"""Top-level internal Dashboard router without a repeated mount prefix."""

from fastapi import APIRouter

from woland_guard_control_plane.web.routes.auth import router as auth_router

web_router = APIRouter()
web_router.include_router(auth_router)
