"""Top-level API router."""

from fastapi import APIRouter

from woland_guard_control_plane.api.routes.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router)
