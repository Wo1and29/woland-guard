"""Top-level API router."""

from fastapi import APIRouter

from woland_guard_control_plane.api.routes.audit import router as audit_router
from woland_guard_control_plane.api.routes.events import router as events_router
from woland_guard_control_plane.api.routes.health import router as health_router
from woland_guard_control_plane.api.routes.incidents import router as incidents_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(events_router)
api_router.include_router(incidents_router)
api_router.include_router(audit_router)
