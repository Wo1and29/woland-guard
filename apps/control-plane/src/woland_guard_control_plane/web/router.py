"""Top-level internal Dashboard router without a repeated mount prefix."""

from fastapi import APIRouter

from woland_guard_control_plane.web.routes.audit import router as audit_router
from woland_guard_control_plane.web.routes.auth import router as auth_router
from woland_guard_control_plane.web.routes.incidents import router as incidents_router
from woland_guard_control_plane.web.routes.lang import router as lang_router
from woland_guard_control_plane.web.routes.notifications import router as notifications_router
from woland_guard_control_plane.web.routes.overview import router as overview_router
from woland_guard_control_plane.web.routes.rules import router as rules_router
from woland_guard_control_plane.web.routes.servers import router as servers_router

web_router = APIRouter()
web_router.include_router(auth_router)
web_router.include_router(lang_router)
web_router.include_router(overview_router)
web_router.include_router(servers_router)
web_router.include_router(incidents_router)
web_router.include_router(rules_router)
web_router.include_router(notifications_router)
web_router.include_router(audit_router)
