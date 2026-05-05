from __future__ import annotations

from fastapi import APIRouter

from app.api.routes.incidents import router as incidents_api_router


router = APIRouter()
router.include_router(incidents_api_router)