from __future__ import annotations

from fastapi import APIRouter

from app.api.uiruntimestatus import router as runtime_status_router

router = APIRouter()

router.include_router(runtime_status_router)