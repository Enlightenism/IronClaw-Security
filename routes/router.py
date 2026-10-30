from __future__ import annotations

from fastapi import APIRouter

from app.routes.customerkeys import router as customer_keys_router
from app.routes.integrations import router as integrations_router
from routes.incidents import router as incidents_router
from routes.reviewqueue import router as review_queue_router

router = APIRouter()

router.include_router(customer_keys_router)
router.include_router(incidents_router)
router.include_router(integrations_router)
router.include_router(review_queue_router)
