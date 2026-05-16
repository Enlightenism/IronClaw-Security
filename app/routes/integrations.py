from __future__ import annotations

from fastapi import APIRouter

from app.routes.integrations.compatibility import router as compatibility_router
from app.routes.integrations.health import router as health_router
from app.routes.integrations.installer import router as installer_router
from app.routes.integrations.lifecycle import router as lifecycle_router
from app.routes.integrations.observability import router as observability_router
from app.routes.integrations.readiness import router as readiness_router
from app.routes.integrations.rollouts import router as rollouts_router
from app.routes.integrations.secrets import router as secrets_router
from app.routes.integrations.telemetry import router as telemetry_router
from app.routes.integrations.verifier import router as verifier_router

router = APIRouter(tags=["integrations"])

router.include_router(installer_router)
router.include_router(verifier_router)
router.include_router(compatibility_router)
router.include_router(secrets_router)
router.include_router(rollouts_router)
router.include_router(telemetry_router)
router.include_router(health_router)
router.include_router(lifecycle_router)
router.include_router(readiness_router)
router.include_router(observability_router)
