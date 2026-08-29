from __future__ import annotations

from fastapi import APIRouter

from app.routes.integrations.agent_skills import router as agent_skills_router
from app.routes.integrations.claude_code import router as claude_code_router
from app.routes.integrations.compatibility import router as compatibility_router
from app.routes.integrations.copilot import router as copilot_router
from app.routes.integrations.cursor import router as cursor_router
from app.routes.integrations.gemini_cli import router as gemini_cli_router
from app.routes.integrations.goose import router as goose_router
from app.routes.integrations.health import router as health_router
from app.routes.integrations.installer import router as installer_router
from app.routes.integrations.lifecycle import router as lifecycle_router
from app.routes.integrations.observability import router as observability_router
from app.routes.integrations.openclaw import router as openclaw_router
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
router.include_router(claude_code_router)
router.include_router(openclaw_router)
router.include_router(cursor_router)
router.include_router(goose_router)
router.include_router(gemini_cli_router)
router.include_router(copilot_router)
router.include_router(agent_skills_router)
