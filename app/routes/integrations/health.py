from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel

from app.orchestrator.policy_enforcer import build_policy_engine
from app.services.integration_registry import initialize_integration_registry

router = APIRouter(
    prefix="/integrations/health",
    tags=["integrations"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class IntegrationHealthResponse(BaseModel):
    status: str
    checked_at: str
    registry_count: int
    policy_mode: str
    integrations: list[dict[str, Any]]


@router.get(
    "",
    response_model=IntegrationHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Return health status for all registered integrations",
    description=("Checks the integration registry and policy engine, returning a health summary for every registered integration alongside the active policy mode."),
)
async def integrations_health() -> IntegrationHealthResponse:
    registry = initialize_integration_registry()
    engine = build_policy_engine()

    records = registry.list_integrations() if hasattr(registry, "list_integrations") else []

    integrations: list[dict[str, Any]] = []
    for record in records:
        integrations.append(
            {
                "integration_id": getattr(record, "integration_id", None),
                "name": getattr(record, "name", None),
                "platform": getattr(record, "platform", None),
                "status": getattr(record, "status", "unknown"),
                "health": getattr(record, "health", "unknown"),
            }
        )

    return IntegrationHealthResponse(
        status="ok",
        checked_at=_utc_now(),
        registry_count=len(integrations),
        policy_mode=engine.mode,
        integrations=integrations,
    )
