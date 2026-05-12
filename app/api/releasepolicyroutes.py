from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/policy/release",
    tags=["release-policy"],
)


# ---------------------------------------------------------------------------
# Lazy service factory — defined at module scope so pytest can monkeypatch
# app.api.releasepolicyroutes.build_release_policy_service before any route
# is called. The actual import is deferred inside the factory so that a
# missing app.services.releasepolicy module never crashes collection.
# ---------------------------------------------------------------------------

def build_release_policy_service():  # noqa: ANN201
    from app.services.release_policy import build_release_policy_service as _factory
    return _factory()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class EvaluateReleasePolicyRequest(BaseModel):
    runtime: str = Field(..., min_length=1)
    environment: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    context: dict[str, Any] | None = Field(default_factory=dict)


class PutReleasePolicyRequest(BaseModel):
    runtime: str = Field(..., min_length=1)
    environment: str = Field(..., min_length=1)
    rollout_percent: int = Field(..., ge=0, le=100)
    enabled: bool
    mode: str = Field(..., min_length=1)
    bundle_id: str | None = None
    bundle_version: str | None = None


class CreateOverrideRequest(BaseModel):
    runtime: str = Field(..., min_length=1)
    environment: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    scope: str | None = None
    scope_id: str | None = None
    reason: str | None = None
    active: bool = True


class RollbackReleasePolicyRequest(BaseModel):
    runtime: str = Field(..., min_length=1)
    environment: str = Field(..., min_length=1)
    target_version: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/evaluate")
def evaluate_release_policy(payload: EvaluateReleasePolicyRequest) -> dict[str, Any]:
    service = build_release_policy_service()
    result = service.evaluate(
        runtime=payload.runtime,
        environment=payload.environment,
        action=payload.action,
        context=payload.context or {},
    )
    if hasattr(result, "as_dict"):
        return result.as_dict()
    return dict(result)


@router.put("")
def put_release_policy(payload: PutReleasePolicyRequest) -> dict[str, Any]:
    service = build_release_policy_service()
    return service.save_release_policy(
        runtime=payload.runtime,
        environment=payload.environment,
        rollout_percent=payload.rollout_percent,
        enabled=payload.enabled,
        mode=payload.mode,
        bundle_id=payload.bundle_id,
        bundle_version=payload.bundle_version,
    )


@router.post("/overrides")
def create_override(payload: CreateOverrideRequest) -> dict[str, Any]:
    service = build_release_policy_service()
    return service.save_override(
        runtime=payload.runtime,
        environment=payload.environment,
        action=payload.action,
        scope=payload.scope,
        scope_id=payload.scope_id,
        reason=payload.reason,
        active=payload.active,
    )


@router.get("/current")
def get_release_policy() -> dict[str, Any]:
    service = build_release_policy_service()
    return service.get_release_policy()


@router.get("/history")
def list_release_policy_history() -> list[dict[str, Any]]:
    service = build_release_policy_service()
    return service.list_release_policies()


@router.post("/rollback")
def rollback_release_policy(payload: RollbackReleasePolicyRequest) -> dict[str, Any]:
    service = build_release_policy_service()
    return service.rollback_policy(
        runtime=payload.runtime,
        environment=payload.environment,
        target_version=payload.target_version,
    )