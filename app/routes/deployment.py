from __future__ import annotations

from fastapi import APIRouter

from app.services.deploymentreadiness import build_deployment_readiness_view

router = APIRouter(tags=["deployment"])


@router.get(
    "/deployment/readiness",
    summary="Get Deployment Readiness",
)
def get_deployment_readiness() -> dict:
    return build_deployment_readiness_view()
