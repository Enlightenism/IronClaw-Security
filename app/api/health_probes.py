from __future__ import annotations


from datetime import UTC, datetime


from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel


from app.dependencies.action_execute import get_action_execute_pipeline



router = APIRouter(prefix="/health", tags=["health-probes"])



class HealthProbeResponse(BaseModel):
    status: str
    service: str
    probe: str
    timestamp: str



def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")



@router.get("/live", response_model=HealthProbeResponse)
def liveness_probe() -> HealthProbeResponse:
    return HealthProbeResponse(
        status="ok",
        service="IronClaw-Security",
        probe="liveness",
        timestamp=_utc_now_iso(),
    )



@router.get("/ready", response_model=HealthProbeResponse)
def readiness_probe(request: Request) -> JSONResponse | HealthProbeResponse:
    pipeline = get_action_execute_pipeline()
    app_pipeline = getattr(request.app.state, "action_execute_pipeline", None)


    if pipeline is None or app_pipeline is None:
        body = HealthProbeResponse(
            status="not_ready",
            service="IronClaw-Security",
            probe="readiness",
            timestamp=_utc_now_iso(),
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=body.model_dump(),
        )


    return HealthProbeResponse(
        status="ok",
        service="IronClaw-Security",
        probe="readiness",
        timestamp=_utc_now_iso(),
    )