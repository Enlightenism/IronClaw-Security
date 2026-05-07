from __future__ import annotations

from fastapi import APIRouter, Query

from app.ui.telemetryaccesssummary import get_telemetry_access_summary
from app.schemas.telemetry import TelemetryAccessSummaryResponse

router = APIRouter(
    prefix="/ui/telemetry-access",
    tags=["ui-telemetry-access"],
)


@router.get(
    "/summary",
    response_model=TelemetryAccessSummaryResponse,
    summary="Get Telemetry Access Summary",
)
def get_telemetry_access_summary_route(
    summary_limit: int = Query(500, ge=1, le=5000),
    events_limit: int = Query(50, ge=1, le=500),
) -> TelemetryAccessSummaryResponse:
    return get_telemetry_access_summary(
        summary_limit=summary_limit,
        events_limit=events_limit,
    )