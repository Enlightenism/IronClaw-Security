from __future__ import annotations

from fastapi import APIRouter, Query

from app.schemas.telemetry import TelemetryAccessSummaryResponse
from app.ui.telemetryaccesssummary import get_telemetry_access_summary

router = APIRouter(
    prefix="/ui/telemetry-access",
    tags=["ui-telemetry-access"],
)


def get_telemetry_access_service() -> dict:
    return get_telemetry_access_summary()


@router.get(
    "/summary",
    response_model=TelemetryAccessSummaryResponse,
    summary="Get Telemetry Access Summary",
)
def get_telemetry_access_summary_route(
    summary_limit: int = Query(500, ge=1, le=5000),
    events_limit: int = Query(50, ge=1, le=500),
) -> TelemetryAccessSummaryResponse:
    data = get_telemetry_access_summary()
    return TelemetryAccessSummaryResponse(**data)