from fastapi import APIRouter, Query

from app.schemas.telemetry import TelemetryEvent, TelemetryResponse
from app.services.telemetry import read_telemetry_events

router = APIRouter(tags=["telemetry"])


@router.get(
    "/",
    response_model=TelemetryResponse,
    summary="Get telemetry events",
    description="Return recent telemetry events for operational visibility, newest-first.",
)
def get_telemetry(
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
        description="Maximum number of telemetry events to return.",
    ),
) -> TelemetryResponse:
    events_raw = read_telemetry_events(limit=limit)
    items = [TelemetryEvent(**event) for event in events_raw]
    return TelemetryResponse(count=len(items), items=items)