from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.ui.telemetryaccesssummary import get_telemetry_access_summary

router = APIRouter(
    prefix="/telemetry/access",
    tags=["ui-telemetry-access"],
)


class TelemetryAccessService:
    def summary(
        self,
        *,
        actor_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        organization_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        data = get_telemetry_access_summary()
        return {
            "title": data.get("title", "Telemetry Access Summary"),
            "status": "ok",
            "summary": data.get("counts", {}),
            "items": data.get("recentevents", []),
        }

    def events(
        self,
        *,
        actor_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        organization_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        data = get_telemetry_access_summary()
        items = data.get("recentevents", [])
        return {
            "items": items,
            "count": len(items),
            "status": "ok",
        }


def get_telemetry_access_service() -> TelemetryAccessService:
    return TelemetryAccessService()


@router.get(
    "",
    summary="Get Telemetry Access Summary",
)
def get_telemetry_access_summary_route(
    actor_id: str | None = Query(None),
    session_id: str | None = Query(None),
    request_id: str | None = Query(None),
    organization_id: str | None = Query(None),
    limit: int | None = Query(None, ge=1, le=5000),
    service: TelemetryAccessService = Depends(get_telemetry_access_service),
) -> dict[str, Any]:
    return service.summary(
        actor_id=actor_id,
        session_id=session_id,
        request_id=request_id,
        organization_id=organization_id,
        limit=limit,
    )


@router.get(
    "/events",
    summary="Get Telemetry Access Events",
)
def get_telemetry_access_events_route(
    actor_id: str | None = Query(None),
    session_id: str | None = Query(None),
    request_id: str | None = Query(None),
    organization_id: str | None = Query(None),
    limit: int | None = Query(None, ge=1, le=500),
    service: TelemetryAccessService = Depends(get_telemetry_access_service),
) -> dict[str, Any]:
    return service.events(
        actor_id=actor_id,
        session_id=session_id,
        request_id=request_id,
        organization_id=organization_id,
        limit=limit,
    )