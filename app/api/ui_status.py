from __future__ import annotations


from datetime import UTC, datetime
from typing import Any


from fastapi import APIRouter
from pydantic import BaseModel, Field


from app.services.review_queue_service import get_review_queue_summary
from app.services.telemetry import (
    append_telemetry_event,
    read_telemetry_events,
    summarize_telemetry_events,
)


router = APIRouter(prefix="/ui-status", tags=["ui-status"])



class UIStatusCounts(BaseModel):
    pending_reviews: int = 0
    critical_reviews: int = 0
    total_reviews: int = 0
    recent_telemetry_events: int = 0



class UIStatusFlags(BaseModel):
    has_pending_reviews: bool
    has_critical_reviews: bool
    telemetry_available: bool
    system_degraded: bool



class UIStatusResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    counts: UIStatusCounts
    flags: UIStatusFlags
    review_summary: dict[str, Any] = Field(default_factory=dict)
    telemetry_summary: dict[str, Any] = Field(default_factory=dict)
    recent_events: list[dict[str, Any]] = Field(default_factory=list)



def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")



def _safe_append_telemetry_event(event_name: str, payload: dict[str, Any]) -> None:
    try:
        append_telemetry_event(event_name, payload)
    except Exception:
        pass



@router.get("", response_model=UIStatusResponse)
def read_ui_status() -> UIStatusResponse:
    review_summary: dict[str, Any]
    telemetry_summary: dict[str, Any]
    recent_events: list[dict[str, Any]]


    review_error = False
    telemetry_error = False


    try:
        review_summary = get_review_queue_summary()
    except Exception as exc:
        review_error = True
        review_summary = {
            "status": "degraded",
            "error": str(exc),
            "pending_items": 0,
            "critical_items": 0,
            "total_items": 0,
        }


    try:
        telemetry_summary = summarize_telemetry_events(limit=250)
    except Exception as exc:
        telemetry_error = True
        telemetry_summary = {
            "status": "degraded",
            "error": str(exc),
        }


    try:
        recent_events = read_telemetry_events(limit=20)
    except Exception as exc:
        telemetry_error = True
        recent_events = [
            {
                "type": "telemetry_read_error",
                "error": str(exc),
            }
        ]


    pending_reviews = int(review_summary.get("pending_items") or 0)
    critical_reviews = int(review_summary.get("critical_items") or 0)
    total_reviews = int(review_summary.get("total_items") or 0)
    recent_telemetry_events = len(recent_events)


    system_degraded = review_error or telemetry_error
    telemetry_available = not telemetry_error


    result = UIStatusResponse(
        status="degraded" if system_degraded else "ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        counts=UIStatusCounts(
            pending_reviews=pending_reviews,
            critical_reviews=critical_reviews,
            total_reviews=total_reviews,
            recent_telemetry_events=recent_telemetry_events,
        ),
        flags=UIStatusFlags(
            has_pending_reviews=pending_reviews > 0,
            has_critical_reviews=critical_reviews > 0,
            telemetry_available=telemetry_available,
            system_degraded=system_degraded,
        ),
        review_summary=review_summary,
        telemetry_summary=telemetry_summary,
        recent_events=recent_events,
    )


    _safe_append_telemetry_event(
        "ui_status_requested",
        {
            "status": result.status,
            "pending_reviews": pending_reviews,
            "critical_reviews": critical_reviews,
            "total_reviews": total_reviews,
            "recent_telemetry_events": recent_telemetry_events,
            "telemetry_available": telemetry_available,
            "system_degraded": system_degraded,
        },
    )


    return result



# Consumed by app.main via _optional_attr("app.api.ui_status", "get_ui_status")
def get_ui_status() -> dict[str, Any]:
    return read_ui_status().model_dump()