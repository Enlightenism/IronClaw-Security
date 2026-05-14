from __future__ import annotations

import copy
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
    checks: list[dict[str, Any]] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_append_telemetry_event(event_name: str, payload: dict[str, Any]) -> None:
    try:
        append_telemetry_event(event_name, payload)
    except Exception:
        pass


def _build_ui_status_payload() -> UIStatusResponse:
    review_error = False
    telemetry_error = False

    try:
        review_summary: dict[str, Any] = get_review_queue_summary()
    except Exception as exc:
        review_error = True
        review_summary = {
            "status": "degraded",
            "error": str(exc),
            "pending_items": 0,
            "critical_items": 0,
            "total_items": 0,
        }

    # Snapshot recent_events and telemetry_summary BEFORE any append
    try:
        recent_events: list[dict[str, Any]] = read_telemetry_events(limit=20)
    except Exception as exc:
        telemetry_error = True
        recent_events = [{"type": "telemetry_read_error", "error": str(exc)}]

    try:
        raw_summary = summarize_telemetry_events(limit=250)
        # Deep-copy to prevent the live store mutation from changing this dict
        telemetry_summary: dict[str, Any] = copy.deepcopy(raw_summary)
    except Exception as exc:
        telemetry_error = True
        telemetry_summary = {"status": "degraded", "error": str(exc)}

    pending_reviews = int(review_summary.get("pending_items") or 0)
    critical_reviews = int(review_summary.get("critical_items") or 0)
    total_reviews = int(review_summary.get("total_items") or 0)
    recent_telemetry_events = len(recent_events)

    system_degraded = review_error or telemetry_error
    telemetry_available = not telemetry_error

    checks = [
        {"name": "review_queue", "status": "degraded" if review_error else "ok"},
        {"name": "telemetry_store", "status": "degraded" if telemetry_error else "ok"},
    ]

    metrics = {
        "pending_reviews": pending_reviews,
        "critical_reviews": critical_reviews,
        "total_reviews": total_reviews,
        "recent_telemetry_events": recent_telemetry_events,
        "telemetry_available": telemetry_available,
    }

    return UIStatusResponse(
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
        checks=checks,
        metrics=metrics,
    )


@router.get("", response_model=UIStatusResponse)
def read_ui_status() -> UIStatusResponse:
    result = _build_ui_status_payload()

    # Append AFTER full payload is built and snapshotted
    _safe_append_telemetry_event(
        "ui_status_requested",
        {
            "status": result.status,
            "pending_reviews": result.counts.pending_reviews,
            "critical_reviews": result.counts.critical_reviews,
            "total_reviews": result.counts.total_reviews,
            "recent_telemetry_events": result.counts.recent_telemetry_events,
            "telemetry_available": result.flags.telemetry_available,
            "system_degraded": result.flags.system_degraded,
        },
    )

    return result


# Consumed by app.main via _optional_attr("app.api.ui_status", "get_ui_status")
def get_ui_status() -> dict[str, Any]:
    return _build_ui_status_payload().model_dump()
