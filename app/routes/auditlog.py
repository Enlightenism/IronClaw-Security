from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

from app.ui.uiauditlog import build_audit_log_page

router = APIRouter(tags=["audit-log"])


@router.get("/ui/audit-log")
def get_audit_log(
    selected_event_id: Optional[str] = Query(
        default=None,
        description="Optional audit event identifier to focus in the UI response.",
    ),
    actor_id: Optional[str] = Query(
        default=None,
        description="Optional actor identifier filter for UI hydration.",
    ),
    request_id: Optional[str] = Query(
        default=None,
        description="Optional request identifier filter for UI hydration.",
    ),
    trace_id: Optional[str] = Query(
        default=None,
        description="Optional trace identifier filter for UI hydration.",
    ),
    verdict: Optional[str] = Query(
        default=None,
        description="Optional verdict filter for UI hydration.",
    ),
    event_type: Optional[str] = Query(
        default=None,
        description="Optional event type filter for UI hydration.",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
        description="Maximum number of audit events to include in the UI response.",
    ),
) -> Dict[str, Any]:
    filters: Dict[str, Any] = {
        "actor_id": actor_id,
        "request_id": request_id,
        "trace_id": trace_id,
        "verdict": verdict,
        "event_type": event_type,
        "limit": limit,
    }

    normalized_filters: Dict[str, Any] = {
        key: value
        for key, value in filters.items()
        if value is not None and value != ""
    }

    return build_audit_log_page(
        selected_event_id=selected_event_id,
        filters=normalized_filters,
    )