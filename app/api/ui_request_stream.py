from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/ui",
    tags=["request-stream"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RequestStreamItemView(BaseModel):
    request_id: str
    timestamp: str
    client_id: str | None = None
    session_id: str | None = None
    route: str
    method: str
    status: str
    risk_level: str
    action_type: str | None = None
    verdict: str | None = None
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequestStreamResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    requested_by: str
    total: int
    items: list[RequestStreamItemView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_request_items() -> list[RequestStreamItemView]:
    return [
        RequestStreamItemView(
            request_id="req-7001",
            timestamp="2026-04-21T16:32:00Z",
            client_id="client-alpha",
            session_id="sess-alpha-001",
            route="/guard/execute",
            method="POST",
            status="blocked",
            risk_level="critical",
            action_type="shell_execute",
            verdict="block",
            summary="Blocked high-risk shell execution request before runtime dispatch.",
            metadata={"trace_id": "trace-7001"},
        ),
        RequestStreamItemView(
            request_id="req-7002",
            timestamp="2026-04-21T16:34:00Z",
            client_id="client-beta",
            session_id="sess-beta-008",
            route="/guard/review",
            method="POST",
            status="review_required",
            risk_level="high",
            action_type="web_fetch",
            verdict="quarantine",
            summary="Suspicious fetched content routed into manual review.",
            metadata={"trace_id": "trace-7002"},
        ),
        RequestStreamItemView(
            request_id="req-7003",
            timestamp="2026-04-21T16:36:00Z",
            client_id="client-gamma",
            session_id="sess-gamma-014",
            route="/guard/execute",
            method="POST",
            status="completed",
            risk_level="low",
            action_type="file_read",
            verdict="allow",
            summary="Low-risk file read completed successfully inside guarded runtime.",
            metadata={"trace_id": "trace-7003"},
        ),
    ]


@router.get("/request-stream", response_model=RequestStreamResponse)
def get_ui_request_stream(
    requested_by: str = Query("ui-request-stream", min_length=1),
    limit: int = Query(50, ge=1, le=500),
) -> RequestStreamResponse:
    items = _build_request_items()[:limit]
    return RequestStreamResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=requested_by,
        total=len(items),
        items=items,
        metadata={
            "requested_by": requested_by,
            "limit": limit,
        },
    )
