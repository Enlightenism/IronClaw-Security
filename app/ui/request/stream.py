from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/request",
    tags=["request-stream"],
)


class RequestStreamItem(BaseModel):
    requestid: str
    timestamp: str
    clientid: str | None = None
    sessionid: str | None = None
    route: str
    method: str
    riskscore: int
    policyverdict: str
    executionstate: str
    responsestatus: str
    summary: str


class RequestStreamTotals(BaseModel):
    total: int
    allow: int
    review: int
    block: int


class RequestStreamResponse(BaseModel):
    generatedat: str
    items: list[RequestStreamItem] = Field(default_factory=list)
    totals: RequestStreamTotals


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _build_placeholder_items() -> list[RequestStreamItem]:
    return [
        RequestStreamItem(
            requestid="req-001",
            timestamp=_utc_iso(2026, 4, 18, 8, 0),
            clientid="client-alpha",
            sessionid="sess-alpha-001",
            route="/guard/execute",
            method="POST",
            riskscore=12,
            policyverdict="allow",
            executionstate="executed",
            responsestatus="completed",
            summary="Low-risk public fetch request completed successfully.",
        ),
        RequestStreamItem(
            requestid="req-002",
            timestamp=_utc_iso(2026, 4, 18, 8, 12),
            clientid="client-alpha",
            sessionid="sess-alpha-001",
            route="/guard/execute",
            method="POST",
            riskscore=58,
            policyverdict="review",
            executionstate="dryrun",
            responsestatus="queuedforreview",
            summary="Mid-risk request was routed to manual review.",
        ),
        RequestStreamItem(
            requestid="req-003",
            timestamp=_utc_iso(2026, 4, 18, 8, 20),
            clientid="client-beta",
            sessionid="sess-beta-004",
            route="/guard/execute",
            method="POST",
            riskscore=94,
            policyverdict="block",
            executionstate="denied",
            responsestatus="denied",
            summary="High-risk shell-style request was blocked at the boundary.",
        ),
    ]


@router.get("/stream", response_model=RequestStreamResponse)
def get_request_stream() -> RequestStreamResponse:
    items = _build_placeholder_items()

    return RequestStreamResponse(
        generatedat=datetime.now(UTC).isoformat(),
        items=items,
        totals=RequestStreamTotals(
            total=len(items),
            allow=sum(1 for item in items if item.policyverdict == "allow"),
            review=sum(1 for item in items if item.policyverdict == "review"),
            block=sum(1 for item in items if item.policyverdict == "block"),
        ),
    )