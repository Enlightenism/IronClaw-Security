from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/activity",
    tags=["session-timeline"],
)


class SessionTimelineEvent(BaseModel):
    executionid: str
    timestamp: str
    actiontype: str
    target: str
    riskscore: int
    executionstate: str
    responsestatus: str
    policyverdict: str
    reviewitemid: Optional[str] = None
    reason: Optional[str] = None


class SessionTimelineResponse(BaseModel):
    sessionid: str
    clientid: Optional[str] = None
    generatedat: str
    totalexecutions: int
    pendingreviews: int
    events: list[SessionTimelineEvent] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=timezone.utc).isoformat()


def _sample_session_timelines() -> dict[str, SessionTimelineResponse]:
    return {
        "sess-alpha-001": SessionTimelineResponse(
            sessionid="sess-alpha-001",
            clientid="client-alpha",
            generatedat=datetime.now(timezone.utc).isoformat(),
            totalexecutions=2,
            pendingreviews=1,
            events=[
                SessionTimelineEvent(
                    executionid="exec-101",
                    timestamp=_utc_iso(2026, 4, 18, 8, 15),
                    actiontype="httpfetch",
                    target="https://example.com",
                    riskscore=6,
                    executionstate="executed",
                    responsestatus="completed",
                    policyverdict="allow",
                    reviewitemid=None,
                    reason="Low-risk fetch allowed through guarded execution.",
                ),
                SessionTimelineEvent(
                    executionid="exec-102",
                    timestamp=_utc_iso(2026, 4, 18, 9, 10),
                    actiontype="toolcall",
                    target="shell",
                    riskscore=74,
                    executionstate="dryrun",
                    responsestatus="queuedforreview",
                    policyverdict="review",
                    reviewitemid="review-102",
                    reason="Mid-risk shell-adjacent request queued for review.",
                ),
            ],
        ),
        "sess-beta-002": SessionTimelineResponse(
            sessionid="sess-beta-002",
            clientid="client-beta",
            generatedat=datetime.now(timezone.utc).isoformat(),
            totalexecutions=1,
            pendingreviews=1,
            events=[
                SessionTimelineEvent(
                    executionid="exec-104",
                    timestamp=_utc_iso(2026, 4, 18, 11, 20),
                    actiontype="toolcall",
                    target="shell",
                    riskscore=96,
                    executionstate="denied",
                    responsestatus="denied",
                    policyverdict="block",
                    reviewitemid="review-104",
                    reason="High-risk shell request denied by runtime boundary.",
                )
            ],
        ),
    }


@router.get("/session/{sessionid}", response_model=SessionTimelineResponse)
def get_session_timeline(sessionid: str) -> SessionTimelineResponse:
    timelines = _sample_session_timelines()
    timeline = timelines.get(sessionid)
    if timeline is None:
        raise HTTPException(status_code=404, detail="Session timeline not found.")
    return timeline