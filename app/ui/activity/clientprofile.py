from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/activity",
    tags=["client-profile"],
)


class ClientExecutionItem(BaseModel):
    executionid: str
    timestamp: str
    actiontype: str
    target: str
    riskscore: int
    executionstate: str
    responsestatus: str
    policyverdict: str
    reviewitemid: str | None = None


class ClientProfileResponse(BaseModel):
    clientid: str
    generatedat: str
    totalexecutions: int
    average_riskscore: float
    highest_riskscore: int
    pendingreviews: int
    verdictcounts: dict[str, int] = Field(default_factory=dict)
    sessions: list[str] = Field(default_factory=list)
    recentexecutions: list[ClientExecutionItem] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _sample_client_profiles() -> dict[str, ClientProfileResponse]:
    return {
        "client-alpha": ClientProfileResponse(
            clientid="client-alpha",
            generatedat=datetime.now(UTC).isoformat(),
            totalexecutions=3,
            average_riskscore=32.67,
            highest_riskscore=74,
            pendingreviews=1,
            verdictcounts={
                "allow": 2,
                "review": 1,
            },
            sessions=["sess-alpha-001", "sess-alpha-002"],
            recentexecutions=[
                ClientExecutionItem(
                    executionid="exec-106",
                    timestamp=_utc_iso(2026, 4, 18, 12, 45),
                    actiontype="httpfetch",
                    target="https://example.com/override",
                    riskscore=18,
                    executionstate="executed",
                    responsestatus="completed",
                    policyverdict="allow",
                    reviewitemid=None,
                ),
                ClientExecutionItem(
                    executionid="exec-102",
                    timestamp=_utc_iso(2026, 4, 18, 9, 10),
                    actiontype="toolcall",
                    target="shell",
                    riskscore=74,
                    executionstate="dryrun",
                    responsestatus="queuedforreview",
                    policyverdict="review",
                    reviewitemid="review-102",
                ),
                ClientExecutionItem(
                    executionid="exec-101",
                    timestamp=_utc_iso(2026, 4, 18, 8, 15),
                    actiontype="httpfetch",
                    target="https://example.com",
                    riskscore=6,
                    executionstate="executed",
                    responsestatus="completed",
                    policyverdict="allow",
                    reviewitemid=None,
                ),
            ],
        ),
        "client-beta": ClientProfileResponse(
            clientid="client-beta",
            generatedat=datetime.now(UTC).isoformat(),
            totalexecutions=2,
            average_riskscore=74.0,
            highest_riskscore=96,
            pendingreviews=2,
            verdictcounts={
                "review": 1,
                "block": 1,
            },
            sessions=["sess-beta-001", "sess-beta-002"],
            recentexecutions=[
                ClientExecutionItem(
                    executionid="exec-104",
                    timestamp=_utc_iso(2026, 4, 18, 11, 20),
                    actiontype="toolcall",
                    target="shell",
                    riskscore=96,
                    executionstate="denied",
                    responsestatus="denied",
                    policyverdict="block",
                    reviewitemid="review-104",
                ),
                ClientExecutionItem(
                    executionid="exec-103",
                    timestamp=_utc_iso(2026, 4, 18, 10, 5),
                    actiontype="httpfetch",
                    target="https://example.com/docs",
                    riskscore=52,
                    executionstate="dryrun",
                    responsestatus="queuedforreview",
                    policyverdict="review",
                    reviewitemid="review-103",
                ),
            ],
        ),
    }


@router.get("/client/{clientid}", response_model=ClientProfileResponse)
def get_client_profile(clientid: str) -> ClientProfileResponse:
    profiles = _sample_client_profiles()
    profile = profiles.get(clientid)
    if profile is None:
        raise HTTPException(status_code=404, detail="Client profile not found.")
    return profile
