from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)

DashboardTone = Literal["neutral", "good", "warning", "critical"]
DashboardAlertSeverity = Literal["low", "medium", "high", "critical"]
DashboardAlertStatus = Literal["open", "acknowledged", "resolved"]
DashboardActivityStatus = Literal["completed", "denied", "in-progress"]
DashboardStatus = Literal["ok"]


class DashboardKPI(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=1, max_length=120)
    tone: DashboardTone = "neutral"


class DashboardActivityItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=160)
    status: DashboardActivityStatus
    timestamp: str = Field(min_length=1)
    summary: str = Field(min_length=1, max_length=500)
    metadata: dict[str, str] = Field(default_factory=dict)


class DashboardAlertItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: DashboardAlertSeverity
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=500)
    status: DashboardAlertStatus


class DashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: DashboardStatus
    service: str = Field(min_length=1, max_length=120)
    timestamp: str = Field(min_length=1)
    environment: str = Field(min_length=1, max_length=120)
    kpis: list[DashboardKPI] = Field(default_factory=list)
    alerts: list[DashboardAlertItem] = Field(default_factory=list)
    activity: list[DashboardActivityItem] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/overview", response_model=DashboardResponse)
def get_dashboard_overview() -> DashboardResponse:
    return DashboardResponse(
        status="ok",
        service="ironclaw-dashboard",
        timestamp=_utc_now_iso(),
        environment="production-simulated",
        kpis=[
            DashboardKPI(label="Protected Requests", value="12,480", tone="good"),
            DashboardKPI(label="Blocked Actions", value="184", tone="warning"),
            DashboardKPI(label="Pending Reviews", value="7", tone="warning"),
            DashboardKPI(label="Runtime Health", value="Healthy", tone="good"),
        ],
        alerts=[
            DashboardAlertItem(
                severity="high",
                title="Prompt injection attempt blocked",
                summary="A high-risk shell-oriented prompt was denied by the runtime boundary.",
                status="open",
            ),
            DashboardAlertItem(
                severity="medium",
                title="Review queue requires attention",
                summary="Several execution decisions remain pending operator approval.",
                status="open",
            ),
        ],
        activity=[
            DashboardActivityItem(
                title="Execution request allowed",
                status="completed",
                timestamp="2026-04-26T19:55:00+00:00",
                summary="Low-risk http fetch request completed through guarded execution.",
                metadata={
                    "actiontype": "httpfetch",
                    "policyverdict": "allow",
                },
            ),
            DashboardActivityItem(
                title="High-risk tool call blocked",
                status="denied",
                timestamp="2026-04-26T19:58:00+00:00",
                summary="Shell-oriented tool call was blocked before execution.",
                metadata={
                    "actiontype": "toolcall",
                    "policyverdict": "block",
                },
            ),
            DashboardActivityItem(
                title="Incident triage updated",
                status="in-progress",
                timestamp="2026-04-26T20:01:00+00:00",
                summary="An operator reviewed a queued incident and kept it open for analysis.",
                metadata={
                    "queue": "incident-triage",
                    "reviewstatus": "pending-follow-up",
                },
            ),
        ],
        metadata={
            "surface": "dashboard",
            "scope": "overview",
            "generatedby": "dashboard-route",
        },
    )
