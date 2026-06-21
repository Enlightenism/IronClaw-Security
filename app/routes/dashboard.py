from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.install_keys import (
    InstallKeyNotFoundError,
    InstallKeyRegistry,
    InstallKeyUsageError,
    get_install_key_registry,
)

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


# ---------------------------------------------------------------------------
# Unit tracking schemas
# ---------------------------------------------------------------------------


class InstallKeyUnitEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str
    program: str
    masked_key: str
    label: str
    active: bool
    units_consumed: int
    last_used_at: str | None = None


class DashboardUnitsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_key: str
    total_keys: int
    total_units_consumed: int
    keys: list[InstallKeyUnitEntry]
    timestamp: str


class RecordKeyUsageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=120)
    units: int = Field(ge=1)


class RecordKeyUsageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str
    units_consumed: int
    last_used_at: str | None = None
    timestamp: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


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


@router.get("/units", response_model=DashboardUnitsResponse)
def get_units_for_owner(
    owner_key: str,
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> DashboardUnitsResponse:
    """
    Return unit consumption tracking for all install keys belonging to owner_key.
    """
    records = registry.get_keys_for_owner(owner_key)
    total_units = sum(r.units_consumed for r in records)
    entries = [
        InstallKeyUnitEntry(
            key_id=r.key_id,
            program=r.program,
            masked_key=r.masked_key,
            label=r.label,
            active=r.active,
            units_consumed=r.units_consumed,
            last_used_at=r.last_used_at.isoformat() if r.last_used_at else None,
        )
        for r in records
    ]
    return DashboardUnitsResponse(
        owner_key=owner_key,
        total_keys=len(records),
        total_units_consumed=total_units,
        keys=entries,
        timestamp=_utc_now_iso(),
    )


@router.post("/units/record", response_model=RecordKeyUsageResponse, status_code=status.HTTP_200_OK)
def record_unit_usage(
    body: RecordKeyUsageRequest,
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> RecordKeyUsageResponse:
    """
    Record unit consumption for a specific install key.
    """
    try:
        updated = registry.record_key_usage(body.key_id, body.units)
    except InstallKeyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InstallKeyUsageError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    return RecordKeyUsageResponse(
        key_id=updated.key_id,
        units_consumed=updated.units_consumed,
        last_used_at=updated.last_used_at.isoformat() if updated.last_used_at else None,
        timestamp=_utc_now_iso(),
    )
