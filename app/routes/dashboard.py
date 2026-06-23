from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.billing import BillingRegistry, get_billing_registry
from app.core.install_keys import (
    InstallKeyNotFoundError,
    InstallKeyRegistry,
    InstallKeyUsageError,
    get_install_key_registry,
)
from app.core.unit_wallet import UnitWalletRegistry, get_unit_wallet_registry

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)

DashboardTone = Literal["neutral", "good", "warning", "critical"]
DashboardAlertSeverity = Literal["low", "medium", "high", "critical"]
DashboardAlertStatus = Literal["open", "acknowledged", "resolved"]
DashboardActivityStatus = Literal["completed", "denied", "in-progress"]
DashboardStatus = Literal["ok"]
InstallKeySlotStatus = Literal["locked", "active", "revoked"]


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


class InstallKeyDashboardSlot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program: str
    masked_key: str | None = None
    status: InstallKeySlotStatus
    units_consumed: int
    last_used_at: str | None = None


class DashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: DashboardStatus
    service: str = Field(min_length=1, max_length=120)
    timestamp: str = Field(min_length=1)
    environment: str = Field(min_length=1, max_length=120)
    kpis: list[DashboardKPI] = Field(default_factory=list)
    alerts: list[DashboardAlertItem] = Field(default_factory=list)
    activity: list[DashboardActivityItem] = Field(default_factory=list)
    install_keys: list[InstallKeyDashboardSlot] = Field(default_factory=list)
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


_PROGRAMS: tuple[str, ...] = ("openclaw", "claude_code")


def _build_install_key_slots(
    owner_key: str,
    install_key_registry: InstallKeyRegistry,
) -> list[InstallKeyDashboardSlot]:
    records = install_key_registry.get_keys_for_owner(owner_key)
    by_program: dict[str, InstallKeyDashboardSlot] = {}

    for rec in records:
        slot_status: InstallKeySlotStatus
        if rec.active:
            slot_status = "active"
        else:
            slot_status = "revoked"

        existing = by_program.get(rec.program)
        # Prefer active key over revoked; most recent revoked over older revoked
        if existing is None or (slot_status == "active" and existing.status != "active"):
            by_program[rec.program] = InstallKeyDashboardSlot(
                program=rec.program,
                masked_key=rec.masked_key,
                status=slot_status,
                units_consumed=rec.units_consumed,
                last_used_at=rec.last_used_at.isoformat() if rec.last_used_at else None,
            )

    slots: list[InstallKeyDashboardSlot] = []
    for program in _PROGRAMS:
        if program in by_program:
            slots.append(by_program[program])
        else:
            slots.append(
                InstallKeyDashboardSlot(
                    program=program,
                    masked_key=None,
                    status="locked",
                    units_consumed=0,
                    last_used_at=None,
                )
            )
    return slots


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/overview", response_model=DashboardResponse)
def get_dashboard_overview(
    owner_key: str,
    install_key_registry: InstallKeyRegistry = Depends(get_install_key_registry),
    wallet_registry: UnitWalletRegistry = Depends(get_unit_wallet_registry),
    billing_registry: BillingRegistry = Depends(get_billing_registry),
) -> DashboardResponse:
    # --- wallet KPI ---
    wallet = wallet_registry.get_wallet(owner_key)
    balance_units = wallet.balance_units if wallet is not None else 0
    total_consumed = wallet.total_consumed_units if wallet is not None else 0
    units_tone: DashboardTone = "good" if balance_units > 0 else "warning"

    # --- plan/subscription KPI ---
    plan_label = "No active plan"
    plan_tone: DashboardTone = "warning"
    try:
        sub = billing_registry.get_active_subscription_for_customer(owner_key)
        if sub is not None:
            from app.core.billing import PLAN_DEFINITIONS

            plan_def = PLAN_DEFINITIONS.get(sub.plan)
            plan_label = plan_def["name"] if plan_def else sub.plan
            plan_tone = "good"
    except Exception:
        pass

    # --- install key slots ---
    install_key_slots = _build_install_key_slots(owner_key, install_key_registry)

    return DashboardResponse(
        status="ok",
        service="ironclaw-dashboard",
        timestamp=_utc_now_iso(),
        environment="production",
        kpis=[
            DashboardKPI(label="Unit Balance", value=str(balance_units), tone=units_tone),
            DashboardKPI(label="Units Consumed", value=str(total_consumed), tone="neutral"),
            DashboardKPI(label="Active Plan", value=plan_label, tone=plan_tone),
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
        install_keys=install_key_slots,
        metadata={
            "surface": "dashboard",
            "scope": "overview",
            "generatedby": "dashboard-route",
            "owner_key": owner_key,
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


@router.post(
    "/units/record",
    response_model=RecordKeyUsageResponse,
    status_code=status.HTTP_200_OK,
)
def record_unit_usage(
    body: RecordKeyUsageRequest,
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> RecordKeyUsageResponse:
    """
    Record unit consumption for a specific install key.
    """
    try:
        updated = registry.record_key_usage(body.key_id, units=body.units)
    except InstallKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except InstallKeyUsageError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return RecordKeyUsageResponse(
        key_id=updated.key_id,
        units_consumed=updated.units_consumed,
        last_used_at=updated.last_used_at.isoformat() if updated.last_used_at else None,
        timestamp=_utc_now_iso(),
    )
