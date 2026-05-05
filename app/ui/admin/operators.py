from __future__ import annotations


from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/admin",
    tags=["operator-management"],
)


class OperatorItem(BaseModel):
    operatorid: str
    displayname: str
    role: str
    status: str
    email: Optional[str] = None
    lastactiveat: Optional[str] = None
    assignment: Optional[str] = None
    capabilities: list[str] = Field(default_factory=list)


class OperatorManagementSummary(BaseModel):
    total: int = 0
    active: int = 0
    inactive: int = 0
    ready: int = 0
    degraded: int = 0


class OperatorManagementResponse(BaseModel):
    title: str = "Operator Management"
    status: str = "ok"
    generatedat: str
    summary: OperatorManagementSummary
    items: list[OperatorItem] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=timezone.utc).isoformat()


def _build_placeholder_items() -> list[OperatorItem]:
    return [
        OperatorItem(
            operatorid="operator-001",
            displayname="Security Analyst One",
            role="analyst",
            status="active",
            email="analyst1@ironclaw.local",
            lastactiveat=_utc_iso(2026, 4, 18, 17, 30),
            assignment="review-queue",
            capabilities=["review_queue", "incident_triage", "request_stream"],
        ),
        OperatorItem(
            operatorid="operator-002",
            displayname="Review Lead",
            role="reviewer",
            status="active",
            email="reviewlead@ironclaw.local",
            lastactiveat=_utc_iso(2026, 4, 18, 17, 20),
            assignment="detonation-control",
            capabilities=["review_queue", "detonation_release", "audit_review"],
        ),
        OperatorItem(
            operatorid="operator-003",
            displayname="Platform Admin",
            role="admin",
            status="inactive",
            email="admin@ironclaw.local",
            lastactiveat=_utc_iso(2026, 4, 17, 22, 0),
            assignment="platform-admin",
            capabilities=["operators_admin", "roles_admin", "system_diagnostics"],
        ),
    ]


@router.get("/operators", response_model=OperatorManagementResponse)
def get_operator_management() -> OperatorManagementResponse:
    items = _build_placeholder_items()
    active = sum(1 for item in items if item.status == "active")
    inactive = sum(1 for item in items if item.status != "active")

    return OperatorManagementResponse(
        generatedat=datetime.now(timezone.utc).isoformat(),
        summary=OperatorManagementSummary(
            total=len(items),
            active=active,
            inactive=inactive,
            ready=active,
            degraded=inactive,
        ),
        items=items,
    )