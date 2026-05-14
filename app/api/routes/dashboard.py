from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.core.unit_wallet import get_unit_wallet_registry
from app.services.audit_store import get_audit_store
from app.services.incident_store import get_incident_store
from app.services.quarantine_store import get_quarantine_store

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_api_key)],
)


class DashboardStatView(BaseModel):
    key: str
    label: str
    value: int
    delta: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DashboardIncidentView(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    source: str
    created_at: str
    verdict: str | None = None


class DashboardQueueView(BaseModel):
    queue_name: str
    pending: int
    in_progress: int
    completed_today: int


class DashboardIntegrationView(BaseModel):
    integration_id: str
    label: str
    status: str
    protected_requests_24h: int
    blocked_events_24h: int


class DashboardWalletView(BaseModel):
    owner_key: str
    balance_units: int
    total_purchased_units: int
    total_consumed_units: int
    updated_at: str


class DashboardResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    environment: str
    kpis: list[DashboardStatView] = Field(default_factory=list)
    alerts: list[DashboardIncidentView] = Field(default_factory=list)
    activity: list[DashboardQueueView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_label(value: str) -> str:
    return value.replace("-", " ").replace("_", " ").title()


@router.get("/overview", response_model=DashboardResponse)
def get_dashboard_overview() -> DashboardResponse:
    now = _utc_now_iso()

    incident_store = get_incident_store()
    quarantine_store = get_quarantine_store()
    audit_store = get_audit_store()
    wallet_registry = get_unit_wallet_registry()

    incidents = incident_store.list_incidents()
    quarantine_items = quarantine_store.list_items()
    audit_events = audit_store.list_events(limit=500)

    open_incidents = [i for i in incidents if i.status in {"open", "triaged"}]
    blocked_events = [e for e in audit_events if (e.verdict or "").lower() in {"block", "quarantine"}]

    integration_rollups: dict[str, dict[str, int | str]] = {}
    for event in audit_events:
        integration_id = event.integration_id or "core-system"
        bucket = integration_rollups.setdefault(
            integration_id,
            {
                "integration_id": integration_id,
                "label": _normalize_label(integration_id),
                "status": "protected",
                "protected_requests_24h": 0,
                "blocked_events_24h": 0,
            },
        )
        bucket["protected_requests_24h"] = int(bucket["protected_requests_24h"]) + 1
        if (event.verdict or "").lower() in {"block", "quarantine"}:
            bucket["blocked_events_24h"] = int(bucket["blocked_events_24h"]) + 1

    wallet = wallet_registry.get_wallet("demo@ironclaw.local")
    if wallet is None:
        wallet = wallet_registry.get_or_create_wallet("demo@ironclaw.local")

    recent_incidents = sorted(incidents, key=lambda i: i.created_at, reverse=True)[:5]

    quarantine_pending = [i for i in quarantine_items if i.status in {"isolated", "under_review"}]
    quarantine_completed = [i for i in quarantine_items if i.status in {"released", "destroyed"}]

    return DashboardResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=now,
        environment="production",
        kpis=[
            DashboardStatView(
                key="protected_requests",
                label="Protected Requests",
                value=len(audit_events),
                delta=0,
                metadata={"window": "active"},
            ),
            DashboardStatView(
                key="blocked_actions",
                label="Blocked Actions",
                value=len(blocked_events),
                delta=0,
                metadata={"window": "active"},
            ),
            DashboardStatView(
                key="quarantined_items",
                label="Quarantined Items",
                value=len(quarantine_items),
                delta=0,
                metadata={"window": "active"},
            ),
            DashboardStatView(
                key="open_incidents",
                label="Open Incidents",
                value=len(open_incidents),
                delta=0,
                metadata={"window": "active"},
            ),
        ],
        alerts=[
            DashboardIncidentView(
                incident_id=i.incident_id,
                title=i.title,
                severity=i.severity,
                status=i.status,
                source=i.source,
                created_at=i.created_at.isoformat().replace("+00:00", "Z"),
                verdict=i.verdict,
            )
            for i in recent_incidents
        ],
        activity=[
            DashboardQueueView(
                queue_name="review_queue",
                pending=len(open_incidents),
                in_progress=len([i for i in open_incidents if i.owner]),
                completed_today=len([i for i in incidents if i.status == "resolved"]),
            ),
            DashboardQueueView(
                queue_name="quarantine_queue",
                pending=len(quarantine_pending),
                in_progress=len([i for i in quarantine_pending if i.owner]),
                completed_today=len(quarantine_completed),
            ),
        ],
        metadata={
            "integrations": [
                {
                    "integration_id": str(item["integration_id"]),
                    "label": str(item["label"]),
                    "status": str(item["status"]),
                    "protected_requests_24h": int(item["protected_requests_24h"]),
                    "blocked_events_24h": int(item["blocked_events_24h"]),
                }
                for item in sorted(
                    integration_rollups.values(),
                    key=lambda item: (
                        -int(item["protected_requests_24h"]),
                        str(item["integration_id"]),
                    ),
                )
            ],
            "wallet": {
                "owner_key": wallet.owner_key,
                "balance_units": wallet.balance_units,
                "total_purchased_units": wallet.total_purchased_units,
                "total_consumed_units": wallet.total_consumed_units,
                "updated_at": wallet.updated_at.isoformat().replace("+00:00", "Z"),
            },
        },
    )
