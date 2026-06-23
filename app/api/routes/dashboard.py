from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.core.billing import BillingRegistry, BillingSubscription, get_billing_registry
from app.core.install_keys import InstallKeyNotFoundError, InstallKeyRegistry, get_install_key_registry
from app.core.settings import Settings, get_settings
from app.core.unit_wallet import UnitWalletRegistry, get_unit_wallet_registry
from app.services.audit_store import get_audit_store
from app.services.incident_store import get_incident_store
from app.services.quarantine_store import get_quarantine_store

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_api_key)],
)


# ---------------------------------------------------------------------------
# Shared models
# ---------------------------------------------------------------------------


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


class DashboardInstallKeyView(BaseModel):
    key_id: str
    program: str
    masked_key: str
    label: str
    status: str
    active: bool
    locked: bool
    revoked: bool
    units_consumed: int
    created_at: str | None
    activated_at: str | None
    revoked_at: str | None
    last_used_at: str | None


class DashboardWalletKPI(BaseModel):
    unit_balance: int
    units_consumed: int
    total_purchased_units: int
    updated_at: str | None


class DashboardBillingKPI(BaseModel):
    plan: str
    status: str
    units_consumed: int
    unit_limit: int
    remaining_units: int


class DashboardResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    environment: str
    kpis: list[DashboardStatView] = Field(default_factory=list)
    alerts: list[DashboardIncidentView] = Field(default_factory=list)
    activity: list[DashboardQueueView] = Field(default_factory=list)
    install_keys: list[DashboardInstallKeyView] = Field(default_factory=list)
    wallet: DashboardWalletKPI | None = None
    billing: DashboardBillingKPI | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KeyUsageSummary(BaseModel):
    key_id: str
    program: str
    masked_key: str
    label: str
    active: bool
    units_consumed: int
    last_used_at: str | None


class DashboardUnitsResponse(BaseModel):
    owner_key: str
    total_keys: int
    total_units_consumed: int
    keys: list[KeyUsageSummary]
    timestamp: str


class RecordKeyUsageRequest(BaseModel):
    key_id: str
    units: int = Field(..., gt=0)


class RecordKeyUsageResponse(BaseModel):
    key_id: str
    units_consumed: int
    last_used_at: str | None
    timestamp: str


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_label(value: str) -> str:
    return value.replace("-", " ").replace("_", " ").title()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


def _build_install_key_views(
    registry: InstallKeyRegistry,
    owner_key: str,
) -> list[DashboardInstallKeyView]:
    """
    Return all install key records for owner_key with correct slot status.
    Status precedence: revoked > locked > active.
    A key is:
      - revoked  : revoked_at is set OR status field == "revoked"
      - locked   : active is False AND revoked_at is None (not yet activated)
      - active   : active is True AND revoked_at is None
    """
    try:
        records = registry.get_keys_for_owner(owner_key)
    except Exception:
        return []

    views: list[DashboardInstallKeyView] = []
    for r in records:
        revoked_at = getattr(r, "revoked_at", None)
        activated_at = getattr(r, "activated_at", None)
        active = bool(getattr(r, "active", False))
        raw_status = str(getattr(r, "status", "") or "")

        is_revoked = revoked_at is not None or raw_status == "revoked"
        is_locked = not active and not is_revoked
        is_active = active and not is_revoked

        if is_revoked:
            slot_status = "revoked"
        elif is_locked:
            slot_status = "locked"
        else:
            slot_status = "active"

        views.append(
            DashboardInstallKeyView(
                key_id=r.key_id,
                program=r.program,
                masked_key=r.masked_key,
                label=r.label,
                status=slot_status,
                active=is_active,
                locked=is_locked,
                revoked=is_revoked,
                units_consumed=getattr(r, "units_consumed", 0),
                created_at=_iso(getattr(r, "created_at", None)),
                activated_at=_iso(activated_at),
                revoked_at=_iso(revoked_at),
                last_used_at=_iso(getattr(r, "last_used_at", None)),
            )
        )
    return views


def _build_wallet_kpi(
    wallet_registry: UnitWalletRegistry,
    owner_key: str,
) -> DashboardWalletKPI | None:
    try:
        wallet = wallet_registry.get_wallet(owner_key)
        if wallet is None:
            return None
        return DashboardWalletKPI(
            unit_balance=wallet.balance_units,
            units_consumed=wallet.total_consumed_units,
            total_purchased_units=wallet.total_purchased_units,
            updated_at=_iso(wallet.updated_at),
        )
    except Exception:
        return None


def _build_billing_kpi(
    billing_registry: BillingRegistry,
    owner_key: str,
) -> DashboardBillingKPI | None:
    try:
        subscription: BillingSubscription | None = billing_registry.get_active_subscription_for_customer(owner_key)
        if subscription is None:
            return None
        return DashboardBillingKPI(
            plan=subscription.plan,
            status=subscription.status,
            units_consumed=subscription.units_consumed,
            unit_limit=subscription.unit_limit,
            remaining_units=subscription.remaining_units,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/overview", response_model=DashboardResponse)
def get_dashboard_overview(
    owner_key: str | None = Query(default=None),
    settings: Settings = Depends(get_settings),
    wallet_registry: UnitWalletRegistry = Depends(get_unit_wallet_registry),
    billing_registry: BillingRegistry = Depends(get_billing_registry),
    install_key_registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> DashboardResponse:
    now = _utc_now_iso()

    incident_store = get_incident_store()
    quarantine_store = get_quarantine_store()
    audit_store = get_audit_store()

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

    # ---------------------------------------------------------------------------
    # Owner-scoped wallet, billing, and install key resolution
    # owner_key query param → live per-owner data
    # no owner_key → fall back to demo sentinel for backward compat
    # ---------------------------------------------------------------------------
    _DEMO_OWNER = "demo@ironclaw.local"
    resolved_owner = owner_key.strip() if owner_key and owner_key.strip() else _DEMO_OWNER

    wallet_kpi = _build_wallet_kpi(wallet_registry, resolved_owner)

    # If no wallet under the resolved key and we fell back to demo, try get_or_create
    if wallet_kpi is None and resolved_owner == _DEMO_OWNER:
        try:
            wallet = wallet_registry.get_or_create_wallet(_DEMO_OWNER)
            wallet_kpi = DashboardWalletKPI(
                unit_balance=wallet.balance_units,
                units_consumed=wallet.total_consumed_units,
                total_purchased_units=wallet.total_purchased_units,
                updated_at=_iso(wallet.updated_at),
            )
        except Exception:
            wallet_kpi = None

    billing_kpi = _build_billing_kpi(billing_registry, resolved_owner)
    install_keys = _build_install_key_views(install_key_registry, resolved_owner)

    # ---------------------------------------------------------------------------
    # Backward-compat metadata.wallet block (legacy consumers)
    # ---------------------------------------------------------------------------
    wallet_meta: dict[str, Any] = {}
    if wallet_kpi is not None:
        wallet_meta = {
            "owner_key": resolved_owner,
            "unit_balance": wallet_kpi.unit_balance,
            "units_consumed": wallet_kpi.units_consumed,
            "total_purchased_units": wallet_kpi.total_purchased_units,
            "updated_at": wallet_kpi.updated_at,
        }

    subscription_meta: dict[str, Any] = {}
    if billing_kpi is not None:
        subscription_meta = {
            "plan": billing_kpi.plan,
            "status": billing_kpi.status,
            "units_consumed": billing_kpi.units_consumed,
            "unit_limit": billing_kpi.unit_limit,
            "remaining_units": billing_kpi.remaining_units,
        }

    recent_incidents = sorted(incidents, key=lambda i: i.created_at, reverse=True)[:5]
    quarantine_pending = [i for i in quarantine_items if i.status in {"isolated", "under_review"}]
    quarantine_completed = [i for i in quarantine_items if i.status in {"released", "destroyed"}]

    return DashboardResponse(
        status="ok",
        service="ironclaw-security",
        timestamp=now,
        environment=settings.environment,
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
        install_keys=install_keys,
        wallet=wallet_kpi,
        billing=billing_kpi,
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
                    key=lambda item: (-int(item["protected_requests_24h"]), str(item["integration_id"])),
                )
            ],
            "wallet": wallet_meta,
            "subscription": subscription_meta,
            "owner_key": resolved_owner,
        },
    )


@router.get("/units", response_model=DashboardUnitsResponse)
def get_dashboard_units(
    owner_key: str = Query(...),
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> DashboardUnitsResponse:
    records = registry.get_keys_for_owner(owner_key)
    return DashboardUnitsResponse(
        owner_key=owner_key,
        total_keys=len(records),
        total_units_consumed=sum(r.units_consumed for r in records),
        keys=[
            KeyUsageSummary(
                key_id=r.key_id,
                program=r.program,
                masked_key=r.masked_key,
                label=r.label,
                active=r.active,
                units_consumed=r.units_consumed,
                last_used_at=r.last_used_at.isoformat().replace("+00:00", "Z") if r.last_used_at else None,
            )
            for r in records
        ],
        timestamp=_utc_now_iso(),
    )


@router.post("/units/record", response_model=RecordKeyUsageResponse)
def record_key_usage(
    body: RecordKeyUsageRequest,
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> RecordKeyUsageResponse:
    try:
        updated = registry.record_key_usage(body.key_id, body.units)
    except InstallKeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RecordKeyUsageResponse(
        key_id=updated.key_id,
        units_consumed=updated.units_consumed,
        last_used_at=updated.last_used_at.isoformat().replace("+00:00", "Z") if updated.last_used_at else None,
        timestamp=_utc_now_iso(),
    )
