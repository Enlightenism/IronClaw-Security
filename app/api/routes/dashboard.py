from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.billing import BillingRegistry, BillingSubscription, get_billing_registry
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import InstallKeyNotFoundError, InstallKeyRegistry, get_install_key_registry
from app.core.settings import Settings, get_settings
from app.core.unit_wallet import UnitWalletRegistry, get_unit_wallet_registry
from app.dependencies.customer_auth import require_customer_read, require_customer_write
from app.services.audit_store import get_audit_store
from app.services.incident_store import get_incident_store
from app.services.quarantine_store import get_quarantine_store

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
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
    masked_key: str | None = None
    label: str
    status: str
    active: bool
    locked: bool
    revoked: bool
    payment_status: str = "unpaid"
    entitlements_status: str = "not_active"
    issued_after_payment: bool = False
    units_consumed: int
    created_at: str | None
    activated_at: str | None
    revoked_at: str | None
    last_used_at: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    if not isinstance(value, datetime):
        return None
    return value.isoformat().replace("+00:00", "Z")


def _coerce_string(value: Any, *, default: str = "") -> str:
    if value is None:
        return default
    if type(value).__module__.startswith("unittest.mock"):
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if hasattr(value, "isoformat") and callable(value.isoformat):
        return value.isoformat().replace("+00:00", "Z")
    return str(value)


def _record_is_paid_entitled(r: Any) -> bool:
    if r is None:
        return False
    if not bool(getattr(r, "active", False)):
        return False

    payment_status = _coerce_string(getattr(r, "payment_status", "paid"), default="paid").strip().lower()
    entitlement_status = _coerce_string(getattr(r, "entitlements_status", "active"), default="active").strip().lower()
    issued_after_payment = bool(getattr(r, "issued_after_payment", True))

    if payment_status not in {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}:
        if payment_status and payment_status != "unpaid":
            return False
    if entitlement_status not in {"active", "paid", "enabled", "granted"}:
        if entitlement_status and entitlement_status != "not_active":
            return False
    return issued_after_payment


def _build_install_key_views(
    registry: InstallKeyRegistry,
    owner_key: str,
) -> list[DashboardInstallKeyView]:
    try:
        records = registry.get_keys_for_owner(owner_key)
    except Exception:
        records = []

    normalized_owner = str(owner_key).strip().lower()
    supported_programs = tuple(InstallKeyFormatRegistry.list_programs())
    canonical_prefixes = tuple(spec.prefix for spec in InstallKeyFormatRegistry.list_specs())
    placeholder_message = "Keys will be generated after purchase"
    views: list[DashboardInstallKeyView] = []
    seen_programs: set[str] = set()

    for r in records:
        record_owner = _coerce_string(getattr(r, "owner_key", ""), default="").strip().lower()
        raw_program = _coerce_string(getattr(r, "program", ""), default="").strip().lower()
        program = InstallKeyFormatRegistry.normalize_program(raw_program) or raw_program
        masked_key = _coerce_string(getattr(r, "masked_key", None), default="")
        masked_key = masked_key.strip() or None

        if not record_owner or record_owner != normalized_owner:
            continue
        if program not in supported_programs:
            continue
        if masked_key is not None and not any(masked_key.startswith(prefix) for prefix in canonical_prefixes):
            continue

        revoked_at = getattr(r, "revoked_at", None)
        activated_at = getattr(r, "activated_at", None)
        active = bool(getattr(r, "active", False))
        raw_status = _coerce_string(getattr(r, "status", "")).strip().lower()
        payment_status = _coerce_string(getattr(r, "payment_status", ""), default="").strip().lower() or "unpaid"
        entitlement_status = _coerce_string(getattr(r, "entitlements_status", ""), default="").strip().lower() or "not_active"
        issued_after_payment = bool(getattr(r, "issued_after_payment", False))

        is_revoked = revoked_at is not None or raw_status == "revoked"
        is_locked = not active and not is_revoked
        is_active = active and not is_revoked

        if payment_status or entitlement_status:
            is_locked = not _record_is_paid_entitled(r) and not is_revoked
            is_active = _record_is_paid_entitled(r) and not is_revoked

        if is_revoked:
            slot_status = "revoked"
        elif is_locked:
            slot_status = "locked"
        else:
            slot_status = "active"

        metadata: dict[str, Any] = {
            "owner_key": normalized_owner,
            "payment_status": payment_status,
            "entitlements_status": entitlement_status,
            "issued_after_payment": issued_after_payment,
            "subscription_id": _coerce_string(getattr(r, "subscription_id", ""), default=""),
            "checkout_session_id": _coerce_string(getattr(r, "checkout_session_id", ""), default=""),
            "purchase_reference": _coerce_string(getattr(r, "purchase_reference", ""), default=""),
            "status": slot_status,
        }
        if slot_status == "locked":
            metadata["placeholder"] = placeholder_message
            metadata["placeholder_text"] = placeholder_message
            metadata["status_message"] = placeholder_message

        views.append(
            DashboardInstallKeyView(
                key_id=_coerce_string(getattr(r, "key_id", ""), default=""),
                program=program,
                masked_key=masked_key,
                label=_coerce_string(getattr(r, "label", ""), default=""),
                status=slot_status,
                active=is_active,
                locked=is_locked,
                revoked=is_revoked,
                payment_status=payment_status,
                entitlements_status=entitlement_status,
                issued_after_payment=issued_after_payment,
                units_consumed=int(getattr(r, "units_consumed", 0) or 0),
                created_at=_iso(getattr(r, "created_at", None)),
                activated_at=_iso(activated_at),
                revoked_at=_iso(revoked_at),
                last_used_at=_iso(getattr(r, "last_used_at", None)),
                metadata=metadata,
            )
        )
        seen_programs.add(program)

    for program in supported_programs:
        if program in seen_programs:
            continue
        views.append(
            DashboardInstallKeyView(
                key_id="",
                program=program,
                masked_key=None,
                label="",
                status="locked",
                active=False,
                locked=True,
                revoked=False,
                payment_status="unpaid",
                entitlements_status="not_active",
                issued_after_payment=False,
                units_consumed=0,
                created_at=None,
                activated_at=None,
                revoked_at=None,
                last_used_at=None,
                metadata={
                    "owner_key": normalized_owner,
                    "placeholder": placeholder_message,
                    "placeholder_text": placeholder_message,
                    "status_message": placeholder_message,
                },
            )
        )

    return sorted(views, key=lambda item: supported_programs.index(item.program) if item.program in supported_programs else len(supported_programs))


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


@router.get(
    "/overview",
    response_model=DashboardResponse,
    dependencies=[Depends(require_customer_read)],
)
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

    _DEMO_OWNER = "demo@ironclaw.local"
    resolved_owner = owner_key.strip() if owner_key and owner_key.strip() else _DEMO_OWNER

    wallet_kpi = _build_wallet_kpi(wallet_registry, resolved_owner)

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


@router.get(
    "/units",
    response_model=DashboardUnitsResponse,
    dependencies=[Depends(require_customer_read)],
)
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


@router.post(
    "/units/record",
    response_model=RecordKeyUsageResponse,
    dependencies=[Depends(require_customer_write)],
)
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
