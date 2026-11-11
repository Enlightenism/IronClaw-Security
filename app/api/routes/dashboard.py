from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.auth import AuthContext
from app.core.billing import (
    UNIT_PACKAGE_CATALOG,
    BillingRegistry,
    BillingSubscription,
    get_billing_registry,
    resolve_authenticated_billing_owner,
    resolve_package_id,
)
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import InstallKeyNotFoundError, InstallKeyRegistry, get_install_key_registry
from app.core.settings import Settings, get_settings
from app.core.unit_wallet import RegistryUnitLedgerEntry, UnitWalletRegistry, get_unit_wallet_registry
from app.dependencies.customer_auth import require_customer_read, require_customer_write
from app.services.audit_store import get_audit_store
from app.services.incident_store import get_incident_store
from app.services.install_key_dashboard_sync import InstallKeyDashboardSyncService

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)

logger = logging.getLogger(__name__)


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


class DashboardLastPaymentView(BaseModel):
    label: str
    amount: float
    units: int
    package_id: str
    purchased_at: str
    support_reference: str | None = None


class DashboardWalletHistoryEntry(BaseModel):
    entry_type: str
    label: str
    units: int
    balance_after: int
    package_id: str | None = None
    created_at: str
    support_reference: str | None = None


class DashboardResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    environment: str
    wallet_units: int = Field(default=0, ge=0)
    wallet_status: str = "unavailable"
    has_paid: bool = False
    last_payment: DashboardLastPaymentView | None = None
    wallet_history: list[DashboardWalletHistoryEntry] = Field(default_factory=list)
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


def _is_connector_program(program: Any) -> bool:
    normalized = _coerce_string(program, default="").strip().lower()
    if not normalized:
        return False
    normalized = normalized.replace(" ", "_").replace("-", "_").replace("__", "_").strip("_")
    return normalized in {
        "security_guardian",
        "securityguardian",
        "security_guardian_skill",
        "security_guardian_skill_",
        "skill",
        "skills",
    }


def _program_label(program: str) -> str:
    try:
        return InstallKeyFormatRegistry.get_spec(program).display_name
    except ValueError:
        return _normalize_label(program)


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
    if isinstance(value, int | float | bool):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if hasattr(value, "isoformat") and callable(value.isoformat):
        return value.isoformat().replace("+00:00", "Z")
    return str(value)


def _resolve_dashboard_owner(auth_ctx: AuthContext, requested_owner_key: str | None = None) -> str:
    resolved_owner = resolve_authenticated_billing_owner(auth_ctx)
    if not resolved_owner:
        metadata = getattr(auth_ctx, "metadata", None)
        logger.warning(
            "dashboard.owner_unresolved principal_type=%s key_type=%s identity_claims=%s",
            getattr(auth_ctx, "principal_type", None),
            getattr(auth_ctx, "key_type", None),
            sorted(metadata.keys()) if isinstance(metadata, dict) else [],
        )
        raise HTTPException(status_code=403, detail="Dashboard owner could not be resolved from authenticated identity.")
    if requested_owner_key is not None and requested_owner_key.strip().lower() != resolved_owner:
        raise HTTPException(status_code=403, detail="Requested dashboard owner does not match authenticated identity.")
    return resolved_owner


def _record_matches_dashboard_identity(
    record: Any,
    *,
    owner_key: str,
    principal_id: str | None,
    organization_id: str | None,
) -> bool:
    metadata = record.get("metadata") if isinstance(record, dict) else getattr(record, "metadata", None)
    if not isinstance(metadata, dict):
        metadata = {}

    owner_candidates = (
        record.get("owner_key") if isinstance(record, dict) else getattr(record, "owner_key", None),
        metadata.get("owner_key"),
        metadata.get("billing_owner_key"),
    )
    if any(_coerce_string(value).strip().lower() == owner_key for value in owner_candidates if value is not None):
        return True

    if principal_id:
        principal_candidates = (
            record.get("principal_id") if isinstance(record, dict) else getattr(record, "principal_id", None),
            record.get("actor_id") if isinstance(record, dict) else getattr(record, "actor_id", None),
            metadata.get("principal_id"),
            metadata.get("actor_id"),
            metadata.get("user_id"),
            metadata.get("subject_id"),
        )
        if any(_coerce_string(value).strip().lower() == principal_id.lower() for value in principal_candidates if value is not None):
            return True

    if organization_id:
        organization_candidates = (
            record.get("organization_id") if isinstance(record, dict) else getattr(record, "organization_id", None),
            record.get("org_id") if isinstance(record, dict) else getattr(record, "org_id", None),
            metadata.get("organization_id"),
            metadata.get("org_id"),
            metadata.get("tenant_id"),
        )
        if any(_coerce_string(value).strip().lower() == organization_id.lower() for value in organization_candidates if value is not None):
            return True

    return False


def _record_is_paid_entitled(r: Any) -> bool:
    if r is None:
        return False

    status_value = _coerce_string(getattr(r, "status", ""), default="").strip().lower()
    active_flag = bool(getattr(r, "active", False))
    if status_value == "active":
        active_flag = True
    elif status_value == "revoked":
        active_flag = False

    if not active_flag:
        return False

    payment_status = _coerce_string(getattr(r, "payment_status", "unpaid"), default="unpaid").strip().lower()
    entitlement_status = _coerce_string(getattr(r, "entitlements_status", "not_active"), default="not_active").strip().lower()
    issued_after_payment = bool(getattr(r, "issued_after_payment", False))

    if status_value == "active" and not payment_status and not entitlement_status:
        return True
    if status_value == "active" and payment_status in {"", "unpaid"} and entitlement_status in {"", "not_active"}:
        return True

    if payment_status not in {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}:
        return False
    if entitlement_status not in {"active", "paid", "enabled", "granted"}:
        return False
    if not issued_after_payment and status_value != "active":
        return False
    return True


def _build_install_key_views(
    records: list[Any],
    owner_key: str,
    wallet_usage: dict[str, Any] | None = None,
) -> list[DashboardInstallKeyView]:
    normalized_owner = str(owner_key).strip().lower()
    supported_programs = tuple(InstallKeyFormatRegistry.list_programs())
    canonical_prefixes = tuple(spec.prefix for spec in InstallKeyFormatRegistry.list_specs())
    placeholder_message = "Keys will be generated after purchase"
    views: list[DashboardInstallKeyView] = []
    by_program: dict[str, DashboardInstallKeyView] = {}

    for r in records:
        record_owner = _coerce_string(getattr(r, "owner_key", ""), default="").strip().lower()
        raw_program = _coerce_string(getattr(r, "program", ""), default="").strip().lower()
        program = InstallKeyFormatRegistry.normalize_program(raw_program) or raw_program
        masked_key = _coerce_string(getattr(r, "masked_key", None), default="")
        masked_key = masked_key.strip() or None

        if not record_owner or record_owner != normalized_owner:
            continue
        if _is_connector_program(raw_program) or _is_connector_program(program):
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
        record_metadata = getattr(r, "metadata", None)
        revoke_reason = ""
        if isinstance(record_metadata, dict):
            revoke_reason = _coerce_string(record_metadata.get("revoke_reason"), default="").strip().lower()
        is_refunded = is_revoked and revoke_reason == "refunded"
        is_locked = not active and not is_revoked
        is_active = active and not is_revoked

        if raw_status == "active":
            is_locked = False
            is_active = True
        elif raw_status == "locked":
            is_locked = True
            is_active = False

        if payment_status or entitlement_status:
            is_locked = not _record_is_paid_entitled(r) and not is_revoked
            is_active = _record_is_paid_entitled(r) and not is_revoked

        if raw_status == "active" and not is_revoked:
            is_locked = False
            is_active = True

        if is_refunded:
            slot_status = "refunded"
        elif is_revoked:
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

        label = _coerce_string(getattr(r, "label", ""), default="") or _program_label(program)
        metadata.setdefault("program_label", label)
        metadata.setdefault("display_name", label)

        wallet_usage_entry = (wallet_usage or {}).get(_coerce_string(getattr(r, "key_id", ""), default=""))
        wallet_consumed = int(getattr(wallet_usage_entry, "total_consumed_units", 0) or 0)

        candidate = DashboardInstallKeyView(
            key_id=_coerce_string(getattr(r, "key_id", ""), default=""),
            program=program,
            masked_key=masked_key,
            label=label,
            status=slot_status,
            active=is_active,
            locked=is_locked,
            revoked=is_revoked,
            payment_status=payment_status,
            entitlements_status=entitlement_status,
            issued_after_payment=issued_after_payment,
            units_consumed=max(int(getattr(r, "units_consumed", 0) or 0), wallet_consumed),
            created_at=_iso(getattr(r, "created_at", None)),
            activated_at=_iso(activated_at),
            revoked_at=_iso(revoked_at),
            last_used_at=_iso(getattr(r, "last_used_at", None)),
            metadata=metadata,
        )

        existing = by_program.get(program)
        if existing is None:
            by_program[program] = candidate
            continue

        preference = {"refunded": 3, "revoked": 3, "active": 2, "locked": 1}
        if preference.get(candidate.status, 0) > preference.get(existing.status, 0):
            by_program[program] = candidate
        elif preference.get(candidate.status, 0) == preference.get(existing.status, 0) and candidate.last_used_at and (existing.last_used_at is None or candidate.last_used_at > existing.last_used_at):
            by_program[program] = candidate

    for program in supported_programs:
        slot = by_program.get(program)
        if slot is not None:
            views.append(slot)
            continue
        label = _program_label(program)
        views.append(
            DashboardInstallKeyView(
                key_id="",
                program=program,
                masked_key=None,
                label=label,
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
                    "program_label": label,
                    "display_name": label,
                },
            )
        )

    return sorted(views, key=lambda item: supported_programs.index(item.program) if item.program in supported_programs else len(supported_programs))


def _build_wallet_kpi(
    wallet: Any | None,
) -> DashboardWalletKPI | None:
    if wallet is None:
        return None
    return DashboardWalletKPI(
        unit_balance=wallet.balance_units,
        units_consumed=wallet.total_consumed_units,
        total_purchased_units=wallet.total_purchased_units,
        updated_at=_iso(wallet.updated_at),
    )


def _build_billing_kpi(
    billing_registry: BillingRegistry,
    owner_key: str,
) -> DashboardBillingKPI | None:
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


def _ledger_timestamp_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _build_last_payment_view(ledger_entries: list[RegistryUnitLedgerEntry]) -> DashboardLastPaymentView | None:
    latest_entry: RegistryUnitLedgerEntry | None = None
    latest_package_id: str | None = None
    for entry in ledger_entries:
        if entry.entry_type != "credit":
            continue
        package_id = resolve_package_id(str(entry.metadata.get("package_id") or ""))
        if package_id is None:
            continue
        if latest_entry is None or _ledger_timestamp_utc(entry.created_at) > _ledger_timestamp_utc(latest_entry.created_at):
            latest_entry = entry
            latest_package_id = package_id
    if latest_entry is None or latest_package_id is None:
        return None
    catalog_entry = next((item for item in UNIT_PACKAGE_CATALOG if item["package_id"] == latest_package_id), None)
    if catalog_entry is None:
        return None
    return DashboardLastPaymentView(
        label=catalog_entry["name"],
        amount=float(catalog_entry["price_usd"]),
        units=latest_entry.units,
        package_id=latest_package_id,
        purchased_at=_ledger_timestamp_utc(latest_entry.created_at).isoformat(),
        support_reference=latest_entry.checkout_session_id or latest_entry.purchase_id,
    )


def _build_wallet_history_view(
    ledger_entries: list[RegistryUnitLedgerEntry],
    *,
    limit: int = 10,
) -> list[DashboardWalletHistoryEntry]:
    recent_entries = sorted(
        ledger_entries,
        key=lambda entry: _ledger_timestamp_utc(entry.created_at),
        reverse=True,
    )[:limit]
    history: list[DashboardWalletHistoryEntry] = []
    package_names = {item["package_id"]: item["name"] for item in UNIT_PACKAGE_CATALOG}
    for entry in recent_entries:
        package_id = resolve_package_id(str(entry.metadata.get("package_id") or ""))
        entry_type = str(entry.entry_type).strip().lower()
        label = package_names.get(package_id, "") if package_id else ""
        if not label:
            label = entry_type.replace("_", " ").title()
        history.append(
            DashboardWalletHistoryEntry(
                entry_type=entry_type,
                label=label,
                units=int(entry.units),
                balance_after=int(entry.balance_after),
                package_id=package_id,
                created_at=_ledger_timestamp_utc(entry.created_at).isoformat(),
                support_reference=entry.checkout_session_id or entry.purchase_id,
            )
        )
    return history


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/overview",
    response_model=DashboardResponse,
)
def get_dashboard_overview(
    owner_key: str | None = Query(default=None),
    auth_ctx: AuthContext = Depends(require_customer_read),
    settings: Settings = Depends(get_settings),
    wallet_registry: UnitWalletRegistry = Depends(get_unit_wallet_registry),
    billing_registry: BillingRegistry = Depends(get_billing_registry),
    install_key_registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> DashboardResponse:
    now = _utc_now_iso()
    resolved_owner = _resolve_dashboard_owner(auth_ctx, owner_key)
    principal_id = _coerce_string(getattr(auth_ctx, "principal_id", None), default="").strip() or None
    organization_id = _coerce_string(getattr(auth_ctx, "org_id", None), default="").strip() or None

    incident_store = get_incident_store()
    audit_store = get_audit_store()

    def _matches_owner(event: Any) -> bool:
        return _record_matches_dashboard_identity(
            event,
            owner_key=resolved_owner,
            principal_id=principal_id,
            organization_id=organization_id,
        )

    incidents = [
        incident
        for incident in incident_store.list_incidents(include_seeded=False)
        if _record_matches_dashboard_identity(
            incident,
            owner_key=resolved_owner,
            principal_id=principal_id,
            organization_id=organization_id,
        )
    ]
    audit_events = audit_store.list_events(
        limit=500,
        include_seeded=False,
        newest_first=True,
        predicate=_matches_owner,
    )
    owner_blocked_total = sum(1 for event in audit_store.list_events(limit=None, include_seeded=False, predicate=_matches_owner) if (event.verdict or "").lower() == "block")

    open_incidents = [i for i in incidents if i.status in {"open", "triaged"}]
    blocked_events = [e for e in audit_events if (e.verdict or "").lower() == "block"]

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
        if (event.verdict or "").lower() == "block":
            bucket["blocked_events_24h"] = int(bucket["blocked_events_24h"]) + 1

    wallet = wallet_registry.get_wallet(resolved_owner)
    wallet_kpi = _build_wallet_kpi(wallet)
    ledger_entries = wallet_registry.list_ledger_entries(owner_key=resolved_owner, limit=500)
    last_payment = _build_last_payment_view(ledger_entries)
    wallet_history = _build_wallet_history_view(ledger_entries)
    billing_kpi = _build_billing_kpi(billing_registry, resolved_owner)
    install_key_records = install_key_registry.get_keys_for_owner(resolved_owner)
    install_keys = _build_install_key_views(
        install_key_records,
        resolved_owner,
        wallet.install_key_usage if wallet is not None else None,
    )
    install_key_dashboard = InstallKeyDashboardSyncService().build_dashboard_summary(
        owner_key=resolved_owner,
        install_keys=install_key_records,
        wallet_summary=wallet.as_summary() if wallet is not None else {},
        audit_events=audit_events,
        blocked_activity_total=owner_blocked_total,
    )

    wallet_status = "not_created" if wallet is None else "active" if wallet.balance_units > 0 else "empty"
    wallet_meta: dict[str, Any] = {
        "owner_key": resolved_owner,
        "status": wallet_status,
    }
    if wallet_kpi is not None:
        wallet_meta.update(
            {
                "unit_balance": wallet_kpi.unit_balance,
                "units_consumed": wallet_kpi.units_consumed,
                "total_purchased_units": wallet_kpi.total_purchased_units,
                "updated_at": wallet_kpi.updated_at,
            }
        )

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

    return DashboardResponse(
        status="ok",
        service="ironclaw-security",
        timestamp=now,
        environment=settings.environment,
        wallet_units=wallet_kpi.unit_balance if wallet_kpi is not None else 0,
        wallet_status=wallet_status,
        has_paid=last_payment is not None,
        last_payment=last_payment,
        wallet_history=wallet_history,
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
                key="blocked_attacks",
                label="Blocked Attacks",
                value=int(install_key_dashboard["blocked_activity_total"]),
                delta=0,
                metadata={"source": "attack_feed"},
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
            "install_key_dashboard": install_key_dashboard,
            "owner_key": resolved_owner,
        },
    )


@router.get(
    "/units",
    response_model=DashboardUnitsResponse,
)
def get_dashboard_units(
    owner_key: str = Query(...),
    auth_ctx: AuthContext = Depends(require_customer_read),
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
    wallet_registry: UnitWalletRegistry = Depends(get_unit_wallet_registry),
) -> DashboardUnitsResponse:
    resolved_owner = _resolve_dashboard_owner(auth_ctx, owner_key)
    records = registry.get_keys_for_owner(resolved_owner)
    wallet = wallet_registry.get_wallet(resolved_owner)
    wallet_usage = wallet.install_key_usage if wallet is not None else {}
    effective_units = {
        r.key_id: max(
            int(r.units_consumed or 0),
            int(getattr(wallet_usage.get(r.key_id), "total_consumed_units", 0) or 0),
        )
        for r in records
    }
    return DashboardUnitsResponse(
        owner_key=resolved_owner,
        total_keys=len(records),
        total_units_consumed=sum(effective_units.values()),
        keys=[
            KeyUsageSummary(
                key_id=r.key_id,
                program=r.program,
                masked_key=r.masked_key,
                label=r.label,
                active=r.active,
                units_consumed=effective_units[r.key_id],
                last_used_at=r.last_used_at.isoformat().replace("+00:00", "Z") if r.last_used_at else None,
            )
            for r in records
        ],
        timestamp=_utc_now_iso(),
    )


@router.post(
    "/units/record",
    response_model=RecordKeyUsageResponse,
)
def record_key_usage(
    body: RecordKeyUsageRequest,
    auth_ctx: AuthContext = Depends(require_customer_write),
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
) -> RecordKeyUsageResponse:
    resolved_owner = _resolve_dashboard_owner(auth_ctx)
    record = registry.get_key_by_id(body.key_id)
    record_owner = _coerce_string(getattr(record, "owner_key", None), default="").strip().lower() if record is not None else ""
    if record is None or record_owner != resolved_owner:
        raise HTTPException(status_code=404, detail="Install key not found.")

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
