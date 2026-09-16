from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.billing import BillingRegistry, get_billing_registry
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import (
    InstallKeyNotFoundError,
    InstallKeyRegistry,
    InstallKeyUsageError,
    get_install_key_registry,
)
from app.core.unit_wallet import UnitWalletRegistry, get_unit_wallet_registry
from app.dependencies.hybrid_auth import HybridAuthResult, require_hybrid_auth
from app.services.install_key_provisioning import InstallKeyProvisioningService, provision_install_key_service

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

    key_id: str | None = None
    program: str
    masked_key: str | None = None
    status: InstallKeySlotStatus
    active: bool = False
    remaining_units: int = 0
    units_consumed: int = 0
    total_blocked_attacks: int = 0
    usage_by_action: dict[str, int] = Field(default_factory=dict)
    payment_status: str = "unpaid"
    entitlements_status: str = "not_active"
    issued_after_payment: bool = False
    last_used_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    metadata: dict[str, Any] = Field(default_factory=dict)


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
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return value.isoformat().replace("+00:00", "Z")


_PROGRAMS: tuple[str, ...] = InstallKeyFormatRegistry.list_programs()
_PLACEHOLDER_PURCHASE_MESSAGE = "Keys will be generated after purchase"


def _canonical_program_name(program: Any) -> str:
    if program is None:
        return ""
    canonical = InstallKeyFormatRegistry.normalize_program(str(program))
    if canonical is not None:
        return canonical

    normalized = str(program).strip().lower().replace(" ", "_").replace("-", "_")
    normalized = normalized.replace("__", "_").strip("_")
    return normalized


def _norm_status(value: Any, *, default: str = "unpaid") -> str:
    if value is None:
        return default
    normalized = str(value).strip().lower()
    return normalized or default


def _record_is_paid_entitled(rec: Any) -> bool:
    if rec is None:
        return False

    status_value = _norm_status(getattr(rec, "status", ""), default="")
    active_flag = bool(getattr(rec, "active", False))
    if status_value == "active":
        active_flag = True
    elif status_value == "revoked":
        active_flag = False

    if not active_flag:
        return False

    payment_raw = getattr(rec, "payment_status", None)
    entitlement_raw = getattr(rec, "entitlements_status", None)
    issued_after_payment = bool(getattr(rec, "issued_after_payment", False))

    def _has_real_scalar(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (bool, int, float)):
            return True
        return False

    if status_value == "active" and not _has_real_scalar(payment_raw) and not _has_real_scalar(entitlement_raw):
        return True

    payment = _norm_status(payment_raw if _has_real_scalar(payment_raw) else "paid", default="paid")
    entitlement = _norm_status(entitlement_raw if _has_real_scalar(entitlement_raw) else "active", default="active")

    if payment not in {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}:
        return False
    if entitlement != "active":
        return False
    return issued_after_payment or status_value == "active"


def _resolve_dashboard_owner(
    owner_key: str | None,
    auth_result: HybridAuthResult,
    lifecycle_service: InstallKeyProvisioningService,
) -> str:
    def _looks_like_generic_auth_identity(candidate: str) -> bool:
        value = candidate.strip().lower()
        if not value:
            return False
        if value.startswith("ic_") and any(token in value for token in ("key", "token", "auth", "legacy", "system", "api")):
            return True
        if value.startswith("sk_") or value.startswith("ghp_") or value.startswith("ghu_"):
            return True
        return False

    if owner_key and str(owner_key).strip():
        return str(owner_key).strip()

    principal = (auth_result.principal_id or "").strip()
    if principal:
        candidate = principal.strip().lower()
        if "@" in candidate and not candidate.startswith("ic_"):
            return candidate
        if not _looks_like_generic_auth_identity(candidate):
            return candidate

    return "demo@ironclaw.local"


def _canonical_wallet_usage_for_key(
    wallet_registry: UnitWalletRegistry,
    owner_key: str,
    key_id: str,
) -> dict[str, Any]:
    if wallet_registry is None:
        return {}

    summary = wallet_registry.get_key_usage_summary(owner_key, key_id=key_id)
    usage_map = summary.get("install_key_usage") or {}
    if not usage_map:
        return {}
    usage = next(iter(usage_map.values()), {})
    if hasattr(usage, "as_summary"):
        return usage.as_summary()
    if isinstance(usage, dict):
        return usage
    return {}


def _usage_by_action_for_key(
    wallet_registry: UnitWalletRegistry,
    owner_key: str,
    key_id: str,
) -> dict[str, int]:
    usage_by_action: dict[str, int] = {}
    if wallet_registry is None:
        return usage_by_action

    entries = wallet_registry.list_ledger_entries(owner_key=owner_key, limit=500)
    for entry in entries:
        metadata = getattr(entry, "metadata", {}) or {}
        if metadata.get("key_id") != key_id:
            continue
        action_type = str(metadata.get("action_type") or "prompt").strip() or "prompt"
        usage_by_action[action_type] = usage_by_action.get(action_type, 0) + int(getattr(entry, "units", 0) or 0)
    return usage_by_action


def _build_install_key_slots(
    owner_key: str,
    install_key_registry: InstallKeyRegistry,
    wallet_registry: UnitWalletRegistry,
    lifecycle_service: InstallKeyProvisioningService,
) -> list[InstallKeyDashboardSlot]:
    normalized_owner = _resolve_dashboard_owner(owner_key, HybridAuthResult(None, None, None, True, "dashboard"), lifecycle_service)
    wallet = wallet_registry.get_wallet(normalized_owner)
    records = install_key_registry.get_keys_for_owner(normalized_owner)
    by_program: dict[str, InstallKeyDashboardSlot] = {}

    for rec in records:
        program = _canonical_program_name(getattr(rec, "program", ""))
        if not program or program not in _PROGRAMS:
            continue

        payload = _canonical_wallet_usage_for_key(wallet_registry, normalized_owner, rec.key_id)
        usage_by_action = _usage_by_action_for_key(wallet_registry, normalized_owner, rec.key_id)
        wallet_balance = int(getattr(wallet, "balance_units", 0)) if wallet is not None else 0
        remaining_units = wallet_balance if wallet_balance > 0 or _record_is_paid_entitled(rec) else 0
        units_consumed = int(getattr(rec, "units_consumed", 0) or payload.get("total_consumed_units", 0))
        if payload.get("total_consumed_units") is not None:
            units_consumed = int(payload["total_consumed_units"])
        blocked_attacks = int(payload.get("total_blocked_attacks", 0) or 0)

        revoked_at = getattr(rec, "revoked_at", None)
        if revoked_at is not None and (isinstance(revoked_at, datetime) or (isinstance(revoked_at, str) and revoked_at.strip())):
            status = "revoked"
        elif _record_is_paid_entitled(rec):
            status = "active"
        else:
            status = "locked"
            remaining_units = 0

        metadata: dict[str, Any] = {
            "subscription_id": getattr(rec, "subscription_id", None),
            "checkout_session_id": getattr(rec, "checkout_session_id", None),
            "purchase_reference": getattr(rec, "purchase_reference", None),
            "payment_status": _norm_status(getattr(rec, "payment_status", "unpaid"), default="unpaid"),
            "entitlements_status": _norm_status(getattr(rec, "entitlements_status", "not_active"), default="not_active"),
            "issued_after_payment": bool(getattr(rec, "issued_after_payment", False)),
            "owner_key": getattr(rec, "owner_key", normalized_owner),
            "usage_summary": payload,
        }
        if status == "locked":
            metadata.update(
                {
                    "placeholder": _PLACEHOLDER_PURCHASE_MESSAGE,
                    "placeholder_text": _PLACEHOLDER_PURCHASE_MESSAGE,
                    "status_message": _PLACEHOLDER_PURCHASE_MESSAGE,
                }
            )

        by_program[program] = InstallKeyDashboardSlot(
            key_id=rec.key_id,
            program=program,
            masked_key=getattr(rec, "masked_key", None) or None,
            status=status,
            active=bool(getattr(rec, "active", False)) and _record_is_paid_entitled(rec),
            remaining_units=remaining_units,
            units_consumed=units_consumed,
            total_blocked_attacks=blocked_attacks,
            usage_by_action=usage_by_action,
            payment_status=_norm_status(getattr(rec, "payment_status", "unpaid"), default="unpaid"),
            entitlements_status=_norm_status(getattr(rec, "entitlements_status", "not_active"), default="not_active"),
            issued_after_payment=bool(getattr(rec, "issued_after_payment", False)),
            last_used_at=_iso(getattr(rec, "last_used_at", None)),
            metadata=metadata,
        )

    slots: list[InstallKeyDashboardSlot] = []
    for program in _PROGRAMS:
        slot = by_program.get(program)
        if slot is not None:
            slots.append(slot)
            continue
        slots.append(
            InstallKeyDashboardSlot(
                program=program,
                masked_key=None,
                status="locked",
                active=False,
                remaining_units=0,
                units_consumed=0,
                total_blocked_attacks=0,
                usage_by_action={},
                payment_status="unpaid",
                entitlements_status="not_active",
                issued_after_payment=False,
                last_used_at=None,
                metadata={
                    "placeholder": _PLACEHOLDER_PURCHASE_MESSAGE,
                    "placeholder_text": _PLACEHOLDER_PURCHASE_MESSAGE,
                    "status_message": _PLACEHOLDER_PURCHASE_MESSAGE,
                    "owner_key": normalized_owner,
                },
            )
        )
    return slots


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/overview", response_model=DashboardResponse)
def get_dashboard_overview(
    owner_key: str | None = Query(default=None),
    auth_result: HybridAuthResult = Depends(require_hybrid_auth),
    install_key_registry: InstallKeyRegistry = Depends(get_install_key_registry),
    wallet_registry: UnitWalletRegistry = Depends(get_unit_wallet_registry),
    billing_registry: BillingRegistry = Depends(get_billing_registry),
) -> DashboardResponse:
    lifecycle_service = provision_install_key_service()
    resolved_owner = _resolve_dashboard_owner(owner_key, auth_result, lifecycle_service)

    wallet = wallet_registry.get_wallet(resolved_owner)
    balance_units = wallet.balance_units if wallet is not None else 0
    total_consumed = wallet.total_consumed_units if wallet is not None else 0
    units_tone: DashboardTone = "good" if balance_units > 0 else "warning"

    plan_label = "No active plan"
    plan_tone: DashboardTone = "warning"
    try:
        sub = billing_registry.get_active_subscription_for_customer(resolved_owner)
        if sub is not None:
            from app.core.billing import PLAN_DEFINITIONS

            plan_def = PLAN_DEFINITIONS.get(sub.plan)
            plan_label = plan_def["name"] if plan_def else sub.plan
            plan_tone = "good"
    except Exception:
        pass

    install_key_slots = _build_install_key_slots(
        resolved_owner,
        install_key_registry,
        wallet_registry,
        lifecycle_service,
    )

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
            "owner_key": resolved_owner,
        },
    )


@router.get("/units", response_model=DashboardUnitsResponse)
def get_units_for_owner(
    owner_key: str,
    _: HybridAuthResult = Depends(require_hybrid_auth),
    registry: InstallKeyRegistry = Depends(get_install_key_registry),
    wallet_registry: UnitWalletRegistry = Depends(get_unit_wallet_registry),
) -> DashboardUnitsResponse:
    """
    Return unit consumption tracking for all install keys belonging to owner_key.
    """
    records = registry.get_keys_for_owner(owner_key)
    wallet = wallet_registry.get_wallet(owner_key)
    total_units = int(getattr(wallet, "total_consumed_units", 0) if wallet is not None else 0)
    if total_units == 0:
        total_units = sum(int(getattr(r, "units_consumed", 0) or 0) for r in records)

    entries = []
    for r in records:
        payload = _canonical_wallet_usage_for_key(wallet_registry, owner_key, r.key_id)
        units_consumed = int(getattr(r, "units_consumed", 0) or payload.get("total_consumed_units", 0))
        if payload.get("total_consumed_units") is not None:
            units_consumed = int(payload["total_consumed_units"])
        entries.append(
            InstallKeyUnitEntry(
                key_id=r.key_id,
                program=r.program,
                masked_key=getattr(r, "masked_key", None) or "",
                label=getattr(r, "label", "") or "",
                active=bool(getattr(r, "active", False)) and _record_is_paid_entitled(r),
                units_consumed=units_consumed,
                last_used_at=(_iso(getattr(r, "last_used_at", None)) if getattr(r, "last_used_at", None) is not None else None),
            )
        )
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
    _: HybridAuthResult = Depends(require_hybrid_auth),
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
