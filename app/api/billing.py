from __future__ import annotations

from datetime import UTC, datetime
import logging
import math
import re
import threading
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from app.core.auth import AuthContext, require_auth_context
from app.core.billing import resolve_billing_owner
from app.core.install_keys import InstallKeyAlreadyExistsError, get_install_key_registry
from app.core.unit_wallet import (
    TOKEN_CHUNK_SIZE,
    UNIT_PACKAGE_CATALOG,
    InsufficientUnitsError,
    RegistryUnitWallet,
    get_unit_wallet_registry,
)

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[^@]+@[^@]+\.[^@]+")
_PURCHASES_MAX = 10_000
_RESERVED_OWNER_KEYS = {
    "ironclaw-system",
    "ironclaw-system-owner",
    "ironclaw-root",
    "ironclaw-root-owner",
    "root",
    "system",
}


router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(require_auth_context)],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _new_purchase_id() -> str:
    return f"purch_{uuid4().hex[:16]}"


def _require_known_package(package_id: str) -> tuple[str, dict[str, Any]]:
    normalized = package_id.strip()
    package = UNIT_PACKAGE_CATALOG.get(normalized)
    if package is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown billing package: {package_id!r}",
        )
    return normalized, package


def _wallet_view(wallet: RegistryUnitWallet) -> dict[str, Any]:
    return {
        "wallet_id": wallet.wallet_id,
        "owner_key": wallet.owner_key,
        "balance_units": wallet.balance_units,
        "total_purchased_units": wallet.total_purchased_units,
        "total_consumed_units": wallet.total_consumed_units,
        "total_refunded_units": wallet.total_refunded_units,
        "updated_at": wallet.updated_at.isoformat().replace("+00:00", "Z"),
        "metadata": getattr(wallet, "metadata", {}),
    }


def _is_paid_payment_status(value: str | None) -> bool:
    if value is None:
        return False
    normalized = str(value).strip().lower()
    return normalized in {"paid", "succeeded", "success", "completed", "complete", "active", "authorized"}


def _has_confirmed_paid_entitlement(payment_status: str | None, entitlement_status: str | None) -> bool:
    return _is_paid_payment_status(payment_status) and _normalize_entitlement_status(entitlement_status) == "active"


def _normalize_entitlement_status(value: str | None) -> str:
    if value is None:
        return "not_active"
    normalized = str(value).strip().lower()
    if not normalized:
        return "not_active"
    if normalized in {"paid", "active", "enabled", "granted", "succeeded", "success", "completed", "complete"}:
        return "active"
    return normalized


def _assert_owner_access(
    auth_ctx: AuthContext,
    owner_key: str,
    *,
    action: str = "access",
) -> None:
    is_org_wallet = owner_key.startswith("ic_org_")

    if is_org_wallet:
        if auth_ctx.key_type != "org" or not auth_ctx.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "status": "forbidden",
                    "reason": "org_wallet_requires_org_key",
                    "owner_key": owner_key,
                    "action": action,
                },
            )
        expected = f"ic_org_{auth_ctx.org_id}"
        if owner_key != expected:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Org key does not match wallet owner: expected {expected}, got {owner_key}",
            )
    else:
        if auth_ctx.key_type == "org":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "status": "forbidden",
                    "reason": "org_key_cannot_access_personal_wallet",
                    "owner_key": owner_key,
                    "action": action,
                },
            )


def _is_customer_owner_context(auth_ctx: AuthContext | None) -> bool:
    if auth_ctx is None:
        return False
    key_type = str(getattr(auth_ctx, "key_type", "") or "").strip().lower()
    principal_type = str(getattr(auth_ctx, "principal_type", "") or "").strip().lower()
    if key_type in {"personal", "customer", "user", "buyer", "org"}:
        return True
    if principal_type in {"personal", "customer", "user", "buyer", "org"}:
        return True
    return False


def _assert_customer_install_key_context(auth_ctx: AuthContext | None, owner_key: str | None) -> None:
    if _is_customer_owner_context(auth_ctx):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "status": "forbidden",
            "reason": "install_key_requires_customer_owner_context",
            "owner_key": owner_key,
            "principal_type": str(getattr(auth_ctx, "principal_type", "") or "") if auth_ctx is not None else None,
            "key_type": str(getattr(auth_ctx, "key_type", "") or "") if auth_ctx is not None else None,
            "action": "fulfill_install_keys",
        },
    )


def _safe_owner_key(auth_ctx: AuthContext, buyer_email: str) -> str:
    owner_key = resolve_billing_owner(auth_ctx, buyer_email)
    if not owner_key or owner_key.lower() in _RESERVED_OWNER_KEYS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "status": "invalid_owner_key",
                "reason": "purchase_checkout_must_not_resolve_to_visible_system_key",
                "owner_key": owner_key,
            },
        )
    _assert_customer_install_key_context(auth_ctx, owner_key)
    return owner_key


def _usage_summary_for_key(
    *,
    owner_key: str,
    program: str,
    payment_id: str | None,
    entitlement_status: str,
) -> dict[str, Any]:
    return {
        "owner_key": owner_key,
        "program": program,
        "payment_id": payment_id,
        "entitlement_status": entitlement_status,
        "usage_count": 0,
        "units_consumed": 0,
        "last_seen_at": _utc_now_iso(),
    }


# ---------------------------------------------------------------------------
# Schemas — packages
# ---------------------------------------------------------------------------


class ProtectionValueView(BaseModel):
    title: str
    detail: str


class UnitPolicyView(BaseModel):
    unit_definition: str
    delivery_model: str
    buyer_positioning: str
    token_chunk_size: int
    protection_layers: list[ProtectionValueView] = Field(default_factory=list)
    market_context: list[str] = Field(default_factory=list)


class BillingPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    token_coverage: int
    tokens_per_unit: int
    description: str


class BillingPackagesResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    packages: list[BillingPackageView] = Field(default_factory=list)
    unit_policy: UnitPolicyView


# ---------------------------------------------------------------------------
# Schemas — purchase
# ---------------------------------------------------------------------------


class InstallKeyDeliveryView(BaseModel):
    install_key_id: str | None = None
    masked_key: str | None = None
    owner_key: str | None = None
    program: str | None = None
    payment_id: str | None = None
    entitlement_status: str = "not_active"
    usage_summary: dict[str, Any] = Field(default_factory=dict)


class BillingPackagePurchaseRequest(BaseModel):
    package_id: str = Field(min_length=1, max_length=120)
    buyer_name: str = Field(min_length=1, max_length=120)
    buyer_email: str = Field(min_length=3, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("buyer_email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if not _EMAIL_RE.match(v.strip()):
            raise ValueError("buyer_email must be a valid email address")
        return v.strip().lower()


class BillingPackagePurchaseView(BaseModel):
    purchase_id: str
    package_id: str
    package_name: str
    buyer_name: str
    buyer_email: str
    owner_key: str
    price_usd: float
    granted_units: int
    token_coverage: int
    tokens_per_unit: int
    created_at: str
    payment_id: str | None = None
    payment_status: str = "pending"
    entitlement_status: str = "not_active"
    install_key_id: str | None = None
    masked_key: str | None = None
    program: str | None = None
    usage_summary: dict[str, Any] = Field(default_factory=dict)
    openclaw_install_key: str | None = None
    claude_code_install_key: str | None = None
    hermes_install_key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPackagePurchaseResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    purchase: BillingPackagePurchaseView
    wallet: dict[str, Any]


# ---------------------------------------------------------------------------
# Schemas — debit
# ---------------------------------------------------------------------------


class WalletDebitRequest(BaseModel):
    units: int | None = Field(default=None, ge=1)
    token_count: int | None = Field(default=None, ge=1)
    reason: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def _require_one(self) -> WalletDebitRequest:
        if self.units is None and self.token_count is None:
            raise PydanticCustomError(
                "missing",
                "Provide either 'units' or 'token_count'.",
            )
        return self


class WalletDebitResponse(BaseModel):
    status: str
    owner_key: str
    units_debited: int
    token_count: int | None = None
    wallet: dict[str, Any]


# ---------------------------------------------------------------------------
# Schemas — refund
# ---------------------------------------------------------------------------


class WalletRefundRequest(BaseModel):
    units: int = Field(ge=1)
    reason: str | None = Field(default=None, max_length=255)


class WalletRefundResponse(BaseModel):
    status: str
    owner_key: str
    units_refunded: int
    wallet: dict[str, Any]


# ---------------------------------------------------------------------------
# Schemas — wallet get
# ---------------------------------------------------------------------------


class WalletGetResponse(BaseModel):
    status: str
    wallet: dict[str, Any]


# ---------------------------------------------------------------------------
# Schemas — ledger
# ---------------------------------------------------------------------------


class LedgerResponse(BaseModel):
    status: str
    owner_key: str | None
    limit: int
    entries: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

_PURCHASES: list[BillingPackagePurchaseView] = []
_PURCHASES_LOCK: threading.Lock = threading.Lock()


# ---------------------------------------------------------------------------
# Package catalog helpers
# ---------------------------------------------------------------------------


def _package_to_view(pkg: dict[str, Any]) -> BillingPackageView:
    unit_amount = int(pkg["unit_amount"])
    return BillingPackageView(
        package_id=pkg["package_id"],
        name=pkg["name"],
        price_usd=float(pkg["price_usd"]),
        included_units=unit_amount,
        token_coverage=unit_amount * TOKEN_CHUNK_SIZE,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
        description=pkg["description"],
    )


def _build_unit_policy() -> UnitPolicyView:
    return UnitPolicyView(
        unit_definition="1 protection unit = 1 IronClaw protection event.",
        delivery_model="All packages are prepaid unit bundles with no recurring subscription requirement.",
        buyer_positioning=("Customers are buying protected AI usage, not raw API calls. Each unit funds layered security checks around prompts, tool activity, returned content, and release decisions."),
        token_chunk_size=TOKEN_CHUNK_SIZE,
        protection_layers=[
            ProtectionValueView(
                title="Prompt ingress protection",
                detail="Screens incoming prompts before risky instructions begin spreading through the workflow.",
            ),
            ProtectionValueView(
                title="Tool-call guardrails",
                detail="Reviews agent actions before external tools, files, or execution paths are allowed to continue.",
            ),
            ProtectionValueView(
                title="Source inspection",
                detail="Checks returned web or external content for hostile prompt-injection patterns and suspicious payloads.",
            ),
            ProtectionValueView(
                title="Response release control",
                detail="Applies final safety review before content is released back into the user session or downstream agent flow.",
            ),
            ProtectionValueView(
                title="Sandbox-backed isolation",
                detail="Pairs AI judgment with runtime boundaries so suspicious content can be contained instead of trusted.",
            ),
        ],
        market_context=[
            "Agent platforms process untrusted instructions from websites, files, repositories, docs, and generated artifacts.",
            "Prompt-injection attacks target AI systems specifically because they can redirect tools, leak data, or manipulate autonomous workflows.",
            "IronClaw protection units are designed to add security coverage around every stage where hostile content can enter or spread.",
        ],
    )


# ---------------------------------------------------------------------------
# Install key issuance gating
# ---------------------------------------------------------------------------


def _attach_install_key_delivery(
    *,
    purchase: BillingPackagePurchaseView,
    owner_key: str,
    program: str,
    payment_id: str | None,
    entitlement_status: str,
    install_key_record: Any | None,
) -> None:
    if install_key_record is None:
        return

    payment_status = str(getattr(install_key_record, "payment_status", "") or "").strip().lower()
    normalized_entitlement = _normalize_entitlement_status(entitlement_status)
    if payment_status != "paid" or normalized_entitlement != "active" or not bool(getattr(install_key_record, "issued_after_payment", False)):
        return

    masked_key = getattr(install_key_record, "masked_key", None)
    if masked_key is None:
        return

    purchase.program = program
    purchase.payment_id = payment_id
    purchase.entitlement_status = normalized_entitlement
    purchase.install_key_id = getattr(install_key_record, "key_id", None)
    purchase.masked_key = masked_key
    purchase.usage_summary = _usage_summary_for_key(
        owner_key=owner_key,
        program=program,
        payment_id=payment_id,
        entitlement_status=normalized_entitlement,
    )

    if program == "openclaw":
        purchase.openclaw_install_key = masked_key
    elif program == "claude_code":
        purchase.claude_code_install_key = masked_key
    elif program == "hermes":
        purchase.hermes_install_key = masked_key


def _provision_install_keys(
    *,
    owner_key: str,
    purchase_id: str,
    payment_id: str | None,
    payment_status: str | None,
    entitlement_status: str | None,
) -> list[InstallKeyDeliveryView]:
    if not _has_confirmed_paid_entitlement(payment_status, entitlement_status):
        return []

    ik_registry = get_install_key_registry()
    results: list[InstallKeyDeliveryView] = []
    normalized_entitlement = _normalize_entitlement_status(entitlement_status)

    for program in ("openclaw", "claude_code", "hermes"):
        try:
            record = ik_registry.generate_install_key(
                owner_key=owner_key,
                subscription_id=purchase_id,
                program=program,
                label=f"paid-provisioned on purchase {purchase_id}",
                metadata={
                    "purchase_id": purchase_id,
                    "payment_id": payment_id,
                    "payment_status": payment_status or "paid",
                    "entitlement_status": normalized_entitlement,
                    "issued_after_payment": True,
                    "auto_provisioned": True,
                },
            )
        except InstallKeyAlreadyExistsError:
            existing = next(
                (item for item in ik_registry.get_keys_for_owner(owner_key) if item.program == program and (item.active or item.payment_status == "paid")),
                None,
            )
            if existing is None:
                continue
            record = existing
        except Exception:
            logger.exception(
                "install_key_provision_failed",
                extra={
                    "owner_key": owner_key,
                    "program": program,
                    "purchase_id": purchase_id,
                    "payment_id": payment_id,
                },
            )
            continue

        if str(getattr(record, "payment_status", "")).strip().lower() != "paid":
            continue
        if _normalize_entitlement_status(getattr(record, "entitlements_status", None)) != "active":
            continue
        if not bool(getattr(record, "issued_after_payment", False)):
            continue
        if not getattr(record, "masked_key", None):
            continue

        results.append(
            InstallKeyDeliveryView(
                install_key_id=record.key_id,
                masked_key=record.masked_key,
                owner_key=record.owner_key,
                program=record.program,
                payment_id=payment_id,
                entitlement_status=normalized_entitlement,
                usage_summary=_usage_summary_for_key(
                    owner_key=record.owner_key,
                    program=record.program,
                    payment_id=payment_id,
                    entitlement_status=normalized_entitlement,
                ),
            )
        )

    return results


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/packages",
    response_model=BillingPackagesResponse,
)
def list_billing_packages() -> BillingPackagesResponse:
    packages = [_package_to_view(pkg) for pkg in UNIT_PACKAGE_CATALOG.values()]
    return BillingPackagesResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        packages=packages,
        unit_policy=_build_unit_policy(),
    )


@router.post(
    "/packages/purchase",
    response_model=BillingPackagePurchaseResponse,
    status_code=status.HTTP_201_CREATED,
)
def purchase_billing_package(
    payload: BillingPackagePurchaseRequest,
    auth_ctx: AuthContext = Depends(require_auth_context),
) -> BillingPackagePurchaseResponse:
    package_id, package = _require_known_package(payload.package_id)
    unit_amount = int(package["unit_amount"])

    owner_key = _safe_owner_key(auth_ctx, payload.buyer_email)
    purchase_id = _new_purchase_id()

    registry = get_unit_wallet_registry()
    wallet = registry.get_or_create_wallet(owner_key)

    purchase = BillingPackagePurchaseView(
        purchase_id=purchase_id,
        package_id=package_id,
        package_name=str(package["name"]),
        buyer_name=payload.buyer_name.strip(),
        buyer_email=payload.buyer_email,
        owner_key=owner_key,
        price_usd=float(package["price_usd"]),
        granted_units=0,
        token_coverage=unit_amount * TOKEN_CHUNK_SIZE,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
        created_at=_utc_now_iso(),
        payment_status="pending",
        entitlement_status="not_active",
        install_key_id=None,
        masked_key=None,
        program=None,
        usage_summary={},
        openclaw_install_key=None,
        claude_code_install_key=None,
        hermes_install_key=None,
        metadata={
            **payload.metadata,
            "package_id": package_id,
            "buyer_name": payload.buyer_name.strip(),
            "buyer_email": payload.buyer_email,
            "owner_key": owner_key,
            "payment_required": True,
            "payment_status": "pending",
            "fulfillment_status": "pending",
            "install_keys_provisioned": False,
            "units_credited": False,
        },
    )

    with _PURCHASES_LOCK:
        if len(_PURCHASES) >= _PURCHASES_MAX:
            _PURCHASES.pop(0)
        _PURCHASES.append(purchase)

    return BillingPackagePurchaseResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        purchase=purchase,
        wallet=_wallet_view(wallet),
    )


@router.post(
    "/packages/{purchase_id}/fulfill",
    response_model=BillingPackagePurchaseResponse,
)
def fulfill_billing_purchase(
    purchase_id: str,
    payment_id: str | None = None,
    payment_status: str | None = None,
    entitlement_status: str | None = None,
    auth_ctx: AuthContext = Depends(require_auth_context),
) -> BillingPackagePurchaseResponse:
    purchase = next((item for item in _PURCHASES if item.purchase_id == purchase_id), None)
    if purchase is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Purchase not found: {purchase_id!r}",
        )

    _assert_customer_install_key_context(auth_ctx, purchase.owner_key)

    normalized_owner = (purchase.owner_key or "").strip().lower()
    if normalized_owner and normalized_owner in _RESERVED_OWNER_KEYS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "status": "invalid_owner_key",
                "reason": "purchase_checkout_must_not_resolve_to_visible_system_key",
                "owner_key": purchase.owner_key,
            },
        )

    normalized_payment_status = str(payment_status or "").strip().lower() or "pending"
    normalized_entitlement = _normalize_entitlement_status(entitlement_status)
    registry = get_unit_wallet_registry()
    wallet = registry.get_or_create_wallet(purchase.owner_key)

    if not _has_confirmed_paid_entitlement(normalized_payment_status, normalized_entitlement):
        purchase.payment_status = normalized_payment_status if normalized_payment_status != "" else "pending"
        purchase.entitlement_status = normalized_entitlement
        purchase.payment_id = payment_id
        purchase.install_key_id = None
        purchase.masked_key = None
        purchase.program = None
        purchase.usage_summary = {}
        purchase.openclaw_install_key = None
        purchase.claude_code_install_key = None
        purchase.hermes_install_key = None
        purchase.metadata["payment_status"] = purchase.payment_status
        purchase.metadata["fulfillment_status"] = "pending"
        purchase.metadata["install_keys_provisioned"] = False
        return BillingPackagePurchaseResponse(
            status="ok",
            service="IronClaw-Security",
            timestamp=_utc_now_iso(),
            purchase=purchase,
            wallet=_wallet_view(wallet),
        )

    if purchase.payment_status == "paid" and purchase.entitlement_status == "active" and purchase.metadata.get("install_keys_provisioned") is True:
        return BillingPackagePurchaseResponse(
            status="ok",
            service="IronClaw-Security",
            timestamp=_utc_now_iso(),
            purchase=purchase,
            wallet=_wallet_view(wallet),
        )

    package_id, package = _require_known_package(purchase.package_id)
    granted_units = int(package["unit_amount"])
    purchase.payment_id = payment_id or f"pay_{uuid4().hex[:16]}"
    purchase.payment_status = normalized_payment_status
    purchase.entitlement_status = normalized_entitlement
    purchase.granted_units = granted_units

    wallet = registry.credit_units(
        owner_key=purchase.owner_key,
        units=granted_units,
        metadata={
            "purchase_id": purchase.purchase_id,
            "package_id": package_id,
            "payment_id": purchase.payment_id,
            "source": "fulfillment",
        },
    )

    for item in _provision_install_keys(
        owner_key=purchase.owner_key,
        purchase_id=purchase.purchase_id,
        payment_id=purchase.payment_id,
        payment_status=purchase.payment_status,
        entitlement_status=purchase.entitlement_status,
    ):
        if item.program == "openclaw":
            purchase.openclaw_install_key = item.masked_key
        elif item.program == "claude_code":
            purchase.claude_code_install_key = item.masked_key
        elif item.program == "hermes":
            purchase.hermes_install_key = item.masked_key

        purchase.install_key_id = item.install_key_id
        purchase.masked_key = item.masked_key
        purchase.program = item.program
        purchase.payment_id = item.payment_id
        purchase.entitlement_status = item.entitlement_status
        purchase.usage_summary = item.usage_summary
        purchase.metadata["install_keys_provisioned"] = True
        purchase.metadata["payment_status"] = "paid"
        purchase.metadata["fulfillment_status"] = "fulfilled"

    if purchase.install_key_id is None:
        purchase.metadata["install_keys_provisioned"] = False
        purchase.metadata["fulfillment_status"] = "fulfilled_without_key"

    return BillingPackagePurchaseResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        purchase=purchase,
        wallet=_wallet_view(wallet),
    )


@router.post("/wallet/{owner_key}/debit", response_model=WalletDebitResponse)
def debit_wallet(
    owner_key: str,
    payload: WalletDebitRequest,
    auth_ctx: AuthContext = Depends(require_auth_context),
) -> Any:
    _assert_owner_access(auth_ctx, owner_key, action="debit")

    registry = get_unit_wallet_registry()
    try:
        if payload.token_count is not None:
            units_debited = math.ceil(payload.token_count / TOKEN_CHUNK_SIZE)
            wallet = registry.debit_units(
                owner_key=owner_key,
                units=units_debited,
                metadata={
                    "token_count": payload.token_count,
                    "tokens_per_unit": TOKEN_CHUNK_SIZE,
                    "reason": payload.reason,
                },
            )
            return WalletDebitResponse(
                status="ok",
                owner_key=owner_key,
                units_debited=units_debited,
                token_count=payload.token_count,
                wallet=_wallet_view(wallet),
            )
        else:
            wallet = registry.debit_units(
                owner_key=owner_key,
                units=payload.units,  # type: ignore[arg-type]
                metadata={"reason": payload.reason},
            )
            return WalletDebitResponse(
                status="ok",
                owner_key=owner_key,
                units_debited=payload.units,  # type: ignore[arg-type]
                token_count=None,
                wallet=_wallet_view(wallet),
            )
    except InsufficientUnitsError as exc:
        return JSONResponse(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            content={
                "detail": {
                    "status": "insufficient_units",
                    "owner_key": exc.owner_key or owner_key,
                    "have": exc.have,
                    "need": exc.need,
                },
            },
        )


@router.post("/wallet/{owner_key}/refund", response_model=WalletRefundResponse)
def refund_wallet(
    owner_key: str,
    payload: WalletRefundRequest,
    auth_ctx: AuthContext = Depends(require_auth_context),
) -> WalletRefundResponse:
    _assert_owner_access(auth_ctx, owner_key, action="refund")

    registry = get_unit_wallet_registry()
    wallet = registry.refund_units(
        owner_key=owner_key,
        units=payload.units,
        metadata={"reason": payload.reason},
    )
    return WalletRefundResponse(
        status="ok",
        owner_key=owner_key,
        units_refunded=payload.units,
        wallet=_wallet_view(wallet),
    )


@router.get(
    "/wallet/{owner_key}",
    response_model=WalletGetResponse,
)
def get_wallet(
    owner_key: str,
    auth_ctx: AuthContext = Depends(require_auth_context),
) -> WalletGetResponse:
    _assert_owner_access(auth_ctx, owner_key, action="read_wallet")
    registry = get_unit_wallet_registry()
    wallet = registry.get_or_create_wallet(owner_key=owner_key)
    return WalletGetResponse(status="ok", wallet=_wallet_view(wallet))


@router.get(
    "/ledger",
    response_model=LedgerResponse,
)
def get_ledger(
    auth_ctx: AuthContext = Depends(require_auth_context),
    owner_key: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> LedgerResponse:
    if owner_key is not None:
        is_org_wallet = owner_key.startswith("ic_org_")
        if is_org_wallet:
            if auth_ctx.key_type != "org" or not getattr(auth_ctx, "org_id", None):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "status": "forbidden",
                        "reason": "org_wallet_requires_org_key",
                        "owner_key": owner_key,
                        "action": "read_ledger",
                    },
                )
            expected = f"ic_org_{auth_ctx.org_id}"
            if owner_key != expected:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "status": "forbidden",
                        "reason": "org_id_mismatch",
                        "owner_key": owner_key,
                        "action": "read_ledger",
                    },
                )
        else:
            if auth_ctx.key_type == "org":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "status": "forbidden",
                        "reason": "org_key_cannot_access_personal_wallet",
                        "owner_key": owner_key,
                        "action": "read_ledger",
                    },
                )
    else:
        resolved = resolve_billing_owner(auth_ctx, "")
        owner_key = resolved if resolved else None

    registry = get_unit_wallet_registry()
    entries = registry.list_ledger_entries(owner_key=owner_key, limit=limit)
    serialized = [
        {
            "entry_id": e.entry_id,
            "wallet_id": e.wallet_id,
            "owner_key": e.owner_key,
            "entry_type": e.entry_type,
            "units": e.units,
            "balance_after": e.balance_after,
            "created_at": e.created_at.isoformat().replace("+00:00", "Z"),
            "metadata": e.metadata,
        }
        for e in entries
    ]
    return LedgerResponse(
        status="ok",
        owner_key=owner_key,
        limit=limit,
        entries=serialized,
    )
