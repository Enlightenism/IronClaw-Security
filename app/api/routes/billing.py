from __future__ import annotations

from datetime import UTC, datetime
import logging
import re
from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from app.core.auth import AuthContext, get_auth_context, require_auth_context
from app.core.billing import resolve_billing_owner
from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    get_install_key_registry,
)
from app.core.unit_wallet import (
    ORG_KEY_PREFIX,
    TOKEN_CHUNK_SIZE,
    get_unit_wallet_registry,
    units_required_for_tokens,
)

logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(require_auth_context)],
)


_PURCHASES_MAX_SIZE: int = 1_000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ORG_KEY_RE = re.compile(r"^ic_org_")


_BILLING_PACKAGE_FALLBACK: dict[str, dict[str, Any]] = {
    "pkg_5000": {
        "package_id": "pkg_5000",
        "name": "Starter",
        "price_usd": 20.00,
        "included_units": 5_000,
        "display_label": "5,000 units — $20.00",
        "description": ("Prepaid protection units for individual builders who want guarded prompt handling, tool-call review, source inspection, and safe response release."),
    },
    "pkg_25000": {
        "package_id": "pkg_25000",
        "name": "Team",
        "price_usd": 90.00,
        "included_units": 25_000,
        "display_label": "25,000 units — $90.00",
        "description": ("Prepaid protection units for teams running higher volumes of AI-assisted development, research, and guarded agent workflows."),
    },
    "pkg_60000": {
        "package_id": "pkg_60000",
        "name": "Enterprise",
        "price_usd": 180.00,
        "included_units": 60_000,
        "display_label": "60,000 units — $180.00",
        "description": ("Prepaid protection units for organizations protecting large-scale agent operations, sensitive workflows, and high-frequency prompt activity."),
    },
}


def _derive_package_catalog() -> dict[str, dict[str, Any]]:
    try:
        from app.core.unit_wallet import UNIT_PACKAGE_CATALOG  # noqa: PLC0415

        required_ids = set(_BILLING_PACKAGE_FALLBACK)
        catalog: dict[str, dict[str, Any]] = {}
        for pkg_id in required_ids:
            source = UNIT_PACKAGE_CATALOG.get(pkg_id)
            if source is not None:
                catalog[pkg_id] = {
                    "package_id": pkg_id,
                    "name": str(source["name"]),
                    "price_usd": float(source["price_usd"]),
                    "included_units": int(source["unit_amount"]),
                    "display_label": str(source.get("display_label", "")),
                    "description": str(source.get("description", "")),
                }
            else:
                catalog[pkg_id] = _BILLING_PACKAGE_FALLBACK[pkg_id]
        return catalog
    except Exception:
        logger.exception("billing: failed to derive PACKAGE_CATALOG from unit_wallet; using hardcoded fallback")
        return dict(_BILLING_PACKAGE_FALLBACK)


PACKAGE_CATALOG: dict[str, dict[str, Any]] = _derive_package_catalog()


class BillingPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    display_label: str
    description: str
    token_coverage: int
    tokens_per_unit: int


class ProtectionValueView(BaseModel):
    title: str
    detail: str


class UnitPolicyView(BaseModel):
    unit_definition: str
    token_chunk_size: int
    delivery_model: str
    buyer_positioning: str
    protection_layers: list[ProtectionValueView] = Field(default_factory=list)
    market_context: list[str] = Field(default_factory=list)


class BillingPackagePurchaseRequest(BaseModel):
    package_id: str = Field(min_length=1, max_length=120)
    buyer_name: str = Field(min_length=1, max_length=120)
    buyer_email: str = Field(min_length=3, max_length=254)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("buyer_email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        value = v.strip()
        if _ORG_KEY_RE.match(value):
            return value
        normalized = value.lower()
        if not _EMAIL_RE.match(normalized):
            raise ValueError("Invalid email address")
        return normalized


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
    openclaw_install_key: str | None = None
    claude_code_install_key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletBalanceView(BaseModel):
    wallet_id: str
    owner_key: str
    balance_units: int
    total_purchased_units: int
    total_consumed_units: int
    total_refunded_units: int
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletLedgerEntryView(BaseModel):
    entry_id: str
    wallet_id: str
    owner_key: str
    entry_type: str
    units: int
    balance_after: int
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPackagesResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    packages: list[BillingPackageView] = Field(default_factory=list)
    unit_policy: UnitPolicyView


class BillingPackagePurchaseResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    purchase: BillingPackagePurchaseView
    wallet: WalletBalanceView


class BillingWalletBalanceResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    wallet: WalletBalanceView


class BillingLedgerResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str | None = None
    limit: int
    entries: list[WalletLedgerEntryView] = Field(default_factory=list)


class WalletDebitRequest(BaseModel):
    units: int | None = Field(default=None, ge=1)
    token_count: int | None = Field(default=None, ge=1)
    reason: str = Field(default="api_debit", min_length=1, max_length=120)
    reference_id: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletDebitResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str
    units_debited: int
    token_count: int | None
    wallet: WalletBalanceView


class WalletRefundRequest(BaseModel):
    units: int = Field(ge=1)
    reason: str = Field(default="api_refund", min_length=1, max_length=120)
    reference_id: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletRefundResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str
    units_refunded: int
    wallet: WalletBalanceView


class InsufficientUnitsErrorResponse(BaseModel):
    status: str
    error: str
    owner_key: str
    have: int
    need: int
    tokens_per_unit: int
    timestamp: str


_PURCHASES: list[BillingPackagePurchaseView] = []


def _append_purchase(purchase: BillingPackagePurchaseView) -> None:
    _PURCHASES.append(purchase)
    if len(_PURCHASES) > _PURCHASES_MAX_SIZE:
        del _PURCHASES[: len(_PURCHASES) - _PURCHASES_MAX_SIZE]


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _new_purchase_id() -> str:
    return f"purch_{uuid.uuid4().hex[:16]}"


def _package_to_view(pkg_id: str, pkg: dict[str, Any]) -> BillingPackageView:
    included_units = int(pkg["included_units"])
    token_coverage = included_units * TOKEN_CHUNK_SIZE
    return BillingPackageView(
        package_id=pkg_id,
        name=str(pkg["name"]),
        price_usd=float(pkg["price_usd"]),
        included_units=included_units,
        display_label=str(pkg.get("display_label", "")),
        description=str(pkg.get("description", "")),
        token_coverage=token_coverage,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
    )


def _wallet_to_view(wallet: Any) -> WalletBalanceView:
    updated_at = getattr(wallet, "updated_at", None)
    if hasattr(updated_at, "isoformat"):
        updated_at_value = updated_at.isoformat().replace("+00:00", "Z")
    else:
        updated_at_value = _utc_now_iso()

    metadata = getattr(wallet, "metadata", {}) or {}
    if not isinstance(metadata, dict):
        metadata = {}

    return WalletBalanceView(
        wallet_id=str(wallet.wallet_id),
        owner_key=str(wallet.owner_key),
        balance_units=int(wallet.balance_units),
        total_purchased_units=int(wallet.total_purchased_units),
        total_consumed_units=int(wallet.total_consumed_units),
        total_refunded_units=int(wallet.total_refunded_units),
        updated_at=updated_at_value,
        metadata=metadata,
    )


def _assert_owner_access(owner_key: str, auth_ctx: AuthContext) -> None:
    is_org_wallet = owner_key.startswith(ORG_KEY_PREFIX)
    caller_key_type = getattr(auth_ctx, "key_type", None)
    caller_org_id = getattr(auth_ctx, "org_id", None)

    if is_org_wallet:
        if caller_key_type != "org" or caller_org_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "org_wallet_requires_org_key",
                    "detail": "This wallet requires an org key.",
                },
            )
        expected_owner = f"{ORG_KEY_PREFIX}{caller_org_id}"
        if owner_key != expected_owner:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "org_key_mismatch",
                    "detail": f"Org key does not match wallet owner: expected {expected_owner}, got {owner_key}",
                },
            )
    else:
        if caller_key_type == "org" or caller_org_id is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "org_key_cannot_access_personal_wallet",
                    "detail": "Org keys may not access personal wallets.",
                },
            )
        caller_id = getattr(auth_ctx, "principal_id", None)
        if caller_id and owner_key != caller_id.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "principal_mismatch",
                    "detail": "Access to this wallet is not permitted.",
                },
            )


def _require_existing_wallet(registry: Any, owner_key: str) -> Any:
    wallet = registry.get_wallet(owner_key)
    if wallet is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No wallet found for owner_key: {owner_key!r}",
        )
    return wallet


def _get_or_zero_wallet(registry: Any, owner_key: str) -> Any:
    wallet = registry.get_wallet(owner_key)
    if wallet is None:

        class _ZeroWallet:
            balance_units = 0

        return _ZeroWallet()
    return wallet


def _provision_install_keys(
    owner_key: str,
    purchase_id: str,
) -> tuple[str | None, str | None]:
    registry = get_install_key_registry()
    openclaw_key: str | None = None
    claude_key: str | None = None

    for program, slot in (("openclaw", "openclaw"), ("claude_code", "claude_code")):
        try:
            record = registry.generate_install_key(
                owner_key=owner_key,
                subscription_id=purchase_id,
                program=program,  # type: ignore[arg-type]
                label=f"auto-provisioned on purchase {purchase_id}",
                metadata={"purchase_id": purchase_id, "auto_provisioned": True},
            )
            if slot == "openclaw":
                openclaw_key = record.raw_key
            else:
                claude_key = record.raw_key
        except InstallKeyAlreadyExistsError:
            logger.info(
                "billing: install key already exists for owner=%r program=%r — skipping",
                owner_key,
                program,
            )
        except Exception:
            logger.exception(
                "billing: failed to provision install key for owner=%r program=%r",
                owner_key,
                program,
            )

    return openclaw_key, claude_key


@router.get(
    "/packages",
    response_model=BillingPackagesResponse,
    summary="List available protection unit packages",
)
def get_packages() -> BillingPackagesResponse:
    packages = [_package_to_view(pid, pkg) for pid, pkg in PACKAGE_CATALOG.items()]
    unit_policy = UnitPolicyView(
        unit_definition=f"One protection unit covers {TOKEN_CHUNK_SIZE:,} tokens of inspected AI interaction across all active guardrails.",
        token_chunk_size=TOKEN_CHUNK_SIZE,
        delivery_model="prepaid",
        buyer_positioning="Units are consumed as AI actions pass through IronClaw guardrails. Unused units roll over until your balance is exhausted.",
        protection_layers=[
            ProtectionValueView(
                title="Prompt Injection Guard",
                detail="Detects and blocks adversarial instructions embedded in user input.",
            ),
            ProtectionValueView(
                title="Tool Call Enforcement",
                detail="Validates every tool invocation against your active policy set.",
            ),
            ProtectionValueView(
                title="Data Leakage Prevention",
                detail="Inspects outbound content for sensitive patterns before release.",
            ),
            ProtectionValueView(
                title="Trust Boundary Enforcement",
                detail="Maintains separation between agent tiers and external systems.",
            ),
        ],
        market_context=[
            "Enterprise AI security starts at the token layer.",
            "Every guardrail inspection is metered, auditable, and reproducible.",
            "IronClaw units give your team a shared enforcement budget with full telemetry.",
        ],
    )
    return BillingPackagesResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        packages=packages,
        unit_policy=unit_policy,
    )


@router.post(
    "/purchase",
    response_model=BillingPackagePurchaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Purchase a protection unit package",
)
def purchase_package(
    body: BillingPackagePurchaseRequest,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> BillingPackagePurchaseResponse:
    pkg = PACKAGE_CATALOG.get(body.package_id)
    if pkg is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown package_id: {body.package_id!r}",
        )

    buyer_email_normalized = body.buyer_email
    owner_key = resolve_billing_owner(auth_ctx, buyer_email_normalized)
    registry = get_unit_wallet_registry()

    purchase_id = _new_purchase_id()

    wallet = registry.credit_units(
        owner_key=owner_key,
        units=int(pkg["included_units"]),
        metadata={
            "package_id": body.package_id,
            "purchase_id": purchase_id,
            "buyer_name": body.buyer_name,
            "buyer_email": buyer_email_normalized,
            **body.metadata,
        },
    )

    openclaw_key, claude_key = _provision_install_keys(owner_key, purchase_id)

    purchase = BillingPackagePurchaseView(
        purchase_id=purchase_id,
        package_id=body.package_id,
        package_name=str(pkg["name"]),
        buyer_name=body.buyer_name,
        buyer_email=buyer_email_normalized,
        owner_key=owner_key,
        price_usd=float(pkg["price_usd"]),
        granted_units=int(pkg["included_units"]),
        token_coverage=int(pkg["included_units"]) * TOKEN_CHUNK_SIZE,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
        created_at=_utc_now_iso(),
        openclaw_install_key=openclaw_key,
        claude_code_install_key=claude_key,
        metadata=body.metadata,
    )
    _append_purchase(purchase)

    return BillingPackagePurchaseResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        purchase=purchase,
        wallet=_wallet_to_view(wallet),
    )


@router.get(
    "/purchases",
    summary="List recent in-process purchase records",
)
def list_purchases(
    limit: int = Query(default=50, ge=1, le=_PURCHASES_MAX_SIZE),
) -> dict[str, Any]:
    records = _PURCHASES[-limit:]
    return {
        "status": "ok",
        "service": "IronClaw-Security",
        "timestamp": _utc_now_iso(),
        "count": len(records),
        "purchases": [p.model_dump(mode="json") for p in records],
    }


@router.get(
    "/wallet/{owner_key}",
    response_model=BillingWalletBalanceResponse,
    summary="Get wallet balance for an owner key",
)
def get_wallet_balance(
    owner_key: str,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> BillingWalletBalanceResponse:
    _assert_owner_access(owner_key, auth_ctx)
    registry = get_unit_wallet_registry()
    wallet = _require_existing_wallet(registry, owner_key)
    return BillingWalletBalanceResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        wallet=_wallet_to_view(wallet),
    )


@router.get(
    "/wallet/{owner_key}/ledger",
    response_model=BillingLedgerResponse,
    summary="Get ledger entries for a wallet",
)
def get_wallet_ledger(
    owner_key: str,
    limit: int = Query(default=50, ge=1, le=500),
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> BillingLedgerResponse:
    _assert_owner_access(owner_key, auth_ctx)
    registry = get_unit_wallet_registry()
    try:
        entries = registry.list_ledger_entries(owner_key=owner_key, limit=limit)
    except Exception:
        logger.exception("billing: list_ledger_entries failed for owner_key=%r", owner_key)
        entries = []
    entry_views = [
        WalletLedgerEntryView(
            entry_id=str(e.entry_id),
            wallet_id=str(e.wallet_id),
            owner_key=str(e.owner_key),
            entry_type=str(e.entry_type),
            units=int(e.units),
            balance_after=int(e.balance_after),
            created_at=str(e.created_at),
            metadata=dict(e.metadata) if e.metadata else {},
        )
        for e in entries
    ]
    return BillingLedgerResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        limit=limit,
        entries=entry_views,
    )


@router.post(
    "/wallet/{owner_key}/debit",
    response_model=WalletDebitResponse,
    summary="Debit units from a wallet",
)
def debit_wallet(
    owner_key: str,
    body: WalletDebitRequest,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> WalletDebitResponse:
    _assert_owner_access(owner_key, auth_ctx)

    if body.units is None and body.token_count is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Provide either 'units' or 'token_count'.",
        )

    if body.units is not None:
        units_to_debit = body.units
    else:
        units_to_debit = units_required_for_tokens(body.token_count)  # type: ignore[arg-type]

    registry = get_unit_wallet_registry()
    wallet = _get_or_zero_wallet(registry, owner_key)

    if wallet.balance_units < units_to_debit:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "status": "insufficient_units",
                "error": "Insufficient protection units.",
                "owner_key": owner_key,
                "have": wallet.balance_units,
                "need": units_to_debit,
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
                "timestamp": _utc_now_iso(),
            },
        )

    updated_wallet = registry.debit_units(
        owner_key=owner_key,
        units=units_to_debit,
        metadata={
            "reason": body.reason,
            "reference_id": body.reference_id,
            **body.metadata,
        },
    )
    return WalletDebitResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        units_debited=units_to_debit,
        token_count=body.token_count,
        wallet=_wallet_to_view(updated_wallet),
    )


@router.post(
    "/wallet/{owner_key}/refund",
    response_model=WalletRefundResponse,
    summary="Refund units to a wallet",
)
def refund_wallet(
    owner_key: str,
    body: WalletRefundRequest,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> WalletRefundResponse:
    _assert_owner_access(owner_key, auth_ctx)
    registry = get_unit_wallet_registry()
    _require_existing_wallet(registry, owner_key)
    updated_wallet = registry.refund_units(
        owner_key=owner_key,
        units=body.units,
        metadata={
            "reason": body.reason,
            "reference_id": body.reference_id,
            **body.metadata,
        },
    )
    return WalletRefundResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        units_refunded=body.units,
        wallet=_wallet_to_view(updated_wallet),
    )
