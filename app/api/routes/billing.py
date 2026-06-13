from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.core.unit_wallet import (
    TOKEN_CHUNK_SIZE,
    UNIT_PACKAGE_CATALOG,
    InsufficientUnitsError,
    get_unit_wallet_registry,
    is_org_key,
    units_required_for_tokens,
)

router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(require_api_key)],
)

_PURCHASES_MAX_SIZE: int = 1_000

_BILLING_PACKAGE_FALLBACK: dict[str, dict[str, Any]] = {
    "pkg_5000": {
        "package_id": "pkg_5000",
        "name": "Starter",
        "price_usd": 20.00,
        "included_units": 5_000,
        "display_label": "5,000 units — $20.00",
        "description": ("Prepaid protection units for individual builders who want guarded " "prompt handling, tool-call review, source inspection, and safe response release."),
    },
    "pkg_25000": {
        "package_id": "pkg_25000",
        "name": "Team",
        "price_usd": 90.00,
        "included_units": 25_000,
        "display_label": "25,000 units — $90.00",
        "description": ("Prepaid protection units for teams running higher volumes of AI-assisted " "development, research, and guarded agent workflows."),
    },
    "pkg_60000": {
        "package_id": "pkg_60000",
        "name": "Enterprise",
        "price_usd": 180.00,
        "included_units": 60_000,
        "display_label": "60,000 units — $180.00",
        "description": ("Prepaid protection units for organizations protecting large-scale agent " "operations, sensitive workflows, and high-frequency prompt activity."),
    },
}


def _derive_package_catalog() -> dict[str, dict[str, Any]]:
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


PACKAGE_CATALOG: dict[str, dict[str, Any]] = _derive_package_catalog()


# ---------------------------------------------------------------------------
# Response / request schemas
# ---------------------------------------------------------------------------


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
    buyer_email: str = Field(min_length=3, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPackagePurchaseView(BaseModel):
    purchase_id: str
    package_id: str
    package_name: str
    buyer_name: str
    buyer_email: str
    price_usd: float
    granted_units: int
    token_coverage: int
    tokens_per_unit: int
    created_at: str
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


# ---------------------------------------------------------------------------
# In-process purchase log
# ---------------------------------------------------------------------------

_PURCHASES: list[BillingPackagePurchaseView] = []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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


def _require_known_package(package_id: str) -> tuple[str, dict[str, Any]]:
    normalized = package_id.strip().lower()
    package = PACKAGE_CATALOG.get(normalized)
    if package is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(f"Unknown billing package: {package_id!r}. " f"Valid IDs: {sorted(PACKAGE_CATALOG)}"),
        )
    return normalized, package


def _resolve_wallet_owner_key(buyer_email: str) -> str:
    """Resolve the wallet owner_key from buyer_email.

    Org purchases: buyer_email is an ic_org_ key — the wallet owner_key is
    the org key itself, shared across all team members.

    Personal purchases: buyer_email is a regular email — the wallet owner_key
    is the normalized email, scoped to the individual.

    Normalization (strip + lower) is applied here once so that credit_units
    and all downstream registry operations receive a consistent key.
    """
    normalized = buyer_email.strip().lower()
    # Org keys pass through as-is — their ic_org_ prefix IS the owner_key.
    # Personal emails also pass through as-is — the email IS the owner_key.
    # Both cases are the same code path; the explicit branch documents intent
    # and is the extension point for future auth-context-driven org routing.
    if is_org_key(normalized):
        return normalized
    return normalized


def _build_unit_policy() -> UnitPolicyView:
    return UnitPolicyView(
        unit_definition=(f"1 protection unit = 1 IronClaw inspection window covering up to " f"{TOKEN_CHUNK_SIZE:,} tokens. Requests exceeding that boundary " f"consume one additional unit per {TOKEN_CHUNK_SIZE:,}-token chunk. " f"Scans are unlimited — units auto-deduct with no ceiling."),
        token_chunk_size=TOKEN_CHUNK_SIZE,
        delivery_model="All packages are prepaid unit bundles with no recurring subscription requirement.",
        buyer_positioning=("Customers are buying protected AI usage, not raw API calls. Each unit funds layered " "security checks around prompts, tool activity, returned content, and release decisions."),
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
            f"Each unit covers up to {TOKEN_CHUNK_SIZE:,} tokens; larger payloads automatically consume the correct number of units via ceiling division.",
            "Scans have no upper token ceiling — units simply deduct in 25,000-token chunks for any payload size.",
        ],
    )


def _wallet_to_view(wallet: Any) -> WalletBalanceView:
    return WalletBalanceView(
        wallet_id=wallet.wallet_id,
        owner_key=wallet.owner_key,
        balance_units=wallet.balance_units,
        total_purchased_units=wallet.total_purchased_units,
        total_consumed_units=wallet.total_consumed_units,
        total_refunded_units=getattr(wallet, "total_refunded_units", 0),
        updated_at=wallet.updated_at.isoformat().replace("+00:00", "Z"),
        metadata=wallet.metadata,
    )


def _ledger_entry_to_view(entry: Any) -> WalletLedgerEntryView:
    return WalletLedgerEntryView(
        entry_id=entry.entry_id,
        wallet_id=entry.wallet_id,
        owner_key=entry.owner_key,
        entry_type=entry.entry_type,
        units=entry.units,
        balance_after=entry.balance_after,
        created_at=entry.created_at.isoformat().replace("+00:00", "Z"),
        metadata=entry.metadata,
    )


def _build_insufficient_units_detail(exc: InsufficientUnitsError) -> dict[str, Any]:
    """Build the structured 402 detail body directly from exception fields."""
    return {
        "status": "insufficient_units",
        "error": str(exc),
        "owner_key": exc.owner_key,
        "have": exc.have,
        "need": exc.need,
        "tokens_per_unit": TOKEN_CHUNK_SIZE,
        "timestamp": _utc_now_iso(),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/packages", response_model=BillingPackagesResponse)
def list_billing_packages() -> BillingPackagesResponse:
    packages = [_package_to_view(pkg_id, pkg) for pkg_id, pkg in PACKAGE_CATALOG.items()]
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
) -> BillingPackagePurchaseResponse:
    package_id, package = _require_known_package(payload.package_id)
    granted_units = int(package["included_units"])
    token_coverage = granted_units * TOKEN_CHUNK_SIZE

    # Normalize buyer_email once; it is stored on the purchase record as-is.
    normalized_email = payload.buyer_email.strip().lower()

    # Resolve the wallet owner_key explicitly.
    # Org purchases (ic_org_ prefix): pool units under the shared org wallet.
    # Personal purchases: scope to the individual email wallet.
    # _resolve_wallet_owner_key documents and enforces this routing decision
    # rather than relying on incidental pass-through of buyer_email.
    wallet_owner_key = _resolve_wallet_owner_key(normalized_email)

    purchase = BillingPackagePurchaseView(
        purchase_id=_new_purchase_id(),
        package_id=package_id,
        package_name=str(package["name"]),
        buyer_name=payload.buyer_name.strip(),
        buyer_email=normalized_email,
        price_usd=float(package["price_usd"]),
        granted_units=granted_units,
        token_coverage=token_coverage,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
        created_at=_utc_now_iso(),
        metadata=payload.metadata,
    )

    global _PURCHASES
    _PURCHASES.append(purchase)
    if len(_PURCHASES) > _PURCHASES_MAX_SIZE:
        _PURCHASES = _PURCHASES[-_PURCHASES_MAX_SIZE:]

    wallet_registry = get_unit_wallet_registry()

    try:
        wallet = wallet_registry.credit_units(
            owner_key=wallet_owner_key,
            units=granted_units,
            metadata={
                "source": "billing_package_purchase",
                "purchase_id": purchase.purchase_id,
                "package_id": package_id,
                "package_name": purchase.package_name,
                "buyer_name": purchase.buyer_name,
                "buyer_email": normalized_email,
                "wallet_owner_key": wallet_owner_key,
                "is_org_purchase": is_org_key(wallet_owner_key),
                "token_coverage": token_coverage,
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
                **payload.metadata,
            },
        )
    except InsufficientUnitsError as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=_build_insufficient_units_detail(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Wallet credit failed: {exc}",
        ) from exc

    return BillingPackagePurchaseResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        purchase=purchase,
        wallet=_wallet_to_view(wallet),
    )


@router.get("/wallet/{owner_key}", response_model=BillingWalletBalanceResponse)
def get_billing_wallet_balance(owner_key: str) -> BillingWalletBalanceResponse:
    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.get_wallet(owner_key)

    if wallet is None:
        wallet = wallet_registry.get_or_create_wallet(owner_key=owner_key)

    return BillingWalletBalanceResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        wallet=_wallet_to_view(wallet),
    )


@router.post(
    "/wallet/{owner_key}/debit",
    response_model=WalletDebitResponse,
    status_code=status.HTTP_200_OK,
)
def debit_billing_wallet(
    owner_key: str,
    payload: WalletDebitRequest,
) -> WalletDebitResponse:
    """
    Debit protection units from a wallet.

    Supply either:
    - ``units``: an exact unit count to debit, OR
    - ``token_count``: a raw token count; units are computed via ceiling division
      against TOKEN_CHUNK_SIZE (25,000). Any partial chunk consumes a full unit.

    Returns 402 Payment Required with structured {have, need, owner_key} body
    if the wallet has insufficient balance.
    """
    if payload.units is None and payload.token_count is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide either 'units' or 'token_count'.",
        )

    wallet_registry = get_unit_wallet_registry()
    normalized_owner = owner_key.strip().lower()

    if payload.token_count is not None:
        units_to_debit = units_required_for_tokens(payload.token_count)
    else:
        units_to_debit = payload.units  # type: ignore[assignment]

    debit_metadata: dict[str, Any] = {
        "reason": payload.reason,
        "tokens_per_unit": TOKEN_CHUNK_SIZE,
        **({("token_count"): payload.token_count} if payload.token_count is not None else {}),
        **({("reference_id"): payload.reference_id} if payload.reference_id else {}),
        **payload.metadata,
    }

    try:
        wallet = wallet_registry.debit_units(
            owner_key=normalized_owner,
            units=units_to_debit,
            metadata=debit_metadata,
        )
    except InsufficientUnitsError as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=_build_insufficient_units_detail(exc),
        ) from exc

    return WalletDebitResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=normalized_owner,
        units_debited=units_to_debit,
        token_count=payload.token_count,
        wallet=_wallet_to_view(wallet),
    )


@router.post(
    "/wallet/{owner_key}/refund",
    response_model=WalletRefundResponse,
    status_code=status.HTTP_200_OK,
)
def refund_billing_wallet(
    owner_key: str,
    payload: WalletRefundRequest,
) -> WalletRefundResponse:
    """
    Refund protection units back to a wallet.
    Tracked separately from purchases in the ledger (entry_type=refund).
    """
    wallet_registry = get_unit_wallet_registry()
    normalized_owner = owner_key.strip().lower()

    refund_metadata: dict[str, Any] = {
        "reason": payload.reason,
        "tokens_per_unit": TOKEN_CHUNK_SIZE,
        **({("reference_id"): payload.reference_id} if payload.reference_id else {}),
        **payload.metadata,
    }

    try:
        wallet = wallet_registry.refund_units(
            owner_key=normalized_owner,
            units=payload.units,
            metadata=refund_metadata,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Wallet refund failed: {exc}",
        ) from exc

    return WalletRefundResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=normalized_owner,
        units_refunded=payload.units,
        wallet=_wallet_to_view(wallet),
    )


@router.get("/ledger", response_model=BillingLedgerResponse)
def list_billing_ledger(
    owner_key: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> BillingLedgerResponse:
    wallet_registry = get_unit_wallet_registry()
    normalized_owner = owner_key.strip().lower() if owner_key else None
    entries = wallet_registry.list_ledger_entries(owner_key=normalized_owner, limit=limit)

    return BillingLedgerResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=normalized_owner,
        limit=limit,
        entries=[_ledger_entry_to_view(entry) for entry in entries],
    )
