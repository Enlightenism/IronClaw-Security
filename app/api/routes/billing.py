from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.core.unit_wallet import UNIT_PACKAGE_CATALOG, get_unit_wallet_registry

router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(require_api_key)],
)

# ---------------------------------------------------------------------------
# Token-to-unit coverage constants
# Each protection unit covers one inspection window of up to TOKEN_CHUNK_SIZE
# tokens. Requests exceeding that boundary consume one additional unit per
# additional chunk (ceiling division).
# ---------------------------------------------------------------------------

TOKEN_CHUNK_SIZE: int = 25_000  # tokens covered per unit


def units_required_for_tokens(token_count: int) -> int:
    """Return the number of protection units required to cover *token_count* tokens.

    Coverage model: 1 unit = 1 inspection window of up to TOKEN_CHUNK_SIZE tokens.
    Any partial chunk above the boundary consumes a full additional unit.

    Examples:
        1 token       → 1 unit
        25_000 tokens → 1 unit
        25_001 tokens → 2 units
        50_000 tokens → 2 units
        50_001 tokens → 3 units
    """
    if token_count <= 0:
        return 0
    return math.ceil(token_count / TOKEN_CHUNK_SIZE)


# ---------------------------------------------------------------------------
# Canonical package catalog — single source of truth is UNIT_PACKAGE_CATALOG
# from unit_wallet.py.  The local PACKAGE_CATALOG below is derived from it
# at import time and must never be maintained separately.
#
# Package IDs and pricing (authoritative):
#   pkg_5000   — Starter    —  5,000 units — $20.00
#   pkg_25000  — Team       — 25,000 units — $90.00
#   pkg_60000  — Enterprise — 60,000 units — $180.00
# ---------------------------------------------------------------------------

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
    """Build the billing-route package catalog from UNIT_PACKAGE_CATALOG.

    Maps the catalog's ``unit_amount`` key to ``included_units`` for API
    response consistency and normalises the shape expected by this module.
    Falls back to hardcoded values if the catalog is missing any required ID.
    """
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


# ---------------------------------------------------------------------------
# In-process purchase log (audit trail supplement — not a database substitute)
# ---------------------------------------------------------------------------

_PURCHASES: list[BillingPackagePurchaseView] = []

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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


def _build_unit_policy() -> UnitPolicyView:
    return UnitPolicyView(
        unit_definition=(f"1 protection unit = 1 IronClaw inspection window covering up to " f"{TOKEN_CHUNK_SIZE:,} tokens. Requests exceeding that boundary " f"consume one additional unit per {TOKEN_CHUNK_SIZE:,}-token chunk."),
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

    purchase = BillingPackagePurchaseView(
        purchase_id=f"purch_{len(_PURCHASES) + 1}",
        package_id=package_id,
        package_name=str(package["name"]),
        buyer_name=payload.buyer_name.strip(),
        buyer_email=payload.buyer_email.strip().lower(),
        price_usd=float(package["price_usd"]),
        granted_units=granted_units,
        token_coverage=token_coverage,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
        created_at=_utc_now_iso(),
        metadata=payload.metadata,
    )
    _PURCHASES.append(purchase)

    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.credit_units(
        owner_key=purchase.buyer_email,
        units=granted_units,
        metadata={
            "source": "billing_package_purchase",
            "purchase_id": purchase.purchase_id,
            "package_id": package_id,
            "package_name": purchase.package_name,
            "buyer_name": purchase.buyer_name,
            "token_coverage": token_coverage,
            "tokens_per_unit": TOKEN_CHUNK_SIZE,
            **payload.metadata,
        },
    )

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
