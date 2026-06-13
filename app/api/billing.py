from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator
from pydantic_core import PydanticCustomError

from app.core.auth import AuthContext, require_auth_context
from app.core.billing import resolve_billing_owner
from app.core.unit_wallet import (
    TOKEN_CHUNK_SIZE,
    UNIT_PACKAGE_CATALOG,
    RegistryUnitWallet,
    get_unit_wallet_registry,
)

router = APIRouter(
    prefix="/billing",
    tags=["billing"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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
    owner_key: str
    price_usd: float
    granted_units: int
    token_coverage: int
    tokens_per_unit: int
    created_at: str
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
        buyer_positioning=("Customers are buying protected AI usage, not raw API calls. Each unit funds layered " "security checks around prompts, tool activity, returned content, and release decisions."),
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
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/packages",
    response_model=BillingPackagesResponse,
    dependencies=[Depends(require_auth_context)],
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
    purchase_id = f"purch_{len(_PURCHASES) + 1}"

    # Org-keyed callers pool units under the org wallet; personal callers
    # get their own wallet scoped to buyer_email.
    owner_key = resolve_billing_owner(auth_ctx, payload.buyer_email)

    purchase = BillingPackagePurchaseView(
        purchase_id=purchase_id,
        package_id=package_id,
        package_name=str(package["name"]),
        buyer_name=payload.buyer_name.strip(),
        buyer_email=payload.buyer_email.strip().lower(),
        owner_key=owner_key,
        price_usd=float(package["price_usd"]),
        granted_units=unit_amount,
        token_coverage=unit_amount * TOKEN_CHUNK_SIZE,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
        created_at=_utc_now_iso(),
        metadata=payload.metadata,
    )
    _PURCHASES.append(purchase)

    registry = get_unit_wallet_registry()
    wallet = registry.credit_units(
        owner_key=owner_key,
        units=unit_amount,
        metadata={"purchase_id": purchase_id, "package_id": package_id},
    )

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
) -> WalletDebitResponse:
    # Org-keyed callers override whatever path param was supplied so that
    # all team members debit from the shared org wallet.
    resolved_owner = resolve_billing_owner(auth_ctx, owner_key)

    registry = get_unit_wallet_registry()
    if payload.token_count is not None:
        units_debited = math.ceil(payload.token_count / TOKEN_CHUNK_SIZE)
        wallet = registry.debit_units(
            owner_key=resolved_owner,
            units=units_debited,
            metadata={
                "token_count": payload.token_count,
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
                "reason": payload.reason,
            },
        )
        return WalletDebitResponse(
            status="ok",
            owner_key=resolved_owner,
            units_debited=units_debited,
            token_count=payload.token_count,
            wallet=_wallet_view(wallet),
        )
    else:
        wallet = registry.debit_units(
            owner_key=resolved_owner,
            units=payload.units,  # type: ignore[arg-type]
            metadata={"reason": payload.reason},
        )
        return WalletDebitResponse(
            status="ok",
            owner_key=resolved_owner,
            units_debited=payload.units,  # type: ignore[arg-type]
            token_count=None,
            wallet=_wallet_view(wallet),
        )


@router.post("/wallet/{owner_key}/refund", response_model=WalletRefundResponse)
def refund_wallet(
    owner_key: str,
    payload: WalletRefundRequest,
    auth_ctx: AuthContext = Depends(require_auth_context),
) -> WalletRefundResponse:
    # Org-keyed callers refund back into the shared org wallet.
    resolved_owner = resolve_billing_owner(auth_ctx, owner_key)

    registry = get_unit_wallet_registry()
    wallet = registry.refund_units(
        owner_key=resolved_owner,
        units=payload.units,
        metadata={"reason": payload.reason},
    )
    return WalletRefundResponse(
        status="ok",
        owner_key=resolved_owner,
        units_refunded=payload.units,
        wallet=_wallet_view(wallet),
    )


@router.get(
    "/wallet/{owner_key}",
    response_model=WalletGetResponse,
    dependencies=[Depends(require_auth_context)],
)
def get_wallet(owner_key: str) -> WalletGetResponse:
    registry = get_unit_wallet_registry()
    wallet = registry.get_or_create_wallet(owner_key=owner_key)
    return WalletGetResponse(status="ok", wallet=_wallet_view(wallet))


@router.get(
    "/ledger",
    response_model=LedgerResponse,
    dependencies=[Depends(require_auth_context)],
)
def get_ledger(
    owner_key: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> LedgerResponse:
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
