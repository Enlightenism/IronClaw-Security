from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
    TOKENS_PER_UNIT,
    get_supabase_client,
    is_supabase_configured,
)

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-payment-methods"],
)

_MAX_METHODS = 4

_STATUS_COLOR: dict[str, str] = {
    "active": "success",
    "expired": "warning",
    "revoked": "error",
}

_BRAND_DISPLAY: dict[str, str] = {
    "visa": "Visa",
    "mastercard": "Mastercard",
    "amex": "American Express",
    "discover": "Discover",
    "bank_account": "Bank Account",
}

# ---------------------------------------------------------------------------
# Package catalogue — single source of truth imported from supabaseclient
# Starter   :  5,000 units → $20 USD
# Team      : 25,000 units → $90 USD
# Enterprise: 60,000 units → $180 USD
# Each protection unit covers up to TOKENS_PER_UNIT (25,000) tokens.
# ---------------------------------------------------------------------------

PACKAGE_CATALOGUE: dict[str, dict[str, Any]] = {
    "starter": {
        "label": "Starter",
        "units": BILLING_TIER_5K_UNITS,
        "price_usd": BILLING_TIER_5K_PRICE_USD,
        "price_cents": BILLING_TIER_5K_PRICE_USD * 100,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "token_coverage": BILLING_TIER_5K_UNITS * TOKENS_PER_UNIT,
        "notes": (f"{BILLING_TIER_5K_UNITS:,} units · ${BILLING_TIER_5K_PRICE_USD} USD" f" · each unit protects up to {TOKENS_PER_UNIT:,} tokens"),
    },
    "team": {
        "label": "Team",
        "units": BILLING_TIER_25K_UNITS,
        "price_usd": BILLING_TIER_25K_PRICE_USD,
        "price_cents": BILLING_TIER_25K_PRICE_USD * 100,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "token_coverage": BILLING_TIER_25K_UNITS * TOKENS_PER_UNIT,
        "notes": (f"{BILLING_TIER_25K_UNITS:,} units · ${BILLING_TIER_25K_PRICE_USD} USD" f" · each unit protects up to {TOKENS_PER_UNIT:,} tokens"),
    },
    "enterprise": {
        "label": "Enterprise",
        "units": BILLING_TIER_60K_UNITS,
        "price_usd": BILLING_TIER_60K_PRICE_USD,
        "price_cents": BILLING_TIER_60K_PRICE_USD * 100,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "token_coverage": BILLING_TIER_60K_UNITS * TOKENS_PER_UNIT,
        "notes": (f"{BILLING_TIER_60K_UNITS:,} units · ${BILLING_TIER_60K_PRICE_USD} USD" f" · each unit protects up to {TOKENS_PER_UNIT:,} tokens"),
    },
}


def _get_environment() -> str:
    return os.environ.get("IRONCLAW_ENV", os.environ.get("APP_ENV", "production"))


class BillingPaymentMethodView(BaseModel):
    methodid: str
    type: str
    brand: str
    branddisplay: str
    last4: str
    expmonth: int
    expyear: int
    expdisplay: str
    isdefault: bool
    status: str
    statuscolor: str
    createdat: str
    organizationid: str


class BillingPaymentMethodStatusCount(BaseModel):
    status: str
    count: int
    statuscolor: str


class PackageCatalogueEntry(BaseModel):
    label: str
    units: int
    price_usd: int
    price_cents: int
    tokens_per_unit: int
    token_coverage: int
    notes: str


class BillingPaymentMethodsResponse(BaseModel):
    generatedat: str
    environment: str
    organizationid: str
    organizationname: str
    defaultmethodid: str | None
    methods: list[BillingPaymentMethodView] = Field(default_factory=list)
    methodcount: int
    canaddnew: bool
    maxmethods: int
    statuscounts: list[BillingPaymentMethodStatusCount] = Field(default_factory=list)
    tokens_per_unit: int
    package_catalogue: dict[str, PackageCatalogueEntry] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class BillingPaymentMethodsNotFoundResponse(BaseModel):
    status: str
    organizationid: str
    message: str
    generatedat: str
    environment: str


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _status_color(status: str) -> str:
    return _STATUS_COLOR.get(status, "neutral")


def _brand_display(brand: str) -> str:
    return _BRAND_DISPLAY.get(brand, brand.title())


def _exp_display(expmonth: int, expyear: int) -> str:
    return f"{expmonth:02d}/{expyear}"


def _build_method(
    methodid: str,
    type: str,
    brand: str,
    last4: str,
    expmonth: int,
    expyear: int,
    isdefault: bool,
    status: str,
    createdat: str,
    organizationid: str,
) -> BillingPaymentMethodView:
    return BillingPaymentMethodView(
        methodid=methodid,
        type=type,
        brand=brand,
        branddisplay=_brand_display(brand),
        last4=last4,
        expmonth=expmonth,
        expyear=expyear,
        expdisplay=_exp_display(expmonth, expyear),
        isdefault=isdefault,
        status=status,
        statuscolor=_status_color(status),
        createdat=createdat,
        organizationid=organizationid,
    )


def _resolve_default_method_id(methods: list[BillingPaymentMethodView]) -> str | None:
    for method in methods:
        if method.isdefault:
            return method.methodid
    return None


def _build_status_counts(methods: list[BillingPaymentMethodView]) -> list[BillingPaymentMethodStatusCount]:
    counts: dict[str, int] = {}
    for m in methods:
        counts[m.status] = counts.get(m.status, 0) + 1
    return [
        BillingPaymentMethodStatusCount(
            status=status,
            count=count,
            statuscolor=_status_color(status),
        )
        for status, count in sorted(counts.items())
    ]


def _fetch_org_payment_methods(organizationid: str) -> list[BillingPaymentMethodView] | None:
    """
    Query Supabase for payment methods belonging to the given organizationid.
    Returns a list of BillingPaymentMethodView on success, or None if Supabase
    is not configured or the query fails.
    """
    if not is_supabase_configured():
        return None
    try:
        client = get_supabase_client()
        rows = client.table("payment_methods").select("*").eq("organization_id", organizationid).order("created_at", desc=False).execute().data
        if not rows:
            return []
        methods: list[BillingPaymentMethodView] = []
        for row in rows:
            methods.append(
                _build_method(
                    methodid=str(row.get("id", "")),
                    type=str(row.get("type", "card")),
                    brand=str(row.get("brand", "")),
                    last4=str(row.get("last4", "")),
                    expmonth=int(row.get("exp_month", 0)),
                    expyear=int(row.get("exp_year", 0)),
                    isdefault=bool(row.get("is_default", False)),
                    status=str(row.get("status", "active")),
                    createdat=str(row.get("created_at", datetime.now(UTC).isoformat())),
                    organizationid=organizationid,
                )
            )
        return methods
    except Exception:
        return None


def _fetch_org_name(organizationid: str) -> str | None:
    """
    Query Supabase for the organization name. Returns None if unavailable.
    """
    if not is_supabase_configured():
        return None
    try:
        client = get_supabase_client()
        rows = client.table("organizations").select("name").eq("id", organizationid).limit(1).execute().data
        if rows:
            return str(rows[0].get("name", organizationid))
        return None
    except Exception:
        return None


def _stripe_connection_note() -> str:
    stripe_key = os.environ.get("STRIPE_API_KEY", "")
    if stripe_key and stripe_key.startswith(("sk_live_", "sk_test_")):
        mode = "live" if stripe_key.startswith("sk_live_") else "test"
        return f"Stripe is connected and active (mode: {mode})."
    return "Stripe API key is not configured — payment processing is unavailable."


@router.get(
    "/payment-methods",
    response_model=BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse,
)
def get_payment_methods(
    organizationid: str = "org-001",
) -> BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse:
    env = _get_environment()

    sb_methods = _fetch_org_payment_methods(organizationid)
    sb_org_name = _fetch_org_name(organizationid)

    if sb_methods is None and not is_supabase_configured():
        return BillingPaymentMethodsNotFoundResponse(
            status="not_found",
            organizationid=organizationid,
            message=(f"Organization '{organizationid}' could not be resolved. " "Supabase is not configured — connect SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY."),
            generatedat=datetime.now(UTC).isoformat(),
            environment=env,
        )

    if sb_methods is None:
        return BillingPaymentMethodsNotFoundResponse(
            status="not_found",
            organizationid=organizationid,
            message=(f"Organization '{organizationid}' was not found or returned no data from Supabase."),
            generatedat=datetime.now(UTC).isoformat(),
            environment=env,
        )

    methods: list[BillingPaymentMethodView] = sb_methods
    org_name: str = sb_org_name or organizationid

    methodcount = len(methods)
    defaultmethodid = _resolve_default_method_id(methods)
    canaddnew = methodcount < _MAX_METHODS
    statuscounts = _build_status_counts(methods)

    active_count = sum(1 for m in methods if m.status == "active")
    expired_count = sum(1 for m in methods if m.status == "expired")
    revoked_count = sum(1 for m in methods if m.status == "revoked")

    notes = [
        f"Organization '{organizationid}' has {methodcount} payment method(s) on file.",
        f"Active: {active_count}. Expired: {expired_count}. Revoked: {revoked_count}.",
        f"Maximum allowed payment methods per organization is {_MAX_METHODS}.",
        f"canaddnew is {'true' if canaddnew else 'false'} — organization {'can' if canaddnew else 'cannot'} add new payment methods.",
        "statuscolor maps payment method status to a UI hint: success (active), warning (expired), error (revoked).",
        f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens. Partial token chunks consume a full additional unit.",
        _stripe_connection_note(),
    ]

    if expired_count > 0:
        notes.append("One or more payment methods are expired. Prompt the user to update billing details.")
    if revoked_count > 0:
        notes.append("One or more payment methods have been revoked and cannot be used for future charges.")

    catalogue_out: dict[str, PackageCatalogueEntry] = {k: PackageCatalogueEntry(**v) for k, v in PACKAGE_CATALOGUE.items()}

    return BillingPaymentMethodsResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment=env,
        organizationid=organizationid,
        organizationname=org_name,
        defaultmethodid=defaultmethodid,
        methods=methods,
        methodcount=methodcount,
        canaddnew=canaddnew,
        maxmethods=_MAX_METHODS,
        statuscounts=statuscounts,
        tokens_per_unit=TOKENS_PER_UNIT,
        package_catalogue=catalogue_out,
        notes=notes,
    )
