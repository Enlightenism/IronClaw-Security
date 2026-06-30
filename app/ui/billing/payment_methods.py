from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.supabaseclient import (
    TOKENS_PER_UNIT,
    get_supabase_client,
    is_supabase_configured,
)
from app.ui.billing.package import (
    PACKAGE_CATALOGUE as _BASE_PACKAGE_CATALOGUE,
)
from app.ui.billing.package import (
    StripeStatus,
    _get_stripe_status,
)

__all__ = [
    "PACKAGE_CATALOGUE",
    "StripeStatus",
    "_build_package_catalogue",
    "_get_stripe_status",
    "_get_environment",
    "_stripe_mode",
    "_stripe_connection_note",
    "_stripe_webhook_secret_note",
    "_brand_display",
    "_build_method",
    "_build_status_counts",
    "_exp_display",
    "_resolve_default_method_id",
    "_BRAND_DISPLAY",
    "_MAX_METHODS",
    "_STATUS_COLOR",
    "AddPaymentMethodRequest",
    "AddPaymentMethodResponse",
    "BillingPaymentMethodsNotFoundResponse",
    "BillingPaymentMethodsResponse",
    "BillingPaymentMethodStatusCount",
    "BillingPaymentMethodView",
    "DeletePaymentMethodResponse",
    "PackageCatalogueEntry",
    "SetDefaultPaymentMethodResponse",
]

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-payment-methods"],
)

_MAX_METHODS = 4

_STATUS_COLOR: dict[str, str] = {
    "active": "success",
    "expired": "warning",
    "revoked": "error",
    "pending": "info",
}

_BRAND_DISPLAY: dict[str, str] = {
    "visa": "Visa",
    "mastercard": "Mastercard",
    "amex": "American Express",
    "discover": "Discover",
    "bank_account": "Bank Account",
}


def _get_environment() -> str:
    return os.environ.get("IRONCLAW_ENV", os.environ.get("APP_ENV", "production"))


# ---------------------------------------------------------------------------
# Stripe helpers
# ---------------------------------------------------------------------------


def _stripe_mode() -> str | None:
    key = os.environ.get("STRIPE_API_KEY", "").strip()
    if key.startswith("sk_live_"):
        return "live"
    if key.startswith("sk_test_"):
        return "test"
    return None


def _stripe_connection_note() -> str:
    mode = _stripe_mode()
    if mode == "live":
        return "Stripe is connected and active (mode: live). Real payment processing is enabled."
    if mode == "test":
        return "Stripe is connected in test mode (mode: test). Switch to a live key before going to production."
    return "Stripe API key is not configured — payment processing is unavailable."


def _stripe_webhook_secret_note() -> str:
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if secret and secret.startswith("whsec_"):
        return "Stripe webhook secret is configured."
    return "Stripe webhook secret (STRIPE_WEBHOOK_SECRET) is not configured — webhook signature verification is disabled."


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


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
    stripe_price_id: str
    notes: str


class BillingPaymentMethodsResponse(BaseModel):
    generatedat: str
    environment: str
    organizationid: str
    organizationname: str
    stripe_customer_id: str | None
    stripe: StripeStatus = Field(default_factory=_get_stripe_status)
    stripe_mode: str | None
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


class AddPaymentMethodRequest(BaseModel):
    stripe_payment_method_id: str = Field(
        ...,
        description="Stripe PaymentMethod ID (pm_...) returned by Stripe.js or the Stripe API.",
    )
    set_as_default: bool = Field(
        default=False,
        description="If true, mark this method as the organization default.",
    )


class AddPaymentMethodResponse(BaseModel):
    status: str
    methodid: str
    organizationid: str
    set_as_default: bool
    generatedat: str
    environment: str
    message: str


class SetDefaultPaymentMethodResponse(BaseModel):
    status: str
    methodid: str
    organizationid: str
    generatedat: str
    environment: str
    message: str


class DeletePaymentMethodResponse(BaseModel):
    status: str
    methodid: str
    organizationid: str
    generatedat: str
    environment: str
    message: str


# ---------------------------------------------------------------------------
# PACKAGE_CATALOGUE — built fresh on every call so env patches in tests are
# always picked up. The module-level symbol is kept for import compatibility
# but routes call _build_package_catalogue() directly rather than reading the
# frozen module-level dict.
#
# stripe_price_id resolution: always reads os.environ at call time; the base
# catalogue value is intentionally ignored so that an unset env var always
# yields "" — never a stale hardcoded default from _BASE_PACKAGE_CATALOGUE.
# ---------------------------------------------------------------------------


def _build_package_catalogue() -> dict[str, dict]:
    catalogue: dict[str, dict] = {}
    for key, base in _BASE_PACKAGE_CATALOGUE.items():
        entry = dict(base)
        # Always resolve from env at call time; ignore base.get("stripe_price_id")
        # so that an unset var always produces "" rather than a stale default.
        entry["stripe_price_id"] = os.environ.get(f"STRIPE_PRICE_ID_{key.upper()}", "")
        catalogue[key] = entry
    return catalogue


# Module-level symbol preserved for direct imports; routes call
# _build_package_catalogue() fresh so env patches are always reflected.
PACKAGE_CATALOGUE: dict[str, dict] = _build_package_catalogue()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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


def _build_status_counts(
    methods: list[BillingPaymentMethodView],
) -> list[BillingPaymentMethodStatusCount]:
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


def _fetch_org_payment_methods(
    organizationid: str,
) -> list[BillingPaymentMethodView] | None:
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


def _fetch_stripe_customer_id(organizationid: str) -> str | None:
    if not is_supabase_configured():
        return None
    try:
        client = get_supabase_client()
        rows = client.table("organizations").select("stripe_customer_id").eq("id", organizationid).limit(1).execute().data
        if rows:
            val = rows[0].get("stripe_customer_id")
            return str(val) if val else None
        return None
    except Exception:
        return None


def _insert_payment_method_record(
    organizationid: str,
    stripe_payment_method_id: str,
    set_as_default: bool,
) -> str | None:
    if not is_supabase_configured():
        return None
    try:
        client = get_supabase_client()
        if set_as_default:
            client.table("payment_methods").update({"is_default": False}).eq("organization_id", organizationid).execute()
        payload: dict[str, Any] = {
            "organization_id": organizationid,
            "stripe_payment_method_id": stripe_payment_method_id,
            "type": "card",
            "brand": "",
            "last4": "",
            "exp_month": 0,
            "exp_year": 0,
            "is_default": set_as_default,
            "status": "active",
            "created_at": datetime.now(UTC).isoformat(),
        }
        rows = client.table("payment_methods").insert(payload).execute().data
        if rows:
            return str(rows[0].get("id", ""))
        return None
    except Exception:
        return None


def _set_default_method_in_db(
    organizationid: str,
    methodid: str,
) -> bool:
    if not is_supabase_configured():
        return False
    try:
        client = get_supabase_client()
        client.table("payment_methods").update({"is_default": False}).eq("organization_id", organizationid).execute()
        client.table("payment_methods").update({"is_default": True}).eq("id", methodid).eq("organization_id", organizationid).execute()
        return True
    except Exception:
        return False


def _delete_method_from_db(
    organizationid: str,
    methodid: str,
) -> bool:
    if not is_supabase_configured():
        return False
    try:
        client = get_supabase_client()
        client.table("payment_methods").delete().eq("id", methodid).eq("organization_id", organizationid).execute()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/payment-methods",
    response_model=BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse,
)
def get_payment_methods(
    organizationid: str = "org-001",
) -> BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse:
    if not organizationid or not organizationid.strip():
        organizationid = "org-001"

    env = _get_environment()

    # Build catalogue fresh on every request so env patches are always picked up.
    live_catalogue = _build_package_catalogue()

    sb_methods = _fetch_org_payment_methods(organizationid)
    sb_org_name = _fetch_org_name(organizationid)
    sb_stripe_customer_id = _fetch_stripe_customer_id(organizationid)

    if sb_methods is None and not is_supabase_configured():
        return BillingPaymentMethodsNotFoundResponse(
            status="not_found",
            organizationid=organizationid,
            message=(f"Organization '{organizationid}' could not be resolved. Supabase is not configured — connect SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY."),
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
    pending_count = sum(1 for m in methods if m.status == "pending")

    stripe_status: StripeStatus = _get_stripe_status()

    notes = [
        f"Organization '{organizationid}' has {methodcount} payment method(s) on file.",
        f"Active: {active_count}. Expired: {expired_count}. Revoked: {revoked_count}. Pending: {pending_count}.",
        f"Maximum allowed payment methods per organization is {_MAX_METHODS}.",
        f"canaddnew is {'true' if canaddnew else 'false'} — organization {'can' if canaddnew else 'cannot'} add new payment methods.",
        "statuscolor maps payment method status to a UI hint: success (active), warning (expired), error (revoked), info (pending).",
        f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens. Partial token chunks consume a full additional unit.",
        stripe_status.note,
        _stripe_webhook_secret_note(),
    ]

    if expired_count > 0:
        notes.append("One or more payment methods are expired. Prompt the user to update billing details.")
    if revoked_count > 0:
        notes.append("One or more payment methods have been revoked and cannot be used for future charges.")
    if pending_count > 0:
        notes.append("One or more payment methods are pending verification.")

    catalogue_out: dict[str, PackageCatalogueEntry] = {}
    for k, v in live_catalogue.items():
        catalogue_out[k] = PackageCatalogueEntry(**v)

    return BillingPaymentMethodsResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment=env,
        organizationid=organizationid,
        organizationname=org_name,
        stripe_customer_id=sb_stripe_customer_id,
        stripe=stripe_status,
        stripe_mode=stripe_status.mode if stripe_status.configured else None,
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


@router.post(
    "/payment-methods",
    response_model=AddPaymentMethodResponse,
    status_code=201,
)
def add_payment_method(
    body: AddPaymentMethodRequest,
    organizationid: str = "org-001",
) -> AddPaymentMethodResponse:
    if not organizationid or not organizationid.strip():
        raise HTTPException(status_code=422, detail="organizationid is required.")

    env = _get_environment()

    if not is_supabase_configured():
        raise HTTPException(
            status_code=503,
            detail="Supabase is not configured — payment method cannot be persisted.",
        )

    existing = _fetch_org_payment_methods(organizationid)
    if existing is not None and len(existing) >= _MAX_METHODS:
        raise HTTPException(
            status_code=409,
            detail=(f"Organization '{organizationid}' has reached the maximum of {_MAX_METHODS} payment methods. Remove an existing method before adding a new one."),
        )

    new_id = _insert_payment_method_record(
        organizationid=organizationid,
        stripe_payment_method_id=body.stripe_payment_method_id,
        set_as_default=body.set_as_default,
    )

    if new_id is None:
        raise HTTPException(
            status_code=500,
            detail="Failed to persist the payment method. Please try again.",
        )

    return AddPaymentMethodResponse(
        status="created",
        methodid=new_id,
        organizationid=organizationid,
        set_as_default=body.set_as_default,
        generatedat=datetime.now(UTC).isoformat(),
        environment=env,
        message=(f"Payment method '{new_id}' has been added to organization '{organizationid}'." + (" Set as default." if body.set_as_default else "")),
    )


@router.patch(
    "/payment-methods/{methodid}/default",
    response_model=SetDefaultPaymentMethodResponse,
)
def set_default_payment_method(
    methodid: str,
    organizationid: str = "org-001",
) -> SetDefaultPaymentMethodResponse:
    if not organizationid or not organizationid.strip():
        raise HTTPException(status_code=422, detail="organizationid is required.")

    env = _get_environment()

    if not is_supabase_configured():
        raise HTTPException(
            status_code=503,
            detail="Supabase is not configured — cannot update payment method.",
        )

    success = _set_default_method_in_db(organizationid=organizationid, methodid=methodid)
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to set method '{methodid}' as default. Please try again.",
        )

    return SetDefaultPaymentMethodResponse(
        status="updated",
        methodid=methodid,
        organizationid=organizationid,
        generatedat=datetime.now(UTC).isoformat(),
        environment=env,
        message=f"Payment method '{methodid}' is now the default for organization '{organizationid}'.",
    )


@router.delete(
    "/payment-methods/{methodid}",
    response_model=DeletePaymentMethodResponse,
)
def delete_payment_method(
    methodid: str,
    organizationid: str = "org-001",
) -> DeletePaymentMethodResponse:
    if not organizationid or not organizationid.strip():
        raise HTTPException(status_code=422, detail="organizationid is required.")

    env = _get_environment()

    if not is_supabase_configured():
        raise HTTPException(
            status_code=503,
            detail="Supabase is not configured — cannot delete payment method.",
        )

    success = _delete_method_from_db(organizationid=organizationid, methodid=methodid)
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete method '{methodid}'. Please try again.",
        )

    return DeletePaymentMethodResponse(
        status="deleted",
        methodid=methodid,
        organizationid=organizationid,
        generatedat=datetime.now(UTC).isoformat(),
        environment=env,
        message=f"Payment method '{methodid}' has been removed from organization '{organizationid}'.",
    )
