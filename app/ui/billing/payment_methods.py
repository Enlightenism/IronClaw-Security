from __future__ import annotations

from datetime import UTC, datetime
import os
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.auth import AuthContext, get_auth_context
from app.core.billing import resolve_authenticated_billing_owner
from app.routers.stripe_router import get_stripe_service
from app.services.stripe_service import (
    StripePaymentMethodNotFoundError,
    StripeService,
    StripeServiceError,
)
from app.supabaseclient import TOKENS_PER_UNIT, get_supabase_client, is_supabase_configured
from app.ui.billing.package import (
    PackageCatalogueEntry,
    StripeStatus,
    _build_package_catalogue,
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
    "_resolve_org_id",
    "_resolve_org_id_from_request",
    "_require_org_id",
    "_normalize_method_id",
    "_method_id",
    "_method_brand",
    "_method_type",
    "_method_last4",
    "_method_exp_month",
    "_method_exp_year",
    "_method_is_default",
    "_method_status",
    "_method_created_at",
    "_build_method_from_stripe",
    "_fetch_payment_methods_from_stripe",
    "_fetch_payment_methods_from_supabase",
    "_fetch_org_name",
    "_ensure_supabase_available_for_read",
    "_ensure_supabase_available_for_write",
    "_supabase_table",
    "_safe_execute",
    "_safe_data",
    "_safe_single_row",
    "_apply_eq",
    "_BRAND_DISPLAY",
    "_MAX_METHODS",
    "_STATUS_COLOR",
    "BillingPaymentMethodsNotFoundResponse",
    "BillingPaymentMethodsResponse",
    "BillingPaymentMethodStatusCount",
    "BillingPaymentMethodView",
    "DeletePaymentMethodResponse",
    "PackageCatalogueEntry",
    "SetDefaultPaymentMethodResponse",
    "router",
    "get_supabase_client",
    "is_supabase_configured",
]

router = APIRouter(tags=["billing-payment-methods"])

_MAX_METHODS = 4
_PAYMENT_METHODS_TABLE = "billing_payment_methods"
PACKAGE_CATALOGUE: dict[str, dict[str, Any]] = _build_package_catalogue()

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
    "diners": "Diners Club",
    "diners_club": "Diners Club",
    "jcb": "JCB",
    "unionpay": "UnionPay",
    "bank_account": "Bank Account",
    "unknown": "Unknown",
}


def _get_environment() -> str:
    return os.environ.get("IRONCLAW_ENV", os.environ.get("APP_ENV", "production"))


# ---------------------------------------------------------------------------
# Stripe helpers
# ---------------------------------------------------------------------------


def _stripe_mode() -> str | None:
    key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
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


class BillingPaymentMethodsResponse(BaseModel):
    status: str = "ok"
    generatedat: str
    environment: str
    organizationid: str
    organizationname: str
    stripe_customer_id: str | None
    customer_mapping_status: str = "mapped"
    methods_status: str = "available"
    message: str | None = None
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
# Internal helpers
# ---------------------------------------------------------------------------


def _supabase_table(client: Any) -> Any:
    return client.table(_PAYMENT_METHODS_TABLE)


def _ensure_supabase_available_for_read(organizationid: str) -> BillingPaymentMethodsNotFoundResponse | None:
    if is_supabase_configured():
        return None
    return BillingPaymentMethodsNotFoundResponse(
        status="not_found",
        organizationid=organizationid,
        message="Supabase is not configured, so billing payment methods are unavailable.",
        generatedat=datetime.now(UTC).isoformat(),
        environment=_get_environment(),
    )


def _ensure_supabase_available_for_write() -> None:
    if not is_supabase_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase is not configured for billing payment method writes.",
        )


def _status_color(status_value: str) -> str:
    return _STATUS_COLOR.get((status_value or "").strip().lower(), "neutral")


def _brand_display(brand: str) -> str:
    raw = str(brand or "").strip()
    if not raw:
        return "Unknown"
    normalized = raw.lower()
    if normalized in _BRAND_DISPLAY:
        return _BRAND_DISPLAY[normalized]
    spaced = re.sub(r"[_\-]+", " ", raw)
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
    spaced = re.sub(r"\s+", " ", spaced).strip()
    if not spaced:
        return "Unknown"
    return spaced.title()


def _exp_display(expmonth: int, expyear: int) -> str:
    if expmonth <= 0 or expyear <= 0:
        return ""
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
    safe_expmonth = max(0, int(expmonth or 0))
    safe_expyear = max(0, int(expyear or 0))
    normalized_status = (status or "active").strip().lower() or "active"
    return BillingPaymentMethodView(
        methodid=str(methodid or "").strip(),
        type=type or "card",
        brand=(brand or "unknown"),
        branddisplay=_brand_display(brand),
        last4=(last4 or ""),
        expmonth=safe_expmonth,
        expyear=safe_expyear,
        expdisplay=_exp_display(safe_expmonth, safe_expyear),
        isdefault=bool(isdefault),
        status=normalized_status,
        statuscolor=_status_color(normalized_status),
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
    for method in methods:
        counts[method.status] = counts.get(method.status, 0) + 1
    return [
        BillingPaymentMethodStatusCount(
            status=status_name,
            count=count,
            statuscolor=_status_color(status_name),
        )
        for status_name, count in sorted(counts.items())
    ]


def _resolve_org_id(auth: AuthContext | None) -> str:
    if auth is None:
        return ""
    oid = getattr(auth, "org_id", None) or getattr(auth, "tenant_id", None) or ""
    return str(oid).strip()


def _resolve_org_id_from_request(
    auth: AuthContext | None,
    request: Request | None = None,
) -> str:
    auth_org_id = _resolve_org_id(auth)
    if auth_org_id:
        return auth_org_id

    # Same verified billing owner that checkout uses as its org key, so saved cards
    # are read from the Stripe customer that checkout created.
    owner_key = resolve_authenticated_billing_owner(auth) if auth is not None else None
    if owner_key:
        return owner_key

    if request is not None:
        query_org_id = (request.query_params.get("organizationid") or request.query_params.get("organization_id") or request.query_params.get("organizationId") or "").strip()
        if query_org_id:
            return query_org_id

    return ""


def _require_org_id(
    auth: AuthContext | None,
    request: Request | None = None,
) -> str:
    org_id = _resolve_org_id_from_request(auth=auth, request=request)
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "org_id_unresolved",
                "detail": "Organization ID could not be resolved from auth context or request.",
                "accepted_fallbacks": ["organizationid", "organization_id", "organizationId"],
            },
        )
    return org_id


def _normalize_method_id(candidate: Any) -> str:
    return str(candidate or "").strip()


def _method_created_at(raw: Any) -> str:
    if isinstance(raw, dict):
        value = raw.get("created_at") or raw.get("createdat")
    else:
        value = getattr(raw, "created_at", None) or getattr(raw, "createdat", None)
    if isinstance(value, str) and value.strip():
        return value
    return datetime.now(UTC).isoformat()


def _method_brand(raw: Any) -> str:
    if isinstance(raw, dict):
        return str(raw.get("brand") or "unknown")
    return str(getattr(raw, "brand", "unknown") or "unknown")


def _method_type(raw: Any) -> str:
    if isinstance(raw, dict):
        return str(raw.get("type") or "card")
    return str(getattr(raw, "type", "card") or "card")


def _method_last4(raw: Any) -> str:
    if isinstance(raw, dict):
        return str(raw.get("last4") or "")
    return str(getattr(raw, "last4", "") or "")


def _method_exp_month(raw: Any) -> int:
    if isinstance(raw, dict):
        value = raw.get("exp_month", raw.get("expmonth", 0))
    else:
        value = getattr(raw, "exp_month", None)
        if value is None:
            value = getattr(raw, "expmonth", 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _method_exp_year(raw: Any) -> int:
    if isinstance(raw, dict):
        value = raw.get("exp_year", raw.get("expyear", 0))
    else:
        value = getattr(raw, "exp_year", None)
        if value is None:
            value = getattr(raw, "expyear", 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _method_is_default(raw: Any) -> bool:
    if isinstance(raw, dict):
        return bool(raw.get("is_default") or raw.get("isdefault") or raw.get("default"))
    return bool(getattr(raw, "is_default", False) or getattr(raw, "isdefault", False) or getattr(raw, "default", False))


def _method_status(raw: Any) -> str:
    if isinstance(raw, dict):
        explicit = raw.get("status")
    else:
        explicit = getattr(raw, "status", None)

    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()

    expmonth = _method_exp_month(raw)
    expyear = _method_exp_year(raw)

    if expmonth > 0 and expyear > 0:
        now = datetime.now(UTC)
        if expyear < now.year or (expyear == now.year and expmonth < now.month):
            return "expired"
    return "active"


def _method_id(raw: Any) -> str:
    if isinstance(raw, dict):
        return _normalize_method_id(raw.get("stripe_payment_method_id") or raw.get("payment_method_id") or raw.get("paymentmethodid") or raw.get("id") or raw.get("methodid"))
    return _normalize_method_id(getattr(raw, "stripe_payment_method_id", None) or getattr(raw, "payment_method_id", None) or getattr(raw, "paymentmethodid", None) or getattr(raw, "id", None) or getattr(raw, "methodid", None))


def _build_method_from_stripe(
    raw: Any,
    organizationid: str,
) -> BillingPaymentMethodView:
    return _build_method(
        methodid=_method_id(raw),
        type=_method_type(raw),
        brand=_method_brand(raw),
        last4=_method_last4(raw),
        expmonth=_method_exp_month(raw),
        expyear=_method_exp_year(raw),
        isdefault=_method_is_default(raw),
        status=_method_status(raw),
        createdat=_method_created_at(raw),
        organizationid=organizationid,
    )


def _safe_execute(query: Any) -> Any:
    if hasattr(query, "execute"):
        return query.execute()
    return query


def _safe_data(result: Any) -> list[Any]:
    data = getattr(result, "data", None)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]


def _safe_single_row(result: Any) -> dict[str, Any] | None:
    rows = _safe_data(result)
    if not rows:
        return None
    first = rows[0]
    if isinstance(first, dict):
        return first
    return None


def _apply_eq(query: Any, field: str, value: Any) -> Any:
    if hasattr(query, "eq"):
        return query.eq(field, value)
    return query


def _fetch_payment_methods_from_stripe(
    svc: StripeService,
    organizationid: str,
) -> tuple[str | None, list[BillingPaymentMethodView]]:
    customer_id = svc.resolve_customer_id(organizationid)

    if not customer_id:
        return None, []

    raw_methods = svc.list_payment_methods(customer_id=customer_id)
    methods = [_build_method_from_stripe(item, organizationid=organizationid) for item in raw_methods]
    return customer_id, methods


def _fetch_payment_methods_from_supabase(organizationid: str) -> list[BillingPaymentMethodView]:
    client = get_supabase_client()
    query = _supabase_table(client).select("*")
    query = _apply_eq(query, "organization_id", organizationid)
    if hasattr(query, "order"):
        query = query.order("created_at")
    response = _safe_execute(query)
    rows = _safe_data(response)

    methods: list[BillingPaymentMethodView] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        methods.append(
            _build_method(
                methodid=_normalize_method_id(row.get("stripe_payment_method_id") or row.get("payment_method_id") or row.get("id") or row.get("methodid")),
                type=str(row.get("type") or "card"),
                brand=str(row.get("brand") or "unknown"),
                last4=str(row.get("last4") or ""),
                expmonth=int(row.get("exp_month") or row.get("expmonth") or 0),
                expyear=int(row.get("exp_year") or row.get("expyear") or 0),
                isdefault=bool(row.get("is_default") or row.get("isdefault") or row.get("default")),
                status=str(row.get("status") or "active"),
                createdat=str(row.get("created_at") or row.get("createdat") or datetime.now(UTC).isoformat()),
                organizationid=str(row.get("organization_id") or organizationid),
            )
        )

    return methods[:_MAX_METHODS]


def _fetch_org_name(organizationid: str, customer_id: str | None) -> str:
    if customer_id:
        return organizationid
    return organizationid


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/api/ui/billing/payment-methods",
    operation_id="billing_get_payment_methods",
    response_model=BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse,
)
@router.get(
    "/ui/billing/payment-methods",
    include_in_schema=False,
    response_model=BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse,
)
@router.get(
    "/api/ui/billing/payment-method",
    include_in_schema=False,
    response_model=BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse,
)
@router.get(
    "/ui/billing/payment-method",
    include_in_schema=False,
    response_model=BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse,
)
async def get_payment_methods(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse:
    organizationid = _require_org_id(auth=auth, request=request)

    env = _get_environment()
    generatedat = datetime.now(UTC).isoformat()
    live_catalogue = _build_package_catalogue()

    try:
        stripe_customer_id, stripe_methods = _fetch_payment_methods_from_stripe(
            svc=svc,
            organizationid=organizationid,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "payment_methods_fetch_error",
                "detail": str(exc),
                "organizationid": organizationid,
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "payment_methods_fetch_error",
                "detail": str(exc),
                "organizationid": organizationid,
            },
        ) from exc

    if stripe_customer_id:
        methods = stripe_methods
        customer_mapping_status = "mapped"
        methods_status = "available" if methods else "no_saved_methods"
        response_status = "ok" if methods else "no_saved_methods"
        response_message = None if methods else "No saved payment methods are attached to this Stripe customer."
    elif is_supabase_configured():
        try:
            methods = _fetch_payment_methods_from_supabase(organizationid=organizationid)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "payment_methods_fetch_error",
                    "detail": str(exc),
                    "organizationid": organizationid,
                },
            ) from exc
        customer_mapping_status = "unavailable"
        methods_status = "customer_mapping_unavailable"
        response_status = "customer_mapping_unavailable"
        response_message = "No Stripe customer is currently mapped to this organization, so saved methods could not be verified."
    else:
        methods = []
        customer_mapping_status = "unavailable"
        methods_status = "customer_mapping_unavailable"
        response_status = "customer_mapping_unavailable"
        response_message = "No Stripe customer is currently mapped to this organization, so saved methods could not be verified."

    org_name = _fetch_org_name(organizationid, stripe_customer_id)
    methodcount = len(methods)
    defaultmethodid = _resolve_default_method_id(methods)
    canaddnew = methodcount < _MAX_METHODS
    statuscounts = _build_status_counts(methods)

    active_count = sum(1 for method in methods if method.status == "active")
    expired_count = sum(1 for method in methods if method.status == "expired")
    revoked_count = sum(1 for method in methods if method.status == "revoked")
    pending_count = sum(1 for method in methods if method.status == "pending")

    stripe_status = _get_stripe_status()

    notes = [
        f"Organization '{organizationid}' has {methodcount} payment method(s) on file.",
        f"Active: {active_count}. Expired: {expired_count}. Revoked: {revoked_count}. Pending: {pending_count}.",
        f"Maximum allowed payment methods per organization is {_MAX_METHODS}.",
        f"canaddnew is {'true' if canaddnew else 'false'} — organization {'can' if canaddnew else 'cannot'} add new payment methods.",
        "statuscolor maps payment method status to a UI hint: success (active), warning (expired), error (revoked), info (pending).",
        f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens. Partial token chunks consume a full additional unit.",
        stripe_status.note,
        _stripe_connection_note(),
        _stripe_webhook_secret_note(),
    ]

    if stripe_customer_id is None:
        notes.append(response_message or "No Stripe customer is currently mapped to this organization.")
    if expired_count > 0:
        notes.append("One or more payment methods are expired. Prompt the user to update billing details.")
    if revoked_count > 0:
        notes.append("One or more payment methods have been revoked and cannot be used for future charges.")
    if pending_count > 0:
        notes.append("One or more payment methods are pending verification.")

    catalogue_out: dict[str, PackageCatalogueEntry] = {}
    for key, value in live_catalogue.items():
        catalogue_out[key] = PackageCatalogueEntry(**value)

    return BillingPaymentMethodsResponse(
        status=response_status,
        generatedat=generatedat,
        environment=env,
        organizationid=organizationid,
        organizationname=org_name,
        stripe_customer_id=stripe_customer_id,
        customer_mapping_status=customer_mapping_status,
        methods_status=methods_status,
        message=response_message,
        stripe=stripe_status,
        stripe_mode=stripe_status.mode if stripe_status.configured else _stripe_mode(),
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


@router.patch(
    "/api/ui/billing/payment-methods/{methodid}/default",
    operation_id="billing_set_default_payment_method",
    response_model=SetDefaultPaymentMethodResponse,
)
@router.patch(
    "/ui/billing/payment-methods/{methodid}/default",
    include_in_schema=False,
    response_model=SetDefaultPaymentMethodResponse,
)
@router.patch(
    "/api/ui/billing/payment-methods/set-default/{methodid}",
    include_in_schema=False,
    response_model=SetDefaultPaymentMethodResponse,
)
@router.patch(
    "/ui/billing/payment-methods/set-default/{methodid}",
    include_in_schema=False,
    response_model=SetDefaultPaymentMethodResponse,
)
async def set_default_payment_method(
    methodid: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> SetDefaultPaymentMethodResponse:
    organizationid = _require_org_id(auth=auth, request=request)
    env = _get_environment()
    generatedat = datetime.now(UTC).isoformat()
    normalized_methodid = _normalize_method_id(methodid)

    if not normalized_methodid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "payment_method_id_required",
                "detail": "Payment method ID is required.",
            },
        )

    try:
        customer_id, current_methods = _fetch_payment_methods_from_stripe(svc=svc, organizationid=organizationid)
        if not customer_id or not any(method.methodid == normalized_methodid for method in current_methods):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "payment_method_not_found",
                    "detail": f"Payment method '{normalized_methodid}' was not found for organization '{organizationid}'.",
                },
            )
        svc.set_default_payment_method(customer_id=customer_id, payment_method_id=normalized_methodid)
        if is_supabase_configured():
            table = _supabase_table(get_supabase_client())
            reset_query = table.update({"is_default": False})
            reset_query = _apply_eq(reset_query, "organization_id", organizationid)
            _safe_execute(reset_query)

            set_query = table.update({"is_default": True})
            set_query = _apply_eq(set_query, "organization_id", organizationid)
            set_query = _apply_eq(set_query, "stripe_payment_method_id", normalized_methodid)
            _safe_execute(set_query)
    except HTTPException:
        raise
    except StripePaymentMethodNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "payment_method_not_found",
                "detail": f"Payment method '{normalized_methodid}' was not found for organization '{organizationid}'.",
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "set_default_error", "detail": str(exc), "methodid": normalized_methodid},
        ) from exc

    return SetDefaultPaymentMethodResponse(
        status="updated",
        methodid=normalized_methodid,
        organizationid=organizationid,
        generatedat=generatedat,
        environment=env,
        message=f"Payment method '{normalized_methodid}' is now the default for organization '{organizationid}'.",
    )


@router.delete(
    "/api/ui/billing/payment-methods/{methodid}",
    operation_id="billing_delete_payment_method",
    response_model=DeletePaymentMethodResponse,
)
@router.delete(
    "/ui/billing/payment-methods/{methodid}",
    include_in_schema=False,
    response_model=DeletePaymentMethodResponse,
)
@router.delete(
    "/api/ui/billing/payment-methods/delete/{methodid}",
    include_in_schema=False,
    response_model=DeletePaymentMethodResponse,
)
@router.delete(
    "/ui/billing/payment-methods/delete/{methodid}",
    include_in_schema=False,
    response_model=DeletePaymentMethodResponse,
)
async def delete_payment_method(
    methodid: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> DeletePaymentMethodResponse:
    _ensure_supabase_available_for_write()

    organizationid = _require_org_id(auth=auth, request=request)
    env = _get_environment()
    generatedat = datetime.now(UTC).isoformat()
    normalized_methodid = _normalize_method_id(methodid)

    if not normalized_methodid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "payment_method_id_required",
                "detail": "Payment method ID is required.",
            },
        )

    try:
        customer_id, current_methods = _fetch_payment_methods_from_stripe(svc=svc, organizationid=organizationid)
        if not customer_id or not any(method.methodid == normalized_methodid for method in current_methods):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "payment_method_not_found",
                    "detail": f"Payment method '{normalized_methodid}' was not found for organization '{organizationid}'.",
                },
            )
        svc.detach_payment_method(payment_method_id=normalized_methodid)
    except HTTPException:
        raise
    except StripePaymentMethodNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "payment_method_not_found",
                "detail": f"Payment method '{normalized_methodid}' was not found for organization '{organizationid}'.",
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "detach_error", "detail": str(exc), "methodid": normalized_methodid},
        ) from exc

    try:
        delete_query = _supabase_table(get_supabase_client()).delete()
        delete_query = _apply_eq(delete_query, "organization_id", organizationid)
        delete_query = _apply_eq(delete_query, "stripe_payment_method_id", normalized_methodid)
        _safe_execute(delete_query)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "payment_method_delete_error", "detail": str(exc), "methodid": normalized_methodid},
        ) from exc

    return DeletePaymentMethodResponse(
        status="deleted",
        methodid=normalized_methodid,
        organizationid=organizationid,
        generatedat=generatedat,
        environment=env,
        message=f"Payment method '{normalized_methodid}' has been removed from organization '{organizationid}'.",
    )
