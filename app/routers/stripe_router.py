from __future__ import annotations

import logging
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from app.core.auth import AuthContext, get_auth_context
from app.services.secrets_vault import vault
from app.services.stripe_service import (
    PACKAGE_CATALOGUE,
    TOKENS_PER_UNIT,
    StripeCheckoutMode,
    StripeInsufficientUnitsError,
    StripePaymentMethodNotFoundError,
    StripeService,
    StripeServiceError,
    StripeSessionNotFoundError,
    StripeSubscriptionNotFoundError,
    StripeUnitEventReason,
    units_for_tokens,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])
webhook_router = APIRouter(tags=["billing"])
api_router = APIRouter(prefix="/api/billing", tags=["billing"])

_stripe_service_instance: StripeService | None = None


def get_stripe_service() -> StripeService:
    global _stripe_service_instance  # noqa: PLW0603
    if _stripe_service_instance is None:
        _stripe_service_instance = StripeService()
    return _stripe_service_instance


def _resolve_org_id(auth: AuthContext | None) -> str:
    if auth is None:
        return ""
    oid = getattr(auth, "org_id", None) or getattr(auth, "tenant_id", None) or ""
    return str(oid).strip()


def _resolve_customer_id(svc: StripeService, org_id: str) -> str | None:
    with svc._lock:  # noqa: SLF001
        return svc._org_customer_map.get(org_id)  # noqa: SLF001


PACKAGE_PRICE_ENV_MAP: dict[str, str] = {
    "pkg5000": "BILLING_TIER_5K_PRICE_ID",
    "pkg25000": "BILLING_TIER_25K_PRICE_ID",
    "pkg60000": "BILLING_TIER_60K_PRICE_ID",
}

PACKAGE_UNIT_CREDITS: dict[str, int] = {
    "pkg5000": 5000,
    "pkg25000": 25000,
    "pkg60000": 60000,
}

_VALID_CHECKOUT_MODES: frozenset[str] = frozenset(m.value for m in StripeCheckoutMode)
_VALID_PACKAGE_IDS: frozenset[str] = frozenset(PACKAGE_PRICE_ENV_MAP.keys())


def _http_400(detail: str, *, code: str, extra: dict[str, Any] | None = None) -> HTTPException:
    payload: dict[str, Any] = {"error": code, "detail": detail}
    if extra:
        payload.update(extra)
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=payload)


def _http_404(detail: str, *, code: str, extra: dict[str, Any] | None = None) -> HTTPException:
    payload: dict[str, Any] = {"error": code, "detail": detail}
    if extra:
        payload.update(extra)
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=payload)


def _http_500(detail: str, *, code: str, extra: dict[str, Any] | None = None) -> HTTPException:
    payload: dict[str, Any] = {"error": code, "detail": detail}
    if extra:
        payload.update(extra)
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=payload)


def _is_valid_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _configured_price_id_for_package(package_id: str) -> str:
    env_key = PACKAGE_PRICE_ENV_MAP.get(package_id)
    if not env_key:
        raise _http_400(
            f"Unsupported package_id '{package_id}'.",
            code="unsupported_package_id",
            extra={"package_id": package_id, "valid_package_ids": sorted(_VALID_PACKAGE_IDS)},
        )

    price_id = (vault.get(env_key) or "").strip()
    if not price_id:
        raise _http_500(
            f"Stripe price is not configured for package_id '{package_id}'.",
            code="billing_price_not_configured",
            extra={"package_id": package_id, "env_key": env_key},
        )
    return price_id


def _unit_credits_for_package(package_id: str) -> int:
    units = PACKAGE_UNIT_CREDITS.get(package_id)
    if units is None:
        raise _http_400(
            f"Unsupported package_id '{package_id}'.",
            code="unsupported_package_id",
            extra={"package_id": package_id, "valid_package_ids": sorted(_VALID_PACKAGE_IDS)},
        )
    return units


class CheckoutSessionCreateRequest(BaseModel):
    package_id: str | None = Field(
        default=None,
        description="IronClaw package identifier: pkg5000 | pkg25000 | pkg60000",
    )
    price_id: str = Field(
        default="",
        description="Stripe Price ID for the line item; optional when package_id is supplied",
    )
    mode: str = Field(
        default="payment",
        description="Stripe checkout mode: payment | subscription | setup",
    )
    quantity: int = Field(default=1, ge=1)
    unit_credits: int = Field(
        default=0,
        ge=0,
        description="IronClaw protection units to credit on completion",
    )
    success_url: str = Field(..., description="Redirect URL on successful payment")
    cancel_url: str = Field(..., description="Redirect URL on cancelled payment")
    customer_id: str | None = Field(
        default=None,
        description="Existing Stripe customer_id, if known",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    organizationid: str | None = Field(
        default=None,
        description="Optional frontend fallback org identifier when auth context is unavailable",
    )
    organization_id: str | None = Field(
        default=None,
        description="Optional frontend fallback org identifier when auth context is unavailable",
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        normalized = v.strip()
        if normalized not in _VALID_CHECKOUT_MODES:
            raise ValueError("invalid mode: must be payment | subscription | setup")
        return normalized

    @field_validator("package_id")
    @classmethod
    def validate_package_id(cls, v: str | None) -> str | None:
        if v is None:
            return v
        normalized = v.strip()
        if not normalized:
            return None
        if normalized not in _VALID_PACKAGE_IDS:
            raise ValueError("invalid package_id: must be pkg5000 | pkg25000 | pkg60000")
        return normalized

    @field_validator("price_id")
    @classmethod
    def normalize_price_id(cls, v: str) -> str:
        return v.strip()

    @field_validator("success_url", "cancel_url")
    @classmethod
    def validate_redirect_url(cls, v: str) -> str:
        normalized = v.strip()
        if not _is_valid_http_url(normalized):
            raise ValueError("invalid redirect URL: must be absolute http(s) URL")
        return normalized

    @field_validator("customer_id")
    @classmethod
    def normalize_customer_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip()
        return normalized or None

    @field_validator("organizationid", "organization_id")
    @classmethod
    def normalize_org_fallback(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip()
        return normalized or None


class CheckoutSessionCompleteRequest(BaseModel):
    customer_id: str | None = Field(
        default=None,
        description="Stripe customer_id returned by Stripe webhook / redirect",
    )


class CustomerCreateRequest(BaseModel):
    email: str | None = Field(default=None)
    name: str | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)
    organizationid: str | None = Field(default=None)
    organization_id: str | None = Field(default=None)


class AttachPaymentMethodRequest(BaseModel):
    payment_method_id: str = Field(..., description="Stripe PaymentMethod ID to attach")
    set_as_default: bool = Field(default=False)


class SetDefaultPaymentMethodRequest(BaseModel):
    payment_method_id: str = Field(..., description="Stripe PaymentMethod ID to set as default")


class MeteredUsageSyncRequest(BaseModel):
    subscription_item_id: str = Field(
        ...,
        description="Stripe subscription item ID with a metered price (si_xxx). This is the subscription item, not the subscription ID.",
    )
    quantity: int = Field(..., ge=0, description="Usage quantity to report")
    action: Literal["increment", "set"] = Field(default="increment", description="increment | set")
    idempotency_key: str | None = Field(default=None, description="Optional idempotency key for deduplication")


class UnitDebitRequest(BaseModel):
    token_count: int = Field(..., ge=1, description="Number of tokens to debit units for")
    reference_id: str | None = Field(default=None)


class UnitCreditRequest(BaseModel):
    units: int = Field(..., ge=1, description="Number of units to credit to the org wallet")
    reason: str = Field(default="manual.credit")
    reference_id: str | None = Field(default=None)


def _resolve_org_id_from_request(
    auth: AuthContext | None,
    request: Request | None = None,
    body: Any | None = None,
) -> str:
    auth_org_id = _resolve_org_id(auth)
    if auth_org_id:
        return auth_org_id

    body_org_id = None
    if body is not None:
        body_org_id = getattr(body, "organizationid", None) or getattr(body, "organization_id", None)
    if isinstance(body_org_id, str) and body_org_id.strip():
        return body_org_id.strip()

    if request is not None:
        query_org_id = request.query_params.get("organizationid") or request.query_params.get("organization_id")
        if query_org_id and query_org_id.strip():
            return query_org_id.strip()

    return ""


def _require_org_id(
    auth: AuthContext | None,
    request: Request | None = None,
    body: Any | None = None,
) -> str:
    org_id = _resolve_org_id_from_request(auth=auth, request=request, body=body)
    if not org_id:
        raise _http_400(
            "Organization ID could not be resolved from auth context or request.",
            code="org_id_unresolved",
            extra={"accepted_fallbacks": ["organizationid", "organization_id"]},
        )
    return org_id


def _require_customer_id(svc: StripeService, org_id: str) -> str:
    customer_id = _resolve_customer_id(svc, org_id)
    if not customer_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no_stripe_customer_for_org: No Stripe customer exists for this organization. Call POST /billing/customers first.",
        )
    return customer_id


def _get_checkout_session_record_for_auth(
    session_id: str,
    auth: AuthContext | None,
    svc: StripeService,
) -> dict[str, Any]:
    org_id = _resolve_org_id(auth)
    record = svc.get_checkout_session(session_id)
    if record is None:
        raise _http_404(
            "Checkout session not found.",
            code="checkout_session_not_found",
            extra={"session_id": session_id},
        )
    if org_id and record.get("org_id") != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "checkout_session_not_accessible",
                "detail": "Checkout session does not belong to the authenticated organization.",
                "session_id": session_id,
                "org_id": org_id,
            },
        )
    return record


def _checkout_session_status_payload(session_id: str, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "status": record.get("status", "unknown"),
        "payment_status": record.get("payment_status"),
        "mode": record.get("mode"),
        "org_id": record.get("org_id"),
        "customer_id": record.get("customer_id"),
        "unit_credits": record.get("unit_credits", 0),
        "units_credited": record.get("units_credited", False),
        "checkout_url": record.get("url"),
        "success_url": record.get("success_url"),
        "cancel_url": record.get("cancel_url"),
        "metadata": record.get("metadata", {}),
    }


def _normalize_checkout_inputs(body: CheckoutSessionCreateRequest) -> tuple[str, int]:
    package_id = (body.package_id or "").strip()
    price_id = body.price_id.strip()

    if package_id:
        resolved_price_id = _configured_price_id_for_package(package_id)
        resolved_unit_credits = body.unit_credits if body.unit_credits > 0 else _unit_credits_for_package(package_id)
        return resolved_price_id, resolved_unit_credits

    if price_id:
        if body.unit_credits <= 0:
            raise _http_400(
                "unit_credits must be greater than 0 when using a direct price_id.",
                code="unit_credits_required_for_price_id",
            )
        return price_id, body.unit_credits

    raise _http_400(
        "Either package_id or price_id is required.",
        code="price_id_or_package_id_required",
    )


@webhook_router.post(
    "/webhooks/stripe",
    status_code=status.HTTP_200_OK,
    summary="Receive and process Stripe webhook events",
    tags=["billing"],
)
async def stripe_webhook(
    request: Request,
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    verify_result = svc.verify_webhook_signature(payload=payload, signature_header=sig_header)
    if not verify_result.valid:
        logger.warning("stripe_webhook.signature_rejected error=%s", verify_result.error)
        raise _http_400(
            f"Stripe webhook signature invalid: {verify_result.error}",
            code="webhook_signature_invalid",
        )
    try:
        result = svc.handle_webhook_event(verify_result.payload)
    except StripeServiceError as exc:
        logger.warning("stripe_webhook.dispatch_error error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "webhook_dispatch_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@webhook_router.post("/billing/webhooks/stripe", status_code=status.HTTP_200_OK, tags=["billing"])
async def stripe_webhook_legacy_alias(
    request: Request,
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await stripe_webhook(request=request, svc=svc)


@webhook_router.post("/api/billing/webhooks/stripe", status_code=status.HTTP_200_OK, tags=["billing"])
async def stripe_webhook_api_alias(
    request: Request,
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await stripe_webhook(request=request, svc=svc)


@router.get("/catalogue", status_code=status.HTTP_200_OK)
async def get_billing_catalogue() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "packages": PACKAGE_CATALOGUE,
            "tokens_per_unit": TOKENS_PER_UNIT,
            "notes": f"Each protection unit covers up to {TOKENS_PER_UNIT} tokens. Scans are unlimited; units auto-deduct per chunk.",
        },
    )


@router.get("/billing-catalogue", status_code=status.HTTP_200_OK, tags=["billing"])
async def get_billing_catalogue_alias() -> JSONResponse:
    return await get_billing_catalogue()


@api_router.get("/catalogue", status_code=status.HTTP_200_OK, tags=["billing"])
async def get_billing_catalogue_api_alias() -> JSONResponse:
    return await get_billing_catalogue()


@api_router.get("/billing-catalogue", status_code=status.HTTP_200_OK, tags=["billing"])
async def get_billing_catalogue_api_legacy_alias() -> JSONResponse:
    return await get_billing_catalogue()


@router.get("/success", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def checkout_success(
    session_id: str = Query(..., description="Stripe checkout session ID"),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    record = svc.get_checkout_session(session_id)
    if record is None:
        raise _http_404(
            "Checkout session not found.",
            code="checkout_session_not_found",
            extra={"session_id": session_id},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "success",
            "session_id": session_id,
            "org_id": record.get("org_id"),
            "unit_credits": record.get("unit_credits", 0),
            "units_credited": record.get("units_credited", False),
        },
    )


@api_router.get("/success", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def checkout_success_api_alias(
    session_id: str = Query(..., description="Stripe checkout session ID"),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await checkout_success(session_id=session_id, svc=svc)


@router.post("/units/calculate", status_code=status.HTTP_200_OK)
async def calculate_units(
    token_count: int = Query(..., ge=1, description="Number of tokens to cover"),
) -> JSONResponse:
    units = units_for_tokens(token_count)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "token_count": token_count,
            "units_required": units,
            "tokens_per_unit": TOKENS_PER_UNIT,
        },
    )


@router.get("/units/calculate", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def calculate_units_get(
    token_count: int = Query(..., ge=1, description="Number of tokens to cover"),
) -> JSONResponse:
    return await calculate_units(token_count=token_count)


@api_router.post("/units/calculate", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def calculate_units_api(
    token_count: int = Query(..., ge=1, description="Number of tokens to cover"),
) -> JSONResponse:
    return await calculate_units(token_count=token_count)


@api_router.get("/units/calculate", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def calculate_units_get_api(
    token_count: int = Query(..., ge=1, description="Number of tokens to cover"),
) -> JSONResponse:
    return await calculate_units(token_count=token_count)


@router.get("/units/balance", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_balance(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    result = svc.get_unit_balance(org_id)
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.get("/unit-balance", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_balance_alias(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_balance(request=request, auth=auth, svc=svc)


@api_router.get("/units/balance", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_balance_api(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_balance(request=request, auth=auth, svc=svc)


@api_router.get("/unit-balance", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_balance_api_alias(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_balance(request=request, auth=auth, svc=svc)


@router.post("/units/debit", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def debit_units(
    body: UnitDebitRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    amount = units_for_tokens(body.token_count)
    try:
        result = svc.debit_units(
            org_id=org_id,
            amount=amount,
            reason=StripeUnitEventReason.METERED_SYNC,
            reference_id=body.reference_id,
        )
    except StripeInsufficientUnitsError as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "insufficient_units",
                "detail": "Insufficient protection units.",
                "have": exc.have,
                "need": exc.need,
                "org_id": exc.org_id,
            },
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "debit_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.post("/debit-units", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def debit_units_alias(
    body: UnitDebitRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await debit_units(body=body, request=request, auth=auth, svc=svc)


@api_router.post("/units/debit", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def debit_units_api(
    body: UnitDebitRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await debit_units(body=body, request=request, auth=auth, svc=svc)


@api_router.post("/debit-units", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def debit_units_api_alias(
    body: UnitDebitRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await debit_units(body=body, request=request, auth=auth, svc=svc)


@router.post("/units/credit", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def credit_units(
    body: UnitCreditRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    try:
        reason_enum = StripeUnitEventReason(body.reason)
    except ValueError:
        reason_enum = StripeUnitEventReason.MANUAL_CREDIT

    try:
        result = svc.credit_units(
            org_id=org_id,
            amount=body.units,
            reason=reason_enum,
            reference_id=body.reference_id,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "credit_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@api_router.post("/units/credit", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def credit_units_api(
    body: UnitCreditRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await credit_units(body=body, request=request, auth=auth, svc=svc)


@router.get("/units/ledger", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_ledger(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    result = svc.get_unit_balance(org_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "org_id": org_id,
            "balance": result.balance,
            "ledger": result.ledger_entries,
        },
    )


@router.get("/unit-ledger", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_ledger_alias(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_ledger(request=request, auth=auth, svc=svc)


@api_router.get("/units/ledger", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_ledger_api(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_ledger(request=request, auth=auth, svc=svc)


@api_router.get("/unit-ledger", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def get_unit_ledger_api_alias(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_ledger(request=request, auth=auth, svc=svc)


@router.post("/customers", status_code=status.HTTP_200_OK)
async def get_or_create_customer(
    body: CustomerCreateRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request, body=body)
    try:
        customer_id = svc.get_or_create_stripe_customer(
            org_id=org_id,
            email=body.email,
            name=body.name,
            metadata=body.metadata,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "stripe_customer_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"org_id": org_id, "customer_id": customer_id},
    )


@api_router.post("/customers", status_code=status.HTTP_200_OK, tags=["billing"])
async def get_or_create_customer_api(
    body: CustomerCreateRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_or_create_customer(body=body, request=request, auth=auth, svc=svc)


@router.post(
    "/checkout/sessions",
    status_code=status.HTTP_201_CREATED,
    tags=["billing", "checkout"],
)
async def create_checkout_session(
    body: CheckoutSessionCreateRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request, body=body)
    mode = StripeCheckoutMode(body.mode)
    resolved_price_id, resolved_unit_credits = _normalize_checkout_inputs(body)

    metadata = dict(body.metadata)
    if body.package_id:
        metadata.setdefault("package_id", body.package_id)
    metadata.setdefault("org_id", org_id)

    customer_id = body.customer_id
    if not customer_id:
        try:
            customer_id = _resolve_customer_id(svc, org_id)
        except Exception:
            customer_id = None

    try:
        result = svc.create_checkout_session(
            org_id=org_id,
            price_id=resolved_price_id,
            mode=mode,
            quantity=body.quantity,
            unit_credits=resolved_unit_credits,
            success_url=body.success_url,
            cancel_url=body.cancel_url,
            customer_id=customer_id,
            metadata=metadata,
        )
    except StripeServiceError as exc:
        logger.exception(
            "stripe_router.create_checkout_session_failed org_id=%s package_id=%s price_id=%s",
            org_id,
            body.package_id,
            resolved_price_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "stripe_checkout_error",
                "detail": str(exc),
                "org_id": org_id,
                "package_id": body.package_id,
                "price_id": resolved_price_id,
            },
        ) from exc

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=result.to_dict())


@api_router.post("/checkout/sessions", status_code=status.HTTP_201_CREATED, tags=["billing", "checkout"])
async def create_checkout_session_api(
    body: CheckoutSessionCreateRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await create_checkout_session(body=body, request=request, auth=auth, svc=svc)


@router.get("/checkout/sessions/{session_id}", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def get_checkout_session(
    session_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    record = _get_checkout_session_record_for_auth(session_id=session_id, auth=auth, svc=svc)
    return JSONResponse(status_code=status.HTTP_200_OK, content=record)


@api_router.get("/checkout/sessions/{session_id}", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def get_checkout_session_api(
    session_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_checkout_session(session_id=session_id, auth=auth, svc=svc)


@router.get("/checkout/sessions/{session_id}/status", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def get_checkout_session_status(
    session_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    record = _get_checkout_session_record_for_auth(session_id=session_id, auth=auth, svc=svc)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=_checkout_session_status_payload(session_id=session_id, record=record),
    )


@api_router.get("/checkout/sessions/{session_id}/status", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def get_checkout_session_status_api(
    session_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_checkout_session_status(session_id=session_id, auth=auth, svc=svc)


@router.get("/checkout/status", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def get_checkout_status_by_query(
    session_id: str = Query(..., description="Stripe checkout session ID"),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    record = _get_checkout_session_record_for_auth(session_id=session_id, auth=auth, svc=svc)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=_checkout_session_status_payload(session_id=session_id, record=record),
    )


@api_router.get("/checkout/status", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def get_checkout_status_by_query_api(
    session_id: str = Query(..., description="Stripe checkout session ID"),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_checkout_status_by_query(session_id=session_id, auth=auth, svc=svc)


@router.post("/checkout/sessions/{session_id}/complete", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def complete_checkout_session(
    session_id: str,
    body: CheckoutSessionCompleteRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    try:
        result = svc.complete_checkout_session(
            session_id=session_id,
            customer_id=body.customer_id,
        )
    except StripeSessionNotFoundError as exc:
        raise _http_404(
            "Checkout session not found.",
            code="checkout_session_not_found",
            extra={"session_id": session_id},
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "complete_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@api_router.post("/checkout/sessions/{session_id}/complete", status_code=status.HTTP_200_OK, tags=["billing", "checkout"])
async def complete_checkout_session_api(
    session_id: str,
    body: CheckoutSessionCompleteRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await complete_checkout_session(session_id=session_id, body=body, auth=auth, svc=svc)


@router.get("/subscriptions/{subscription_id}", status_code=status.HTTP_200_OK, tags=["billing", "subscriptions"])
async def get_subscription(
    subscription_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    try:
        result = svc.get_subscription(subscription_id)
    except StripeSubscriptionNotFoundError as exc:
        raise _http_404(
            "Subscription not found.",
            code="subscription_not_found",
            extra={"subscription_id": subscription_id},
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "subscription_fetch_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@api_router.get("/subscriptions/{subscription_id}", status_code=status.HTTP_200_OK, tags=["billing", "subscriptions"])
async def get_subscription_api(
    subscription_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_subscription(subscription_id=subscription_id, auth=auth, svc=svc)


@router.post("/metered/sync", status_code=status.HTTP_200_OK, tags=["billing", "metered"])
async def sync_metered_usage(
    body: MeteredUsageSyncRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    try:
        result = svc.report_metered_usage(
            org_id=org_id,
            subscription_item_id=body.subscription_item_id,
            quantity=body.quantity,
            action=body.action,
            idempotency_key=body.idempotency_key,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "metered_sync_error", "detail": str(exc)},
        ) from exc

    if body.quantity > 0:
        ref = getattr(result, "idempotency_key", None)
        try:
            svc.debit_units(
                org_id=org_id,
                amount=body.quantity,
                reason=StripeUnitEventReason.METERED_SYNC,
                reference_id=ref,
            )
        except StripeInsufficientUnitsError:
            logger.warning(
                "stripe_router.metered_sync insufficient_units org=%s quantity=%d usage reported to Stripe but debit skipped",
                org_id,
                body.quantity,
            )
        except StripeServiceError as exc:
            logger.error(
                "stripe_router.metered_sync debit_error org=%s error=%s",
                org_id,
                exc,
            )

    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.post("/metered-sync", status_code=status.HTTP_200_OK, tags=["billing", "metered"])
async def sync_metered_usage_alias(
    body: MeteredUsageSyncRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await sync_metered_usage(body=body, request=request, auth=auth, svc=svc)


@api_router.post("/metered/sync", status_code=status.HTTP_200_OK, tags=["billing", "metered"])
async def sync_metered_usage_api(
    body: MeteredUsageSyncRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await sync_metered_usage(body=body, request=request, auth=auth, svc=svc)


@api_router.post("/metered-sync", status_code=status.HTTP_200_OK, tags=["billing", "metered"])
async def sync_metered_usage_api_alias(
    body: MeteredUsageSyncRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await sync_metered_usage(body=body, request=request, auth=auth, svc=svc)


@router.get("/metered/log", status_code=status.HTTP_200_OK, tags=["billing", "metered"])
async def get_metered_usage_log(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    entries = svc.get_metered_usage_log(org_id=org_id, limit=limit)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"org_id": org_id, "count": len(entries), "entries": entries},
    )


@api_router.get("/metered/log", status_code=status.HTTP_200_OK, tags=["billing", "metered"])
async def get_metered_usage_log_api(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_metered_usage_log(request=request, limit=limit, auth=auth, svc=svc)


@router.post("/payment-methods/attach", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def attach_payment_method(
    body: AttachPaymentMethodRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    customer_id = _require_customer_id(svc, org_id)
    try:
        result = svc.attach_payment_method(
            customer_id=customer_id,
            payment_method_id=body.payment_method_id,
            set_as_default=body.set_as_default,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "attach_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.post("/payment-methods", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def attach_payment_method_alias(
    body: AttachPaymentMethodRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await attach_payment_method(body=body, request=request, auth=auth, svc=svc)


@api_router.post("/payment-methods/attach", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def attach_payment_method_api(
    body: AttachPaymentMethodRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await attach_payment_method(body=body, request=request, auth=auth, svc=svc)


@api_router.post("/payment-methods", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def attach_payment_method_api_alias(
    body: AttachPaymentMethodRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await attach_payment_method(body=body, request=request, auth=auth, svc=svc)


@router.post("/payment-methods/{payment_method_id}/detach", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def detach_payment_method(
    payment_method_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    try:
        result = svc.detach_payment_method(payment_method_id=payment_method_id)
    except StripePaymentMethodNotFoundError as exc:
        raise _http_404(
            "Payment method not found.",
            code="payment_method_not_found",
            extra={"payment_method_id": payment_method_id},
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "detach_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@api_router.post("/payment-methods/{payment_method_id}/detach", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def detach_payment_method_api(
    payment_method_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await detach_payment_method(payment_method_id=payment_method_id, auth=auth, svc=svc)


@router.get("/payment-methods", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def list_payment_methods(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    customer_id = _resolve_customer_id(svc, org_id)
    if not customer_id:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "org_id": org_id,
                "customer_id": None,
                "payment_methods": [],
            },
        )

    results = svc.list_payment_methods(customer_id=customer_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "org_id": org_id,
            "customer_id": customer_id,
            "count": len(results),
            "payment_methods": [r.to_dict() for r in results],
        },
    )


@api_router.get("/payment-methods", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def list_payment_methods_api(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await list_payment_methods(request=request, auth=auth, svc=svc)


@router.post("/payment-methods/{payment_method_id}/set-default", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def set_default_payment_method(
    payment_method_id: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    customer_id = _require_customer_id(svc, org_id)
    try:
        result = svc.set_default_payment_method(
            customer_id=customer_id,
            payment_method_id=payment_method_id,
        )
    except StripePaymentMethodNotFoundError as exc:
        raise _http_404(
            "Payment method not found.",
            code="payment_method_not_found",
            extra={"payment_method_id": payment_method_id},
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "set_default_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.post("/payment-methods/default", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def set_default_payment_method_alias(
    body: SetDefaultPaymentMethodRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await set_default_payment_method(
        payment_method_id=body.payment_method_id,
        request=request,
        auth=auth,
        svc=svc,
    )


@api_router.post("/payment-methods/{payment_method_id}/set-default", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def set_default_payment_method_api(
    payment_method_id: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await set_default_payment_method(
        payment_method_id=payment_method_id,
        request=request,
        auth=auth,
        svc=svc,
    )


@api_router.post("/payment-methods/default", status_code=status.HTTP_200_OK, tags=["billing", "payment-methods"])
async def set_default_payment_method_api_alias(
    body: SetDefaultPaymentMethodRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await set_default_payment_method_alias(body=body, request=request, auth=auth, svc=svc)


@router.get("/invoices", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def list_invoices(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    try:
        results = svc.get_invoices_for_org(
            org_id=org_id,
            limit=limit,
            force_refresh=force_refresh,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "invoice_fetch_error", "detail": str(exc)},
        ) from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "org_id": org_id,
            "count": len(results),
            "invoices": [r.to_dict() for r in results],
        },
    )


@router.get("/invoice-history", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def list_invoices_alias(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await list_invoices(
        request=request,
        limit=limit,
        force_refresh=force_refresh,
        auth=auth,
        svc=svc,
    )


@api_router.get("/invoices", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def list_invoices_api(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await list_invoices(request=request, limit=limit, force_refresh=force_refresh, auth=auth, svc=svc)


@api_router.get("/invoice-history", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def list_invoices_api_alias(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await list_invoices(request=request, limit=limit, force_refresh=force_refresh, auth=auth, svc=svc)


@router.delete("/invoices/cache", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def invalidate_invoice_cache(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    svc.invalidate_invoice_cache(org_id=org_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"invalidated": True, "org_id": org_id},
    )


@api_router.delete("/invoices/cache", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def invalidate_invoice_cache_api(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await invalidate_invoice_cache(request=request, auth=auth, svc=svc)


router.include_router(api_router)
