from __future__ import annotations

import logging
from typing import Any, Literal

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


# ---------------------------------------------------------------------------
# Public webhook router
# ---------------------------------------------------------------------------

_stripe_service_instance: StripeService | None = None


def get_stripe_service() -> StripeService:
    global _stripe_service_instance  # noqa: PLW0603
    if _stripe_service_instance is None:
        _stripe_service_instance = StripeService()
    return _stripe_service_instance


def _resolve_org_id(auth: AuthContext) -> str:
    oid = getattr(auth, "org_id", None) or getattr(auth, "tenant_id", None) or ""
    return str(oid)


def _resolve_customer_id(svc: StripeService, org_id: str) -> str | None:
    with svc._lock:  # noqa: SLF001
        return svc._org_customer_map.get(org_id)  # noqa: SLF001


# ---------------------------------------------------------------------------
# Package helpers
# ---------------------------------------------------------------------------

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


def _configured_price_id_for_package(package_id: str) -> str:
    env_key = PACKAGE_PRICE_ENV_MAP.get(package_id)
    if not env_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported_package_id:{package_id}",
        )
    price_id = vault.get(env_key) or ""
    price_id = price_id.strip()
    if not price_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"billing_price_not_configured:{env_key}",
        )
    return price_id


def _unit_credits_for_package(package_id: str) -> int:
    units = PACKAGE_UNIT_CREDITS.get(package_id)
    if units is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported_package_id:{package_id}",
        )
    return units


def _normalize_checkout_inputs(body: CheckoutSessionCreateRequest) -> tuple[str, int]:
    package_id = (body.package_id or "").strip()
    price_id = body.price_id.strip()

    if package_id:
        resolved_price_id = _configured_price_id_for_package(package_id)
        resolved_unit_credits = body.unit_credits if body.unit_credits > 0 else _unit_credits_for_package(package_id)
        return resolved_price_id, resolved_unit_credits

    if price_id:
        return price_id, body.unit_credits

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="price_id_or_package_id_required",
    )


# ---------------------------------------------------------------------------
# Validation sets
# ---------------------------------------------------------------------------

_VALID_CHECKOUT_MODES: frozenset[str] = frozenset(m.value for m in StripeCheckoutMode)
_VALID_METERED_ACTIONS: frozenset[str] = frozenset({"increment", "set"})
_VALID_PACKAGE_IDS: frozenset[str] = frozenset(PACKAGE_PRICE_ENV_MAP.keys())


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
    success_url: str = Field(
        ...,
        description="Redirect URL on successful payment",
    )
    cancel_url: str = Field(
        ...,
        description="Redirect URL on cancelled payment",
    )
    customer_id: str | None = Field(
        default=None,
        description="Existing Stripe customer_id, if known",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in _VALID_CHECKOUT_MODES:
            raise ValueError(f"invalid mode '{v}': must be payment | subscription | setup")
        return v

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


class CheckoutSessionCompleteRequest(BaseModel):
    customer_id: str | None = Field(
        default=None,
        description="Stripe customer_id returned by Stripe webhook / redirect",
    )


class CustomerCreateRequest(BaseModel):
    email: str | None = Field(default=None)
    name: str | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_org_id(auth: AuthContext) -> str:
    org_id = _resolve_org_id(auth)
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="org_id could not be resolved",
        )
    return org_id


def _require_customer_id(svc: StripeService, org_id: str) -> str:
    customer_id = _resolve_customer_id(svc, org_id)
    if not customer_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no_stripe_customer_for_org; call POST /billing/customers first",
        )
    return customer_id


def _stripe_error_response(exc: StripeServiceError, detail: str, http_status: int) -> JSONResponse:
    logger.error("stripe_router.error detail=%s error=%s", detail, exc)
    return JSONResponse(
        status_code=http_status,
        content={"error": detail, "message": str(exc)},
    )


def _get_checkout_session_record_for_auth(
    session_id: str,
    auth: AuthContext,
    svc: StripeService,
) -> dict[str, Any]:
    org_id = _resolve_org_id(auth)
    record = svc.get_checkout_session(session_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="checkout_session_not_found",
        )
    if org_id and record.get("org_id") != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="checkout_session_not_accessible",
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


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


@webhook_router.post(
    "/webhooks/stripe",
    status_code=status.HTTP_200_OK,
    summary="Receive and process Stripe webhook events",
    description=("Inbound endpoint for Stripe webhook delivery. Verifies the stripe-signature header using STRIPE_WEBHOOK_SECRET. Handles checkout.session.completed (credits units), invoice.payment_succeeded, customer.subscription.deleted, payment_intent.succeeded, charge.succeeded."),
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"webhook_signature_invalid: {verify_result.error}",
        )
    try:
        result = svc.handle_webhook_event(verify_result.payload)
    except StripeServiceError as exc:
        logger.warning("stripe_webhook.dispatch_error error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"webhook_dispatch_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@webhook_router.post(
    "/billing/webhooks/stripe",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for Stripe webhook events",
    tags=["billing"],
)
async def stripe_webhook_legacy_alias(
    request: Request,
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await stripe_webhook(request=request, svc=svc)


# ---------------------------------------------------------------------------
# Public catalogue / redirect helpers
# ---------------------------------------------------------------------------


@router.get(
    "/catalogue",
    status_code=status.HTTP_200_OK,
    summary="Return IronClaw billing tier catalogue",
    description=("Returns all available IronClaw protection unit packages with pricing. Starter: 5,000 units / $20. Team: 25,000 units / $90. Enterprise: 60,000 units / $180. Each unit covers up to 25,000 tokens with no scan ceiling. Public endpoint; no auth required."),
)
async def get_billing_catalogue() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "packages": PACKAGE_CATALOGUE,
            "tokens_per_unit": TOKENS_PER_UNIT,
            "notes": (f"Each protection unit covers up to {TOKENS_PER_UNIT} tokens. Scans are unlimited; units auto-deduct per chunk."),
        },
    )


@router.get(
    "/billing-catalogue",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for billing catalogue",
    tags=["billing"],
)
async def get_billing_catalogue_alias() -> JSONResponse:
    return await get_billing_catalogue()


@router.get(
    "/success",
    status_code=status.HTTP_200_OK,
    summary="Checkout success confirmation",
    description=("Called by Stripe redirect after a successful checkout. Returns session confirmation. Frontend should use this to verify and display unit balance."),
    tags=["billing", "checkout"],
)
async def checkout_success(
    session_id: str = Query(..., description="Stripe checkout session ID"),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    record = svc.get_checkout_session(session_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="checkout_session_not_found",
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


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


@router.post(
    "/units/calculate",
    status_code=status.HTTP_200_OK,
    summary="Calculate units required for a token count",
    description=("Returns how many IronClaw protection units are needed to cover a given token count. Uses ceiling division at 25,000 tokens per unit."),
)
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


@router.get(
    "/units/calculate",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for calculate units",
    tags=["billing", "units"],
)
async def calculate_units_get(
    token_count: int = Query(..., ge=1, description="Number of tokens to cover"),
) -> JSONResponse:
    return await calculate_units(token_count=token_count)


@router.get(
    "/units/balance",
    status_code=status.HTTP_200_OK,
    summary="Get the org's current protection unit balance",
    description=("Returns current unit balance and full ledger history. Each unit covers up to 25,000 tokens with no scan ceiling."),
    tags=["billing", "units"],
)
async def get_unit_balance(
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
    result = svc.get_unit_balance(org_id)
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.get(
    "/unit-balance",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for unit balance",
    tags=["billing", "units"],
)
async def get_unit_balance_alias(
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_balance(auth=auth, svc=svc)


@router.post(
    "/units/debit",
    status_code=status.HTTP_200_OK,
    summary="Debit protection units for a token-consuming operation",
    description=("Converts token_count to required units via ceiling division at 25,000 tokens/unit, then debits the org wallet. Raises 402 if balance is insufficient. Scans have no ceiling; units must simply be available."),
    tags=["billing", "units"],
)
async def debit_units(
    body: UnitDebitRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
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
                "have": exc.have,
                "need": exc.need,
                "org_id": exc.org_id,
            },
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"debit_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.post(
    "/debit-units",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for debit units",
    tags=["billing", "units"],
)
async def debit_units_alias(
    body: UnitDebitRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await debit_units(body=body, auth=auth, svc=svc)


@router.post(
    "/units/credit",
    status_code=status.HTTP_200_OK,
    summary="Credit protection units to an org wallet",
    description=("Admin/internal endpoint. Credits the specified number of units to the org. Use reason to describe the credit source."),
    tags=["billing", "units"],
)
async def credit_units(
    body: UnitCreditRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
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
            detail=f"credit_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.get(
    "/units/ledger",
    status_code=status.HTTP_200_OK,
    summary="Get the full unit ledger for the authenticated org",
    tags=["billing", "units"],
)
async def get_unit_ledger(
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
    result = svc.get_unit_balance(org_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "org_id": org_id,
            "balance": result.balance,
            "ledger": result.ledger_entries,
        },
    )


@router.get(
    "/unit-ledger",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for unit ledger",
    tags=["billing", "units"],
)
async def get_unit_ledger_alias(
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await get_unit_ledger(auth=auth, svc=svc)


# ---------------------------------------------------------------------------
# Customers / checkout
# ---------------------------------------------------------------------------


@router.post(
    "/customers",
    status_code=status.HTTP_200_OK,
    summary="Get or create a Stripe customer for the authenticated org",
    description=("Returns existing Stripe customer_id if already registered. Creates a new one if not. Idempotent per org."),
)
async def get_or_create_customer(
    body: CustomerCreateRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
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
            detail=f"stripe_customer_error: {exc}",
        ) from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"org_id": org_id, "customer_id": customer_id},
    )


@router.post(
    "/checkout/sessions",
    status_code=status.HTTP_201_CREATED,
    summary="Create a Stripe Checkout Session",
    description=(
        "Creates a Stripe Checkout session for one-time payment or subscription. "
        "Accepts either a direct Stripe price_id or an IronClaw package_id. "
        "When package_id is supplied, the backend resolves the Stripe price from "
        "BILLING_TIER_5K_PRICE_ID, BILLING_TIER_25K_PRICE_ID, BILLING_TIER_60K_PRICE_ID. "
        "On checkout.session.completed, IronClaw credits unit_credits protection units to the org wallet."
    ),
    tags=["billing", "checkout"],
)
async def create_checkout_session(
    body: CheckoutSessionCreateRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
    mode = StripeCheckoutMode(body.mode)
    resolved_price_id, resolved_unit_credits = _normalize_checkout_inputs(body)
    metadata = dict(body.metadata)
    if body.package_id:
        metadata.setdefault("package_id", body.package_id)

    try:
        result = svc.create_checkout_session(
            org_id=org_id,
            price_id=resolved_price_id,
            mode=mode,
            quantity=body.quantity,
            unit_credits=resolved_unit_credits,
            success_url=body.success_url,
            cancel_url=body.cancel_url,
            customer_id=body.customer_id,
            metadata=metadata,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"stripe_checkout_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=result.to_dict())


@router.get(
    "/checkout/sessions/{session_id}",
    status_code=status.HTTP_200_OK,
    summary="Get a checkout session by ID",
    tags=["billing", "checkout"],
)
async def get_checkout_session(
    session_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    record = _get_checkout_session_record_for_auth(session_id=session_id, auth=auth, svc=svc)
    return JSONResponse(status_code=status.HTTP_200_OK, content=record)


@router.get(
    "/checkout/sessions/{session_id}/status",
    status_code=status.HTTP_200_OK,
    summary="Get checkout session status by ID",
    tags=["billing", "checkout"],
)
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


@router.get(
    "/checkout/status",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for checkout session status",
    tags=["billing", "checkout"],
)
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


@router.post(
    "/checkout/sessions/{session_id}/complete",
    status_code=status.HTTP_200_OK,
    summary="Manually complete a checkout session and credit units",
    description=("Idempotent. Credits unit_credits to the org wallet. Intended for internal tooling and integration tests. Production fulfillment is driven by the Stripe webhook at POST /webhooks/stripe."),
    tags=["billing", "checkout"],
)
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="checkout_session_not_found",
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"complete_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.get(
    "/subscriptions/{subscription_id}",
    status_code=status.HTTP_200_OK,
    summary="Get a subscription record by ID",
    tags=["billing", "subscriptions"],
)
async def get_subscription(
    subscription_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    try:
        result = svc.get_subscription(subscription_id)
    except StripeSubscriptionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="subscription_not_found",
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"subscription_fetch_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


# ---------------------------------------------------------------------------
# Metered usage
# ---------------------------------------------------------------------------


@router.post(
    "/metered/sync",
    status_code=status.HTTP_200_OK,
    summary="Sync metered usage to Stripe for a subscription item",
    description=("Reports usage quantity to Stripe for a metered-price subscription item (si_xxx). Uses subscription_item_id, not subscription ID. Idempotent when idempotency_key is supplied. Also debits org unit balance via StripeUnitEventReason.METERED_SYNC."),
    tags=["billing", "metered"],
)
async def sync_metered_usage(
    body: MeteredUsageSyncRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
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
            detail=f"metered_sync_error: {exc}",
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


@router.post(
    "/metered-sync",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for metered sync",
    tags=["billing", "metered"],
)
async def sync_metered_usage_alias(
    body: MeteredUsageSyncRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await sync_metered_usage(body=body, auth=auth, svc=svc)


@router.get(
    "/metered/log",
    status_code=status.HTTP_200_OK,
    summary="Get metered usage log for the org",
    tags=["billing", "metered"],
)
async def get_metered_usage_log(
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
    entries = svc.get_metered_usage_log(org_id=org_id, limit=limit)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"org_id": org_id, "count": len(entries), "entries": entries},
    )


# ---------------------------------------------------------------------------
# Payment methods
# ---------------------------------------------------------------------------


@router.post(
    "/payment-methods/attach",
    status_code=status.HTTP_200_OK,
    summary="Attach a Stripe PaymentMethod to the org customer",
    tags=["billing", "payment-methods"],
)
async def attach_payment_method(
    body: AttachPaymentMethodRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
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
            detail=f"attach_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.post(
    "/payment-methods",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for attach payment method",
    tags=["billing", "payment-methods"],
)
async def attach_payment_method_alias(
    body: AttachPaymentMethodRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await attach_payment_method(body=body, auth=auth, svc=svc)


@router.post(
    "/payment-methods/{payment_method_id}/detach",
    status_code=status.HTTP_200_OK,
    summary="Detach a PaymentMethod from its customer",
    tags=["billing", "payment-methods"],
)
async def detach_payment_method(
    payment_method_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    try:
        result = svc.detach_payment_method(payment_method_id=payment_method_id)
    except StripePaymentMethodNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="payment_method_not_found",
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"detach_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.get(
    "/payment-methods",
    status_code=status.HTTP_200_OK,
    summary="List payment methods for the org",
    tags=["billing", "payment-methods"],
)
async def list_payment_methods(
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
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


@router.post(
    "/payment-methods/{payment_method_id}/set-default",
    status_code=status.HTTP_200_OK,
    summary="Set a payment method as the default for the org customer",
    tags=["billing", "payment-methods"],
)
async def set_default_payment_method(
    payment_method_id: str,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
    customer_id = _require_customer_id(svc, org_id)
    try:
        result = svc.set_default_payment_method(
            customer_id=customer_id,
            payment_method_id=payment_method_id,
        )
    except StripePaymentMethodNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="payment_method_not_found",
        ) from exc
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"set_default_error: {exc}",
        ) from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


@router.post(
    "/payment-methods/default",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for setting default payment method",
    tags=["billing", "payment-methods"],
)
async def set_default_payment_method_alias(
    body: SetDefaultPaymentMethodRequest,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await set_default_payment_method(
        payment_method_id=body.payment_method_id,
        auth=auth,
        svc=svc,
    )


# ---------------------------------------------------------------------------
# Invoices
# ---------------------------------------------------------------------------


@router.get(
    "/invoices",
    status_code=status.HTTP_200_OK,
    summary="List invoices for the org",
    description=("Returns cached invoice list for the org. Pass force_refresh=true to bypass cache and re-fetch from Stripe."),
    tags=["billing", "invoices"],
)
async def list_invoices(
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
    try:
        results = svc.get_invoices_for_org(
            org_id=org_id,
            limit=limit,
            force_refresh=force_refresh,
        )
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"invoice_fetch_error: {exc}",
        ) from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "org_id": org_id,
            "count": len(results),
            "invoices": [r.to_dict() for r in results],
        },
    )


@router.get(
    "/invoice-history",
    status_code=status.HTTP_200_OK,
    summary="Compatibility alias for invoices",
    tags=["billing", "invoices"],
)
async def list_invoices_alias(
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await list_invoices(
        limit=limit,
        force_refresh=force_refresh,
        auth=auth,
        svc=svc,
    )


@router.delete(
    "/invoices/cache",
    status_code=status.HTTP_200_OK,
    summary="Invalidate the invoice cache for the org",
    tags=["billing", "invoices"],
)
async def invalidate_invoice_cache(
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth)
    svc.invalidate_invoice_cache(org_id=org_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"invalidated": True, "org_id": org_id},
    )
