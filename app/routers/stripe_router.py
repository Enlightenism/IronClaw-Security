from __future__ import annotations

import logging
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator

from app.core.auth import AuthContext, get_auth_context
from app.core.billing import (
    PACKAGE_ALIASES,
    PLAN_DEFINITIONS,
    resolve_authenticated_billing_owner,
    resolve_package_id,
    resolve_plan_code,
)
from app.core.permissions import require_permission
from app.core.settings import get_settings
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
    with svc.lock:  # noqa: SLF001
        return svc.org_customer_map.get(org_id)  # noqa: SLF001


PACKAGE_PRICE_ENV_MAP: dict[str, str] = {
    "starter-5k": "BILLING_TIER_5K_PRICE_ID",
    "team-25k": "BILLING_TIER_25K_PRICE_ID",
    "enterprise-60k": "BILLING_TIER_60K_PRICE_ID",
}

VALID_CHECKOUT_MODES: frozenset[str] = frozenset(m.value for m in StripeCheckoutMode)
VALID_PACKAGE_IDS = PACKAGE_ALIASES

# Keep redirect validation aligned with the same canonical domain family used by settings.
# This prevents the billing flow from behaving like different apps depending on whether the
# user lands on the bare domain, the www alias, or a local dev origin.
ALLOWED_REDIRECT_HOSTS: frozenset[str] = frozenset(
    {
        "moving-forward.ca",
        "ironclaw-security.pages.dev",
        "localhost",
        "127.0.0.1",
    }
)


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


def _canonical_redirect_host(value: str) -> str:
    if not isinstance(value, str):
        value = str(value)

    cleaned = value.strip().lower()
    if not cleaned:
        return ""

    try:
        parsed = urlparse(cleaned)
    except Exception:
        return ""

    host = (parsed.netloc or parsed.path or "").strip()
    if not host:
        return ""

    if host.startswith("[") and "]" in host:
        host = host.strip("[]")

    if ":" in host and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]

    return host.removeprefix("www.")


def _normalized_host_name(value: str) -> str:
    return _canonical_redirect_host(value)


def _allowed_redirect_hosts() -> frozenset[str]:
    """Return the canonical redirect hosts used by the active app configuration."""
    hosts = set(ALLOWED_REDIRECT_HOSTS)
    try:
        settings = get_settings()
        for host in getattr(settings, "effective_allowed_redirect_hosts", []):
            canonical = _canonical_redirect_host(host)
            if canonical:
                hosts.add(canonical)

        for origin in getattr(settings, "effective_allowed_origins", []):
            canonical = _canonical_redirect_host(origin)
            if canonical:
                hosts.add(canonical)

        app_base = getattr(settings, "normalized_app_base_url", "")
        app_host = _canonical_redirect_host(app_base)
        if app_host:
            hosts.add(app_host)

        if not settings.is_production:
            hosts.update({"localhost", "127.0.0.1"})
    except Exception:
        pass
    return frozenset(hosts)


def _is_allowed_redirect_url(value: str) -> bool:
    if not _is_valid_http_url(value):
        return False
    host = _normalized_host_name(value)
    return host in _allowed_redirect_hosts()


def _configured_price_id_for_package(package_id: str) -> str:
    plan_code = resolve_plan_code(package_id)
    env_key = PACKAGE_PRICE_ENV_MAP.get(plan_code or "")
    if not env_key:
        raise _http_400(
            f"Unsupported package_id '{package_id}'.",
            code="unsupported_package_id",
            extra={"package_id": package_id, "valid_package_ids": sorted(VALID_PACKAGE_IDS)},
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
    plan_code = resolve_plan_code(package_id)
    if plan_code is None:
        raise _http_400(
            f"Unsupported package_id '{package_id}'.",
            code="unsupported_package_id",
            extra={"package_id": package_id, "valid_package_ids": sorted(VALID_PACKAGE_IDS)},
        )
    return PLAN_DEFINITIONS[plan_code]["unit_limit"]


def _coerce_optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return None


def _is_auth_required() -> bool:
    try:
        settings = get_settings()
    except Exception:
        return True

    explicit = _coerce_optional_bool(getattr(settings, "auth_required", None))
    if explicit is not None:
        return explicit
    return True


def _allow_anonymous_checkout() -> bool:
    return not _is_auth_required()


def _anonymous_auth_context() -> AuthContext:
    return AuthContext(
        api_key=None,
        principal_type="anonymous",
        principal_id=None,
        session_id=None,
        org_id=None,
        authenticated=False,
        auth_source="disabled",
        auth_method=None,
        key_type="personal",
    )


def get_optional_auth_context(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    if getattr(auth, "principal_type", None) == "preflight":
        return auth
    return auth


def get_checkout_auth_context(
    request: Request,
    auth: AuthContext = Depends(get_optional_auth_context),
) -> AuthContext:
    if getattr(auth, "principal_type", None) == "preflight":
        return auth

    auth_source = str(getattr(auth, "auth_source", "") or "").strip().lower()
    auth_method = str(getattr(auth, "auth_method", "") or "").strip().lower()
    authorization_header = request.headers.get("authorization", "").strip()

    if getattr(auth, "authenticated", False):
        return auth

    if auth_source == "bearer" or auth_method == "bearer":
        return auth

    if authorization_header.lower().startswith("bearer "):
        return auth

    if _allow_anonymous_checkout():
        return _anonymous_auth_context()

    return auth


class CheckoutSessionCreateRequest(BaseModel):
    package_id: str | None = Field(
        default=None,
        alias="packageId",
        description="IronClaw package ID or supported alias",
    )
    price_id: str = Field(
        default="",
        alias="priceId",
        description="Stripe Price ID for the line item; optional when package_id is supplied",
    )
    mode: str = Field(
        default="payment",
        description="Stripe checkout mode: payment, subscription, setup",
    )
    quantity: int = Field(default=1, ge=1)
    unit_credits: int = Field(
        default=0,
        alias="unitCredits",
        ge=0,
        description="IronClaw protection units to credit on completion",
    )
    success_url: str = Field(..., alias="successUrl", description="Redirect URL on successful payment")
    cancel_url: str = Field(..., alias="cancelUrl", description="Redirect URL on cancelled payment")
    customer_id: str | None = Field(default=None, alias="customerId", description="Existing Stripe customer ID")
    metadata: dict[str, Any] = Field(default_factory=dict)
    organization_id: str | None = Field(default=None, alias="organizationId")
    organizationid: str | None = Field(default=None)
    org_id: str | None = Field(default=None, alias="orgId")

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, value: str) -> str:
        normalized = value.strip()
        if normalized not in VALID_CHECKOUT_MODES:
            raise ValueError("invalid mode, must be one of: payment, subscription, setup")
        return normalized

    @field_validator("package_id")
    @classmethod
    def validate_package_id(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if not normalized:
            return None
        canonical_package_id = resolve_package_id(normalized)
        if canonical_package_id is None:
            raise ValueError(f"invalid package_id, supported identifiers: {', '.join(sorted(VALID_PACKAGE_IDS))}")
        return canonical_package_id

    @field_validator("price_id")
    @classmethod
    def normalize_price_id(cls, value: str) -> str:
        return value.strip()

    @field_validator("success_url", "cancel_url")
    @classmethod
    def validate_redirect_url(cls, value: str) -> str:
        normalized = value.strip()
        if not _is_valid_http_url(normalized):
            raise ValueError("invalid redirect URL, must be absolute http(s) URL")
        if not _is_allowed_redirect_url(normalized):
            # Provide a clear, structured validation message for frontend operators.
            allowed = sorted(list(_allowed_redirect_hosts()))
            raise ValueError(f"invalid redirect URL host; allowed_hosts={allowed}")
        return normalized

    @field_validator("customer_id", "organization_id", "organizationid", "org_id")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class CheckoutSessionCompleteRequest(BaseModel):
    customer_id: str | None = Field(default=None, alias="customerId", description="Stripe customer ID returned by Stripe")

    @field_validator("customer_id")
    @classmethod
    def normalize_customer_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class CustomerCreateRequest(BaseModel):
    email: str | None = Field(default=None)
    name: str | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)
    organization_id: str | None = Field(default=None, alias="organizationId")
    organizationid: str | None = Field(default=None)
    org_id: str | None = Field(default=None, alias="orgId")

    @field_validator("email", "name", "organization_id", "organizationid", "org_id")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class AttachPaymentMethodRequest(BaseModel):
    payment_method_id: str = Field(..., alias="paymentMethodId", description="Stripe PaymentMethod ID to attach")
    set_as_default: bool = Field(default=False, alias="setAsDefault")

    @field_validator("payment_method_id")
    @classmethod
    def normalize_payment_method_id(cls, value: str) -> str:
        return value.strip()


class SetDefaultPaymentMethodRequest(BaseModel):
    payment_method_id: str = Field(..., alias="paymentMethodId", description="Stripe PaymentMethod ID to set as default")

    @field_validator("payment_method_id")
    @classmethod
    def normalize_payment_method_id(cls, value: str) -> str:
        return value.strip()


class MeteredUsageSyncRequest(BaseModel):
    subscription_item_id: str = Field(..., alias="subscriptionItemId")
    quantity: int = Field(..., ge=0)
    action: Literal["increment", "set"] = Field(default="increment")
    idempotency_key: str | None = Field(default=None, alias="idempotencyKey")

    @field_validator("subscription_item_id", "idempotency_key")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class UnitDebitRequest(BaseModel):
    token_count: int = Field(..., alias="tokenCount", ge=1)
    reference_id: str | None = Field(default=None, alias="referenceId")

    @field_validator("reference_id")
    @classmethod
    def normalize_reference_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class UnitCreditRequest(BaseModel):
    units: int = Field(..., ge=1)
    reason: str = Field(default="manual.credit")
    reference_id: str | None = Field(default=None, alias="referenceId")

    @field_validator("reason", "reference_id")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


def _resolve_org_id_from_request(
    auth: AuthContext | None,
    request: Request | None = None,
    body: Any | None = None,
) -> str:
    auth_org_id = _resolve_org_id(auth)
    if auth_org_id:
        return auth_org_id

    if body is not None:
        body_org_id = getattr(body, "organization_id", None) or getattr(body, "organizationid", None) or getattr(body, "org_id", None)
        if isinstance(body_org_id, str) and body_org_id.strip():
            return body_org_id.strip()

    if request is not None:
        query_org_id = request.query_params.get("organizationId") or request.query_params.get("organizationid") or request.query_params.get("orgId")
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
            extra={"accepted_fallbacks": ["organizationId", "organizationid", "orgId"]},
        )
    return org_id


def _require_customer_id(svc: StripeService, org_id: str) -> str:
    customer_id = _resolve_customer_id(svc, org_id)
    if not customer_id:
        # Return structured error object for frontend consumption
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "no_stripe_customer_for_org",
                "detail": "No Stripe customer exists for this organization. Call POST /billing/customers first.",
                "org_id": org_id,
            },
        )
    return customer_id


def _get_checkout_session_record_for_auth(
    session_id: str,
    auth: AuthContext | None,
    svc: StripeService,
) -> dict[str, Any]:
    org_id = _resolve_org_id(auth)
    if auth is None or getattr(auth, "authenticated", False) is not True:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "authentication_required",
                "detail": "Authentication is required to verify a checkout session.",
            },
        )

    try:
        record = svc.retrieve_checkout_session(session_id)
    except StripeSessionNotFoundError as exc:
        raise _http_404(
            "Checkout session not found.",
            code="checkout_session_not_found",
            extra={"session_id": session_id},
        ) from exc
    except StripeServiceError as exc:
        logger.warning(
            "stripe_router.checkout_session_lookup_failed session_id=%s error_type=%s",
            session_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "checkout_session_status_unavailable",
                "detail": "Stripe checkout status is temporarily unavailable.",
                "session_id": session_id,
            },
        ) from exc

    if record is None:
        raise _http_404(
            "Checkout session not found.",
            code="checkout_session_not_found",
            extra={"session_id": session_id},
        )

    metadata = record.get("metadata")
    session_metadata = metadata if isinstance(metadata, dict) else {}
    if "owner_key" in session_metadata:
        authenticated_owner = resolve_authenticated_billing_owner(auth)
        session_owner = session_metadata.get("owner_key")
        if not authenticated_owner or not isinstance(session_owner, str) or session_owner.strip().lower() != authenticated_owner.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "checkout_session_not_accessible",
                    "detail": "Checkout session does not belong to the authenticated billing owner.",
                    "session_id": session_id,
                },
            )
    elif not org_id or record.get("org_id") != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "checkout_session_not_accessible",
                "detail": "Checkout session does not belong to the authenticated organization.",
                "session_id": session_id,
                "org_id": org_id,
            },
        )

    public_record = dict(record)
    if isinstance(metadata, dict):
        public_record["metadata"] = {key: value for key, value in metadata.items() if key != "owner_key"}
    return public_record


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


def _normalize_checkout_inputs(body: CheckoutSessionCreateRequest) -> tuple[str, int, str]:
    package_id = body.package_id or ""
    price_id = body.price_id.strip()

    if package_id:
        plan_code = resolve_plan_code(package_id)
        if plan_code is None:
            raise _http_400(
                f"Unsupported package_id '{package_id}'.",
                code="unsupported_package_id",
                extra={"package_id": package_id, "valid_package_ids": sorted(VALID_PACKAGE_IDS)},
            )
        resolved_price_id = _configured_price_id_for_package(package_id)
        resolved_unit_credits = _unit_credits_for_package(package_id)
        canonical_package_id = PLAN_DEFINITIONS[plan_code]["package_id"]
        return resolved_price_id, resolved_unit_credits, canonical_package_id

    if price_id:
        matching_plans = [plan_code for plan_code, env_key in PACKAGE_PRICE_ENV_MAP.items() if (vault.get(env_key) or "").strip() == price_id]
        if len(matching_plans) != 1:
            raise _http_400(
                "priceId must match exactly one configured IronClaw package.",
                code="unsupported_price_id",
                extra={"price_id": price_id},
            )
        plan_code = matching_plans[0]
        package = PLAN_DEFINITIONS[plan_code]
        return price_id, package["unit_limit"], package["package_id"]

    raise _http_400(
        "Either packageId or a configured package priceId is required.",
        code="package_id_or_configured_price_id_required",
    )


@webhook_router.post("/webhooks/stripe", status_code=status.HTTP_200_OK, summary="Receive and process Stripe webhook events", tags=["billing"])
async def stripe_webhook(
    request: Request,
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    verify_result = svc.verify_webhook_signature(payload=payload, signature_header=sig_header)
    if not verify_result.valid:
        logger.warning("stripe.webhook.signature_rejected error=%s", verify_result.error)
        raise _http_400(
            f"Stripe webhook signature invalid: {verify_result.error}",
            code="webhook_signature_invalid",
        )

    try:
        result = svc.handle_webhook_event(verify_result.payload)
    except StripeServiceError as exc:
        logger.warning("stripe.webhook.dispatch_error error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "webhook_dispatch_error", "detail": str(exc)},
        ) from exc

    if result.get("action") == "error":
        logger.error(
            "stripe.webhook.handler_failed event_type=%s",
            verify_result.event_type,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "webhook_dispatch_error"},
        )

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
    token_count: int = Query(..., alias="tokenCount", ge=1, description="Number of tokens to cover"),
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
    token_count: int = Query(..., alias="tokenCount", ge=1, description="Number of tokens to cover"),
) -> JSONResponse:
    return await calculate_units(token_count=token_count)


@api_router.post("/units/calculate", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def calculate_units_api(
    token_count: int = Query(..., alias="tokenCount", ge=1, description="Number of tokens to cover"),
) -> JSONResponse:
    return await calculate_units(token_count=token_count)


@api_router.get("/units/calculate", status_code=status.HTTP_200_OK, tags=["billing", "units"])
async def calculate_units_get_api(
    token_count: int = Query(..., alias="tokenCount", ge=1, description="Number of tokens to cover"),
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
    org_id = _require_org_id(auth=auth, request=request, body=body)
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
    require_permission(
        auth,
        "billing:units:credit",
        metadata={"route": "billing.units.credit"},
    )
    org_id = _require_org_id(auth=auth, request=request, body=body)
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
        content={"org_id": org_id, "balance": result.balance, "ledger": result.ledger_entries},
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

    return JSONResponse(status_code=status.HTTP_200_OK, content={"org_id": org_id, "customer_id": customer_id})


@api_router.post("/customers", status_code=status.HTTP_200_OK, tags=["billing"])
async def get_or_create_customer_api(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    # Keep compatibility: accept JSON body but validate manually for logging consistency
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    try:
        body = CustomerCreateRequest.model_validate(payload)
    except ValidationError as exc:
        logger.warning("stripe_router.get_or_create_customer_validation_error errors=%s keys=%s", exc.errors(), list(payload.keys()) if isinstance(payload, dict) else None)
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"error": "validation_error", "detail": exc.errors()})
    return await get_or_create_customer(body=body, request=request, auth=auth, svc=svc)


@router.post("/checkout/sessions", status_code=status.HTTP_201_CREATED, tags=["billing", "checkout"])
async def create_checkout_session(
    request: Request,
    auth: AuthContext = Depends(get_checkout_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    # Manual parsing + validation so we can log detailed validation failures and return structured 422.
    try:
        payload = await request.json()
    except Exception as exc:
        logger.warning("stripe_router.create_checkout_session_invalid_json error=%s", exc)
        raise _http_400("Invalid JSON body", code="invalid_json_body") from exc

    try:
        body = CheckoutSessionCreateRequest.model_validate(payload)
    except ValidationError as exc:
        # Log structured validation error without exposing full token/content
        payload_keys = list(payload.keys()) if isinstance(payload, dict) else None
        logger.warning(
            "stripe_router.create_checkout_session_validation_error errors=%s payload_keys=%s request_origin=%s",
            exc.errors(),
            payload_keys,
            request.headers.get("origin"),
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"error": "validation_error", "detail": exc.errors(), "payload_keys": payload_keys},
        )

    # proceed with original logic using validated `body`
    if getattr(auth, "authenticated", False) is not True:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "authentication_required",
                "detail": "Authentication is required for purchases that provision install keys.",
            },
        )

    owner_key = resolve_authenticated_billing_owner(auth)
    logger.info(
        "stripe_router.create_checkout_session owner_key=%s owner_empty=%s",
        owner_key or None,
        not owner_key,
    )
    if not owner_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "verified_billing_identity_required",
                "detail": "A verified billing identity is required for purchases that provision install keys.",
            },
        )

    org_id = _resolve_org_id(auth) or owner_key
    mode = StripeCheckoutMode(body.mode)
    if mode != StripeCheckoutMode.PAYMENT:
        raise _http_400(
            "IronClaw unit packages require one-time payment mode.",
            code="package_checkout_mode_invalid",
        )
    resolved_price_id, unit_credits_per_package, canonical_package_id = _normalize_checkout_inputs(body)
    resolved_unit_credits = unit_credits_per_package * body.quantity

    metadata = dict(body.metadata)
    metadata["package_id"] = canonical_package_id
    metadata["org_id"] = org_id
    metadata["unit_credits"] = str(resolved_unit_credits)
    metadata["owner_key"] = owner_key

    try:
        customer_id = _resolve_customer_id(svc, org_id)
        logger.info(
            "stripe_router.create_checkout_session org_id=%s package_id=%s price_id=%s",
            org_id,
            canonical_package_id,
            resolved_price_id,
        )
        result = svc.create_checkout_session(
            org_id=org_id,
            price_id=resolved_price_id,
            mode=mode,
            quantity=body.quantity,
            unit_credits=resolved_unit_credits,
            success_url=body.success_url,
            cancel_url=body.cancel_url,
            customer_id=customer_id,
            owner_key=owner_key,
            metadata=metadata,
        )
    except StripeServiceError as exc:
        logger.exception(
            "stripe_router.create_checkout_session_failed org_id=%s package_id=%s price_id=%s",
            org_id,
            canonical_package_id,
            resolved_price_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "stripe_checkout_error",
                "detail": str(exc),
                "org_id": org_id,
                "package_id": canonical_package_id,
                "price_id": resolved_price_id,
            },
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "stripe_router.create_checkout_session_unhandled org_id=%s package_id=%s price_id=%s",
            org_id,
            canonical_package_id,
            resolved_price_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "stripe_checkout_unavailable",
                "detail": "The payment provider could not start checkout. Please try again shortly.",
                "org_id": org_id,
                "package_id": canonical_package_id,
                "price_id": resolved_price_id,
            },
        ) from exc

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=result.to_dict())


@api_router.post("/checkout/sessions", status_code=status.HTTP_201_CREATED, tags=["billing", "checkout"])
async def create_checkout_session_api(
    request: Request,
    auth: AuthContext = Depends(get_checkout_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    # API alias — reuse the same implementation so validation logging is consistent
    return await create_checkout_session(request=request, auth=auth, svc=svc)


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
    session_id: str = Query(..., alias="sessionId", description="Stripe checkout session ID"),
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
    session_id: str = Query(..., alias="sessionId", description="Stripe checkout session ID"),
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
    record = _get_checkout_session_record_for_auth(session_id=session_id, auth=auth, svc=svc)
    if record.get("status") != "complete" or record.get("payment_status") != "paid":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "checkout_payment_not_confirmed",
                "detail": "Stripe has not confirmed payment for this checkout session.",
                "session_id": session_id,
            },
        )

    stripe_customer_id = record.get("customer_id")
    if body.customer_id and body.customer_id != stripe_customer_id:
        raise _http_400(
            "Customer ID does not match the Stripe checkout session.",
            code="checkout_customer_mismatch",
        )

    try:
        result = svc.complete_checkout_session(session_id=session_id, customer_id=stripe_customer_id)
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
    org_id = _require_org_id(auth=auth, request=request, body=body)
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
                "stripe_router.metered_sync_insufficient_units org_id=%s quantity=%d usage reported to Stripe but debit skipped",
                org_id,
                body.quantity,
            )
        except StripeServiceError as exc:
            logger.error("stripe_router.metered_sync_debit_error org_id=%s error=%s", org_id, exc)

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
    limit: int = Query(default=50, ge=1, le=100),
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
    org_id = _require_org_id(auth=auth, request=request, body=body)
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
            content={"org_id": org_id, "customer_id": None, "payment_methods": []},
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
        result = svc.set_default_payment_method(customer_id=customer_id, payment_method_id=payment_method_id)
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
    force_refresh: bool = Query(default=False, alias="forceRefresh"),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    org_id = _require_org_id(auth=auth, request=request)
    try:
        results = svc.get_invoices_for_org(org_id=org_id, limit=limit, force_refresh=force_refresh)
    except StripeServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "invoice_fetch_error", "detail": str(exc)},
        ) from exc

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"org_id": org_id, "count": len(results), "invoices": [r.to_dict() for r in results]},
    )


@router.get("/invoice-history", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def list_invoices_alias(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False, alias="forceRefresh"),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await list_invoices(request=request, limit=limit, force_refresh=force_refresh, auth=auth, svc=svc)


@api_router.get("/invoices", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def list_invoices_api(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False, alias="forceRefresh"),
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await list_invoices(request=request, limit=limit, force_refresh=force_refresh, auth=auth, svc=svc)


@api_router.get("/invoice-history", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def list_invoices_api_alias(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    force_refresh: bool = Query(default=False, alias="forceRefresh"),
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
    return JSONResponse(status_code=status.HTTP_200_OK, content={"invalidated": True, "org_id": org_id})


@api_router.delete("/invoices/cache", status_code=status.HTTP_200_OK, tags=["billing", "invoices"])
async def invalidate_invoice_cache_api(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    svc: StripeService = Depends(get_stripe_service),
) -> JSONResponse:
    return await invalidate_invoice_cache(request=request, auth=auth, svc=svc)


router.include_router(api_router)
