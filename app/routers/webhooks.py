from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import logging
import os
import secrets
from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from app.core.auth import AuthContext, get_auth_context
from app.models.webhook import (
    WebhookCreateResponse,
    WebhookDeliveryLogEntry,
    WebhookEventType,
    WebhookSubscriptionCreate,
    WebhookSubscriptionResponse,
    WebhookSubscriptionUpdateRequest,
)
from app.services.webhook_service import (
    dispatch_event,
    list_retryable_deliveries,
    retry_failed_delivery,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

_WEBHOOK_SUBSCRIPTIONS_TABLE = "webhook_subscriptions"

_SUPPORTED_EVENTS: set[str] = {e.value for e in WebhookEventType if e.value != "*"}


# ---------------------------------------------------------------------------
# Supabase client accessor — delegates to canonical core module
# ---------------------------------------------------------------------------


def _get_supabase_client() -> Any:
    try:
        from app.core.supabase import get_supabase_service_client  # type: ignore[import]

        return get_supabase_service_client()
    except ImportError:
        pass
    try:
        from supabase import create_client  # type: ignore[import]

        return create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_SERVICE_ROLE_KEY"],
        )
    except Exception as exc:
        logger.error("webhooks: supabase client unavailable: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_id() -> str:
    return str(uuid.uuid4())


def _generate_raw_secret() -> str:
    return secrets.token_hex(32)


def _hash_secret(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _key_prefix_hint(raw: str) -> str:
    return raw[:8] + "..."


def _redact_subscription(row: dict[str, Any]) -> dict[str, Any]:
    row = dict(row)
    row.pop("secret_hash", None)
    return row


def _resolve_tenant_id(auth: AuthContext) -> str:
    tid = getattr(auth, "tenant_id", None) or getattr(auth, "org_id", None) or ""
    return str(tid)


def _build_list_item(row: dict[str, Any]) -> dict[str, Any]:
    raw_hash = row.get("secret_hash", "")
    hint = raw_hash[:8] + "..." if raw_hash else "unknown..."
    item = _redact_subscription(row)
    item["secret_hint"] = hint
    return item


def _fetch_subscription(client: Any, subscription_id: str, tenant_id: str) -> dict[str, Any] | None:
    try:
        query = client.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).select("*").eq("id", subscription_id)
        if tenant_id:
            query = query.eq("tenant_id", tenant_id)
        resp = query.limit(1).execute()
        rows: list[dict[str, Any]] = resp.data or []
        return rows[0] if rows else None
    except Exception as exc:
        logger.error("webhooks._fetch_subscription id=%s tenant_id=%s error=%s", subscription_id, tenant_id, exc)
        return None


# ---------------------------------------------------------------------------
# POST /webhooks/subscriptions
# ---------------------------------------------------------------------------


@router.post(
    "/subscriptions",
    status_code=status.HTTP_201_CREATED,
    response_model=WebhookCreateResponse,
    summary="Create a webhook subscription",
    description=("Creates a new webhook subscription for the authenticated tenant. " "Returns the full signing secret exactly once — store it securely. " "The secret_hash is never returned after creation; only a key_prefix hint is shown on subsequent reads."),
)
async def create_webhook_subscription(
    payload: WebhookSubscriptionCreate,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_id could not be resolved from auth context")

    raw_secret = _generate_raw_secret()
    secret_hash = _hash_secret(raw_secret)
    hint = _key_prefix_hint(raw_secret)
    now_iso = datetime.now(UTC).isoformat()
    subscription_id = _generate_id()

    row: dict[str, Any] = {
        "id": subscription_id,
        "tenant_id": tenant_id,
        "target_url": str(payload.target_url),
        "events": payload.events,
        "secret_hash": secret_hash,
        "active": True,
        "max_attempts": payload.max_attempts,
        "metadata": payload.metadata,
        "created_at": now_iso,
    }

    try:
        client.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).insert(row).execute()
    except Exception as exc:
        logger.error("webhooks.create_subscription tenant_id=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="subscription_create_failed") from exc

    logger.info("webhooks.create_subscription id=%s tenant_id=%s events=%s", subscription_id, tenant_id, payload.events)

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "id": subscription_id,
            "tenant_id": tenant_id,
            "target_url": str(payload.target_url),
            "events": payload.events,
            "active": True,
            "max_attempts": payload.max_attempts,
            "metadata": payload.metadata,
            "created_at": now_iso,
            "secret_hint": hint,
            "signing_secret": raw_secret,
        },
    )


# ---------------------------------------------------------------------------
# GET /webhooks/subscriptions
# ---------------------------------------------------------------------------


@router.get(
    "/subscriptions",
    status_code=status.HTTP_200_OK,
    response_model=None,
    summary="List webhook subscriptions for the authenticated tenant",
)
async def list_webhook_subscriptions(
    active_only: bool = Query(default=False, description="Return only active subscriptions"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_id could not be resolved from auth context")

    try:
        query = client.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).select("id,tenant_id,target_url,events,active,max_attempts,metadata,created_at,secret_hash").eq("tenant_id", tenant_id).order("created_at", desc=True).range(offset, offset + limit - 1)
        if active_only:
            query = query.eq("active", True)
        resp = query.execute()
        rows: list[dict[str, Any]] = resp.data or []
    except Exception as exc:
        logger.error("webhooks.list_subscriptions tenant_id=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="list_failed") from exc

    safe_rows = [_build_list_item(r) for r in rows]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"count": len(safe_rows), "subscriptions": safe_rows},
    )


# ---------------------------------------------------------------------------
# GET /webhooks/subscriptions/{subscription_id}
# ---------------------------------------------------------------------------


@router.get(
    "/subscriptions/{subscription_id}",
    status_code=status.HTTP_200_OK,
    response_model=WebhookSubscriptionResponse,
    summary="Get a single webhook subscription",
)
async def get_webhook_subscription(
    subscription_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)
    row = _fetch_subscription(client, subscription_id, tenant_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription_not_found")

    return JSONResponse(status_code=status.HTTP_200_OK, content=_build_list_item(row))


# ---------------------------------------------------------------------------
# PATCH /webhooks/subscriptions/{subscription_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/subscriptions/{subscription_id}",
    status_code=status.HTTP_200_OK,
    response_model=WebhookSubscriptionResponse,
    summary="Update a webhook subscription (enable/disable, change events, etc.)",
)
async def update_webhook_subscription(
    subscription_id: str,
    payload: WebhookSubscriptionUpdateRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)
    existing = _fetch_subscription(client, subscription_id, tenant_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription_not_found")

    updates: dict[str, Any] = {}
    if payload.active is not None:
        updates["active"] = payload.active
    if payload.events is not None:
        updates["events"] = payload.events
    if payload.max_attempts is not None:
        updates["max_attempts"] = payload.max_attempts
    if payload.metadata is not None:
        updates["metadata"] = payload.metadata

    if not updates:
        return JSONResponse(status_code=status.HTTP_200_OK, content=_build_list_item(existing))

    try:
        client.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).update(updates).eq("id", subscription_id).eq("tenant_id", tenant_id).execute()
    except Exception as exc:
        logger.error("webhooks.update_subscription id=%s tenant_id=%s error=%s", subscription_id, tenant_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="update_failed") from exc

    updated = _fetch_subscription(client, subscription_id, tenant_id)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="post_update_fetch_failed")

    logger.info("webhooks.update_subscription id=%s tenant_id=%s updates=%s", subscription_id, tenant_id, list(updates.keys()))
    return JSONResponse(status_code=status.HTTP_200_OK, content=_build_list_item(updated))


# ---------------------------------------------------------------------------
# DELETE /webhooks/subscriptions/{subscription_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/subscriptions/{subscription_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a webhook subscription",
)
async def delete_webhook_subscription(
    subscription_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)
    existing = _fetch_subscription(client, subscription_id, tenant_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription_not_found")

    try:
        client.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).delete().eq("id", subscription_id).eq("tenant_id", tenant_id).execute()
    except Exception as exc:
        logger.error("webhooks.delete_subscription id=%s tenant_id=%s error=%s", subscription_id, tenant_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="delete_failed") from exc

    logger.info("webhooks.delete_subscription id=%s tenant_id=%s", subscription_id, tenant_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"deleted": True, "id": subscription_id},
    )


# ---------------------------------------------------------------------------
# POST /webhooks/subscriptions/{subscription_id}/rotate-secret
# ---------------------------------------------------------------------------


@router.post(
    "/subscriptions/{subscription_id}/rotate-secret",
    status_code=status.HTTP_200_OK,
    summary="Rotate the signing secret for a webhook subscription",
    description=("Generates a new HMAC-SHA256 signing secret for the subscription. " "The new full secret is returned exactly once. Deliveries signed with the old secret " "will be invalid immediately after rotation."),
)
async def rotate_webhook_secret(
    subscription_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)
    existing = _fetch_subscription(client, subscription_id, tenant_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription_not_found")

    raw_secret = _generate_raw_secret()
    new_hash = _hash_secret(raw_secret)
    hint = _key_prefix_hint(raw_secret)

    try:
        client.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).update({"secret_hash": new_hash}).eq("id", subscription_id).eq("tenant_id", tenant_id).execute()
    except Exception as exc:
        logger.error("webhooks.rotate_secret id=%s tenant_id=%s error=%s", subscription_id, tenant_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="rotate_failed") from exc

    logger.info("webhooks.rotate_secret id=%s tenant_id=%s", subscription_id, tenant_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "id": subscription_id,
            "secret_hint": hint,
            "signing_secret": raw_secret,
            "rotated_at": datetime.now(UTC).isoformat(),
        },
    )


# ---------------------------------------------------------------------------
# POST /webhooks/test
# ---------------------------------------------------------------------------


@router.post(
    "/test",
    status_code=status.HTTP_200_OK,
    summary="Send a test event to all active subscriptions for the tenant",
    description="Dispatches a synthetic 'webhook.test' event to verify endpoint reachability. Returns one dispatch result per active subscription.",
)
async def test_webhook_dispatch(
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    tenant_id = _resolve_tenant_id(auth)
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_id could not be resolved from auth context")

    test_payload: dict[str, Any] = {
        "test": True,
        "triggered_by": getattr(auth, "user_id", None) or getattr(auth, "api_key_id", None) or "unknown",
        "timestamp": datetime.now(UTC).isoformat(),
    }

    try:
        # Normal flow — fire edge function so downstream consumers see the test event.
        results = dispatch_event(tenant_id, "webhook.test", test_payload, fire_edge_function=True)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "dispatched": len(results),
                "results": [r.to_dict() for r in results],
            },
        )
    except Exception as exc:
        logger.error("webhooks.test_dispatch tenant_id=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="dispatch_failed") from exc


# ---------------------------------------------------------------------------
# GET /webhooks/deliveries
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries",
    status_code=status.HTTP_200_OK,
    response_model=None,
    summary="List webhook delivery log entries for the tenant",
)
async def list_webhook_deliveries(
    subscription_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    delivery_status: str | None = Query(default=None, description="Filter by delivery status: pending, success, failed, exhausted"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_id could not be resolved from auth context")

    try:
        query = client.table("webhook_delivery_log").select("id,subscription_id,tenant_id,event_type,status,attempts,http_status,error_detail,delivered_at,next_attempt_at,created_at").eq("tenant_id", tenant_id).order("created_at", desc=True).range(offset, offset + limit - 1)
        if subscription_id:
            query = query.eq("subscription_id", subscription_id)
        if event_type:
            query = query.eq("event_type", event_type)
        if delivery_status:
            query = query.eq("status", delivery_status)
        resp = query.execute()
        rows: list[dict[str, Any]] = resp.data or []
    except Exception as exc:
        logger.error("webhooks.list_deliveries tenant_id=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="list_failed") from exc

    validated: list[dict[str, Any]] = [WebhookDeliveryLogEntry.model_validate(r).model_dump() for r in rows]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"count": len(validated), "deliveries": validated},
    )


# ---------------------------------------------------------------------------
# GET /webhooks/deliveries/retryable
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries/retryable",
    status_code=status.HTTP_200_OK,
    summary="List webhook deliveries eligible for retry",
    description="Returns delivery log rows with status='failed' and next_attempt_at <= now. Scoped to the system operator view.",
)
async def list_retryable_webhook_deliveries(
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    try:
        rows = list_retryable_deliveries(limit=limit)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"count": len(rows), "deliveries": rows},
        )
    except Exception as exc:
        logger.error("webhooks.list_retryable_deliveries error=%s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="list_failed") from exc


# ---------------------------------------------------------------------------
# POST /webhooks/deliveries/{delivery_id}/retry
# ---------------------------------------------------------------------------


@router.post(
    "/deliveries/{delivery_id}/retry",
    status_code=status.HTTP_200_OK,
    summary="Retry a specific failed webhook delivery",
    description=("Re-executes a previously failed delivery by its delivery_id. " "Fetches the current subscription state from Supabase before retrying. " "Returns the updated WebhookDispatchResult."),
)
async def retry_webhook_delivery(
    delivery_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage_unavailable")

    tenant_id = _resolve_tenant_id(auth)

    try:
        resp = client.table("webhook_delivery_log").select("*").eq("id", delivery_id).limit(1).execute()
        rows: list[dict[str, Any]] = resp.data or []
    except Exception as exc:
        logger.error("webhooks.retry_delivery fetch delivery_id=%s error=%s", delivery_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="fetch_failed") from exc

    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="delivery_not_found")

    record = rows[0]

    record_tenant = record.get("tenant_id", "")
    if tenant_id and record_tenant and record_tenant != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="delivery_not_accessible")

    delivery_status_val = record.get("status", "")
    if delivery_status_val not in ("failed", "exhausted"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Delivery status '{delivery_status_val}' is not retryable. Only 'failed' or 'exhausted' deliveries can be retried.",
        )

    try:
        # Admin retry path — skip edge function call; the original event already fired it.
        result = retry_failed_delivery(
            delivery_id=delivery_id,
            subscription_id=record["subscription_id"],
            tenant_id=record["tenant_id"],
            event_type=record["event_type"],
            payload_json=record.get("payload_json", "{}"),
            current_attempts=int(record.get("attempts", 1)),
        )
    except Exception as exc:
        logger.error("webhooks.retry_delivery retry delivery_id=%s error=%s", delivery_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="retry_failed") from exc

    logger.info("webhooks.retry_delivery delivery_id=%s status=%s", delivery_id, result.status.value)
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.to_dict())


# ---------------------------------------------------------------------------
# GET /webhooks/events
# ---------------------------------------------------------------------------


@router.get(
    "/events",
    status_code=status.HTTP_200_OK,
    summary="List all supported IronClaw webhook event types",
)
async def list_supported_events(
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"events": sorted(_SUPPORTED_EVENTS)},
    )
