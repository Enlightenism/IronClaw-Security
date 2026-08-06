from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app.core.auth import AuthContext, get_auth_context
from app.models.webhook import (
    WebhookCreateRequest,
    WebhookDeliveryAttempt,
    WebhookEventType,
    WebhookFilterRequest,
    WebhookResponse,
    WebhookRotateSecretResponse,
    WebhookStatusUpdateResponse,
    WebhookSummaryResponse,
    WebhookTestResponse,
    WebhookUpdateRequest,
)
from app.services.webhook_dispatcher import (
    WebhookDispatcher,
    get_webhook_dispatcher,
)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def _dispatcher() -> WebhookDispatcher:
    return get_webhook_dispatcher()


def _org_id(request: Request, ctx: AuthContext = Depends(get_auth_context)) -> str:
    if ctx.org_id:
        return ctx.org_id
    return request.headers.get("X-Organization-Id", "").strip()


def _normalized_org_id(organization_id: str) -> str | None:
    normalized = organization_id.strip() if isinstance(organization_id, str) else ""
    return normalized or None


def _require_org_id(organization_id: str, *, operation: str) -> str:
    normalized = _normalized_org_id(organization_id)
    if normalized is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization context is required to {operation}",
        )
    return normalized


def _assert_org_scope(
    record_org_id: str | None,
    caller_org_id: str,
    webhook_id: str,
) -> None:
    normalized_record_org_id = _normalized_org_id(record_org_id or "")
    normalized_caller_org_id = _normalized_org_id(caller_org_id)
    if normalized_record_org_id is not None and normalized_caller_org_id is not None and normalized_record_org_id != normalized_caller_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Webhook '{webhook_id}' does not belong to your organization",
        )


def _safe_dispatcher_call(
    fn: Any,
    *args: Any,
    not_found_detail: str | None = None,
    **kwargs: Any,
) -> Any:
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=not_found_detail or str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook dispatcher contract error: {exc}",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook router operation failed: {exc}",
        ) from exc


def _coerce_delivery_rows(value: Any) -> list[WebhookDeliveryAttempt]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item if isinstance(item, WebhookDeliveryAttempt) else WebhookDeliveryAttempt.model_validate(item) for item in value]
    if isinstance(value, dict):
        for key in ("items", "deliveries", "results", "data"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [item if isinstance(item, WebhookDeliveryAttempt) else WebhookDeliveryAttempt.model_validate(item) for item in nested]
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Webhook deliveries response shape is invalid",
    )


# ---------------------------------------------------------------------------
# Registration CRUD — collection routes (must precede /{webhook_id})
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a webhook endpoint",
    description=("Register a webhook endpoint using the app.models.webhook contract as the source of truth for this API surface. If org_id is omitted, the caller's resolved organization context is applied automatically."),
)
def register_webhook(
    payload: WebhookCreateRequest,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookResponse:
    normalized_org_id = _normalized_org_id(organization_id)
    if payload.org_id is None:
        payload = payload.model_copy(update={"org_id": normalized_org_id})
    elif normalized_org_id is not None and payload.org_id != normalized_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Payload org_id does not match your organization context",
        )
    return _safe_dispatcher_call(dispatcher.register, payload)


@router.get(
    "",
    response_model=list[WebhookSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="List registered webhooks",
    description=("List webhook registrations scoped to the caller's organization when org context is present. Query validation uses app.models.webhook enum types for consistency with the schema/model layer."),
)
def list_webhooks(
    organization_id: str = Depends(_org_id),
    active: bool | None = Query(default=None),
    event_type: WebhookEventType | None = Query(default=None),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> list[WebhookSummaryResponse]:
    filter_req = WebhookFilterRequest(
        org_id=_normalized_org_id(organization_id),
        active=active,
        event_type=event_type,
    )
    result = _safe_dispatcher_call(dispatcher.list_webhooks, filter_req)
    return list(result or [])


# ---------------------------------------------------------------------------
# Delivery collection route — static route BEFORE /{webhook_id}
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries",
    response_model=list[WebhookDeliveryAttempt],
    status_code=status.HTTP_200_OK,
    summary="List webhook deliveries",
    description=("List delivery attempts for the caller organization. This collection route must resolve before dynamic /{webhook_id} routes and return a stable JSON list shape."),
)
def list_webhook_deliveries(
    limit: int = Query(default=100, ge=1, le=500),
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> list[WebhookDeliveryAttempt]:
    scoped_org_id = _require_org_id(organization_id, operation="list webhook deliveries")

    candidate_calls: list[tuple[Any, tuple[Any, ...], dict[str, Any]]] = [
        (getattr(dispatcher, "list_deliveries", None), (), {"org_id": scoped_org_id, "limit": limit}),
        (getattr(dispatcher, "list_delivery_logs", None), (), {"org_id": scoped_org_id, "limit": limit}),
        (getattr(dispatcher, "list_delivery_attempts", None), (), {"org_id": scoped_org_id, "limit": limit}),
        (getattr(dispatcher, "get_deliveries", None), (), {"org_id": scoped_org_id, "limit": limit}),
    ]

    for fn, args, kwargs in candidate_calls:
        if callable(fn):
            result = _safe_dispatcher_call(fn, *args, **kwargs)
            return _coerce_delivery_rows(result)

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Webhook dispatcher does not expose a collection deliveries reader",
    )


# ---------------------------------------------------------------------------
# Dead-letter queue — static routes BEFORE /{webhook_id} dynamic routes
# ---------------------------------------------------------------------------


@router.get(
    "/dead-letter",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List dead-letter queue entries",
    description=("List dead-letter queue entries strictly scoped to the caller's organization. Cross-organization visibility is not permitted from this router surface."),
)
def list_dead_letter(
    limit: int = Query(default=100, ge=1, le=500),
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> list[dict[str, Any]]:
    scoped_org_id = _require_org_id(organization_id, operation="list dead-letter entries")
    result = _safe_dispatcher_call(
        dispatcher.list_dead_letter,
        org_id=scoped_org_id,
        limit=limit,
        allow_global=False,
    )
    return list(result or [])


@router.post(
    "/dead-letter/{delivery_id}/replay",
    response_model=WebhookDeliveryAttempt,
    status_code=status.HTTP_200_OK,
    summary="Replay a single dead-letter delivery",
    description=("Replay a dead-letter delivery strictly within the caller's organization scope. Cross-organization replay is not permitted from this router surface."),
)
def replay_dead_letter(
    delivery_id: str,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookDeliveryAttempt:
    scoped_org_id = _require_org_id(organization_id, operation="replay dead-letter entries")
    result = _safe_dispatcher_call(
        dispatcher.replay_dead_letter,
        delivery_id,
        org_id=scoped_org_id,
        allow_global=False,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dead-letter entry '{delivery_id}' not found",
        )
    return result


@router.delete(
    "/dead-letter",
    status_code=status.HTTP_200_OK,
    summary="Purge all dead-letter queue entries",
    description=("Purge dead-letter queue entries only for the caller's organization. Cross-organization purge is not permitted from this router surface."),
)
def purge_dead_letter(
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> dict[str, int]:
    scoped_org_id = _require_org_id(organization_id, operation="purge dead-letter entries")
    count = _safe_dispatcher_call(
        dispatcher.purge_dead_letter,
        org_id=scoped_org_id,
        allow_global=False,
    )
    return {"purged": int(count or 0)}


# ---------------------------------------------------------------------------
# Dispatch — static route BEFORE /{webhook_id} dynamic routes
# ---------------------------------------------------------------------------


@router.post(
    "/dispatch",
    response_model=list[WebhookDeliveryAttempt],
    status_code=status.HTTP_200_OK,
    summary="Dispatch an event to all matching webhook subscriptions",
    description=("Dispatch an event using enum-backed event_type validation from app.models.webhook for consistency with other webhook endpoints."),
)
def dispatch_event(
    event_type: WebhookEventType = Query(...),
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
    data: dict[str, Any] | None = None,
) -> list[WebhookDeliveryAttempt]:
    result = _safe_dispatcher_call(
        dispatcher.dispatch_event,
        str(event_type),
        data or {},
        org_id=_normalized_org_id(organization_id),
    )
    return list(result or [])


# ---------------------------------------------------------------------------
# Per-webhook routes — dynamic /{webhook_id} routes AFTER all static routes
# ---------------------------------------------------------------------------


@router.get(
    "/{webhook_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a webhook by ID",
)
def get_webhook(
    webhook_id: str,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookResponse:
    record = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(record.org_id, organization_id, webhook_id)
    return record


@router.patch(
    "/{webhook_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a webhook registration",
)
def update_webhook(
    webhook_id: str,
    payload: WebhookUpdateRequest,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookResponse:
    existing = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    if payload.org_id is not None:
        normalized_org_id = _normalized_org_id(organization_id)
        if normalized_org_id is not None and payload.org_id != normalized_org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Payload org_id does not match your organization context",
            )
    updated = _safe_dispatcher_call(dispatcher.update, webhook_id, payload)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    return updated


@router.delete(
    "/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete a webhook registration",
)
def delete_webhook(
    webhook_id: str,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> Response:
    existing = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    _safe_dispatcher_call(dispatcher.delete, webhook_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Status toggle
# ---------------------------------------------------------------------------


@router.post(
    "/{webhook_id}/enable",
    response_model=WebhookStatusUpdateResponse,
    status_code=status.HTTP_200_OK,
    summary="Enable a webhook",
)
def enable_webhook(
    webhook_id: str,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookStatusUpdateResponse:
    existing = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    result = _safe_dispatcher_call(dispatcher.set_active, webhook_id, active=True)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    return result


@router.post(
    "/{webhook_id}/disable",
    response_model=WebhookStatusUpdateResponse,
    status_code=status.HTTP_200_OK,
    summary="Disable a webhook",
)
def disable_webhook(
    webhook_id: str,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookStatusUpdateResponse:
    existing = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    result = _safe_dispatcher_call(dispatcher.set_active, webhook_id, active=False)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    return result


# ---------------------------------------------------------------------------
# Secret rotation
# ---------------------------------------------------------------------------


@router.post(
    "/{webhook_id}/rotate-secret",
    response_model=WebhookRotateSecretResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate the signing secret for a webhook",
    description=("Rotate the webhook signing secret server-side. The newly generated secret is not returned by this endpoint and must be handled as a one-time re-onboarding operation for the receiver. This router uses app.models.webhook as its public contract source of truth."),
)
def rotate_webhook_secret(
    webhook_id: str,
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookRotateSecretResponse:
    existing = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)

    new_secret = secrets.token_hex(32)
    result = _safe_dispatcher_call(dispatcher.rotate_secret, webhook_id, new_secret)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    return result


# ---------------------------------------------------------------------------
# Test delivery
# ---------------------------------------------------------------------------


@router.post(
    "/{webhook_id}/test",
    response_model=WebhookTestResponse,
    status_code=status.HTTP_200_OK,
    summary="Send a test delivery to a webhook endpoint",
    description=("Send a test delivery using enum-backed event_type validation for consistency with dispatch and filter behavior."),
)
def test_webhook(
    webhook_id: str,
    event_type: WebhookEventType = Query(default=WebhookEventType.GUARD_ALLOW),
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookTestResponse:
    existing = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    return _safe_dispatcher_call(dispatcher.send_test, webhook_id, str(event_type))


# ---------------------------------------------------------------------------
# Delivery log
# ---------------------------------------------------------------------------


@router.get(
    "/{webhook_id}/deliveries",
    response_model=list[WebhookDeliveryAttempt],
    status_code=status.HTTP_200_OK,
    summary="Retrieve delivery attempt log for a webhook",
)
def get_delivery_log(
    webhook_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    organization_id: str = Depends(_org_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> list[WebhookDeliveryAttempt]:
    existing = _safe_dispatcher_call(dispatcher.get, webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    result = _safe_dispatcher_call(dispatcher.get_delivery_log, webhook_id, limit=limit)
    return list(result or [])
