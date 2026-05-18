from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import get_current_organization_id
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
# Dependency
# ---------------------------------------------------------------------------


def _dispatcher() -> WebhookDispatcher:
    return get_webhook_dispatcher()


# ---------------------------------------------------------------------------
# Registration CRUD
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a webhook endpoint",
)
def register_webhook(
    payload: WebhookCreateRequest,
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookResponse:
    if payload.org_id is None:
        payload = payload.model_copy(update={"org_id": organization_id})
    return dispatcher.register(payload)


@router.get(
    "",
    response_model=list[WebhookSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="List registered webhooks",
)
def list_webhooks(
    organization_id: str = Depends(get_current_organization_id),
    active: bool | None = Query(default=None),
    event_type: str | None = Query(default=None, min_length=1, max_length=120),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> list[WebhookSummaryResponse]:
    filter_req = WebhookFilterRequest(
        org_id=organization_id,
        active=active,
        event_type=WebhookEventType(event_type) if event_type is not None else None,
    )
    return dispatcher.list_webhooks(filter_req)


@router.get(
    "/{webhook_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a webhook by ID",
)
def get_webhook(
    webhook_id: str,
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookResponse:
    record = dispatcher.get(webhook_id)
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
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookResponse:
    existing = dispatcher.get(webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    updated = dispatcher.update(webhook_id, payload)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    return updated


@router.delete(
    "/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a webhook registration",
)
def delete_webhook(
    webhook_id: str,
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> None:
    existing = dispatcher.get(webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    dispatcher.delete(webhook_id)


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
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookStatusUpdateResponse:
    existing = dispatcher.get(webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    result = dispatcher.set_active(webhook_id, active=True)
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
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookStatusUpdateResponse:
    existing = dispatcher.get(webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    result = dispatcher.set_active(webhook_id, active=False)
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
)
def rotate_webhook_secret(
    webhook_id: str,
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookRotateSecretResponse:
    existing = dispatcher.get(webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)

    import secrets as _secrets

    new_secret = _secrets.token_hex(32)
    result = dispatcher.rotate_secret(webhook_id, new_secret)
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
)
def test_webhook(
    webhook_id: str,
    event_type: str = Query(
        default=WebhookEventType.GUARD_ALLOW,
        min_length=1,
        max_length=120,
    ),
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookTestResponse:
    existing = dispatcher.get(webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    return dispatcher.send_test(webhook_id, event_type)


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
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> list[WebhookDeliveryAttempt]:
    existing = dispatcher.get(webhook_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )
    _assert_org_scope(existing.org_id, organization_id, webhook_id)
    return dispatcher.get_delivery_log(webhook_id, limit=limit)


# ---------------------------------------------------------------------------
# Dead-letter queue
# ---------------------------------------------------------------------------


@router.get(
    "/dead-letter",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List dead-letter queue entries",
)
def list_dead_letter(
    limit: int = Query(default=100, ge=1, le=500),
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> list[dict[str, Any]]:
    return dispatcher.list_dead_letter(limit=limit)


@router.post(
    "/dead-letter/{delivery_id}/replay",
    response_model=WebhookDeliveryAttempt,
    status_code=status.HTTP_200_OK,
    summary="Replay a single dead-letter delivery",
)
def replay_dead_letter(
    delivery_id: str,
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> WebhookDeliveryAttempt:
    result = dispatcher.replay_dead_letter(delivery_id)
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
)
def purge_dead_letter(
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
) -> dict[str, int]:
    count = dispatcher.purge_dead_letter()
    return {"purged": count}


# ---------------------------------------------------------------------------
# Dispatch (internal / platform use)
# ---------------------------------------------------------------------------


@router.post(
    "/dispatch",
    response_model=list[WebhookDeliveryAttempt],
    status_code=status.HTTP_200_OK,
    summary="Dispatch an event to all matching webhook subscriptions",
)
def dispatch_event(
    event_type: str = Query(min_length=1, max_length=120),
    organization_id: str = Depends(get_current_organization_id),
    dispatcher: WebhookDispatcher = Depends(_dispatcher),
    data: dict[str, Any] | None = None,
) -> list[WebhookDeliveryAttempt]:
    return dispatcher.dispatch_event(
        event_type,
        data or {},
        org_id=organization_id,
    )


# ---------------------------------------------------------------------------
# Internal org-scope guard
# ---------------------------------------------------------------------------


def _assert_org_scope(
    record_org_id: str | None,
    caller_org_id: str,
    webhook_id: str,
) -> None:
    if record_org_id is not None and record_org_id != caller_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Webhook '{webhook_id}' does not belong to your organization",
        )
