from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.dependencies.auth import require_api_key
from app.services.alert_store import (
    AlertEndpointRecord as StoredAlertEndpointRecord,
)
from app.services.alert_store import (
    get_alert_endpoint_store,
)

router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_api_key)],
)

AlertChannel = Literal["email", "webhook", "slack"]
AlertEventType = Literal["incident_created", "incident_updated", "quarantine_created", "policy_changed"]
AlertDeliveryStatus = Literal["active", "paused", "failed"]


class AlertEndpointView(BaseModel):
    endpoint_id: str
    channel: AlertChannel
    name: str
    target: str
    subscribed_events: list[AlertEventType] = Field(default_factory=list)
    status: AlertDeliveryStatus
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertEndpointCreateRequest(BaseModel):
    channel: AlertChannel
    name: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=3, max_length=500)
    subscribed_events: list[AlertEventType] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertEndpointUpdateRequest(BaseModel):
    subscribed_events: list[AlertEventType] = Field(default_factory=list)
    status: AlertDeliveryStatus
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertEndpointListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[AlertEndpointView] = Field(default_factory=list)


class AlertEndpointResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    endpoint: AlertEndpointView


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _to_view(endpoint: StoredAlertEndpointRecord) -> AlertEndpointView:
    return AlertEndpointView(**endpoint.to_dict())


def _find_endpoint_or_404(endpoint_id: str) -> StoredAlertEndpointRecord:
    endpoint = get_alert_endpoint_store().get_endpoint(endpoint_id)
    if endpoint is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown alert endpoint: {endpoint_id}",
        )
    return endpoint


@router.get("/endpoints", response_model=AlertEndpointListResponse)
def list_alert_endpoints(
    channel: AlertChannel | None = Query(default=None),
    status_filter: AlertDeliveryStatus | None = Query(default=None, alias="status"),
) -> AlertEndpointListResponse:
    items = get_alert_endpoint_store().list_endpoints(
        channel=channel,
        status=status_filter,
    )
    return AlertEndpointListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=[_to_view(item) for item in items],
    )


@router.post("/endpoints", response_model=AlertEndpointResponse, status_code=status.HTTP_201_CREATED)
def create_alert_endpoint(payload: AlertEndpointCreateRequest) -> AlertEndpointResponse:
    endpoint = get_alert_endpoint_store().create_endpoint(
        channel=payload.channel,
        name=payload.name,
        target=payload.target,
        subscribed_events=payload.subscribed_events,
        metadata=payload.metadata,
    )
    return AlertEndpointResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        endpoint=_to_view(endpoint),
    )


@router.get("/endpoints/{endpoint_id}", response_model=AlertEndpointResponse)
def get_alert_endpoint(endpoint_id: str) -> AlertEndpointResponse:
    endpoint = _find_endpoint_or_404(endpoint_id)
    return AlertEndpointResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        endpoint=_to_view(endpoint),
    )


@router.put("/endpoints/{endpoint_id}", response_model=AlertEndpointResponse)
def update_alert_endpoint(
    endpoint_id: str,
    payload: AlertEndpointUpdateRequest,
) -> AlertEndpointResponse:
    _find_endpoint_or_404(endpoint_id)

    updated = get_alert_endpoint_store().update_endpoint(
        endpoint_id,
        subscribed_events=payload.subscribed_events,
        status=payload.status,
        metadata=payload.metadata,
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown alert endpoint: {endpoint_id}",
        )
    return AlertEndpointResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        endpoint=_to_view(updated),
    )
