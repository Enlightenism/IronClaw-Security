from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from api.customerkeys import (
    CustomerApiKeyCreatedResponse,
    CustomerApiKeyCreateRequest,
    CustomerApiKeyListResponse,
    CustomerApiKeyResponse,
    CustomerApiKeyRotateResponse,
    create_customer_key,
    get_customer_key,
    list_customer_keys,
    revoke_customer_key,
    rotate_customer_key,
)

router = APIRouter(prefix="/ui/customerkeys", tags=["ui-customer-keys"])


def _metric(
    *,
    metric_id: str,
    label: str,
    value: Any,
    tone: str = "neutral",
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "metric_id": metric_id,
        "label": label,
        "value": value,
        "tone": tone,
        "help_text": help_text,
    }


def _section(
    *,
    section_id: str,
    title: str,
    description: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    notes: list[str] | None = None,
    example_response_shape: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "section_id": section_id,
        "title": title,
        "description": description,
        "method": method,
        "path": path,
        "payload": payload,
        "notes": notes or [],
        "example_response_shape": example_response_shape,
    }


def _field(
    *,
    name: str,
    label: str,
    field_type: str,
    required: bool,
    default: Any | None = None,
    placeholder: str | None = None,
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": field_type,
        "required": required,
        "default": default,
        "placeholder": placeholder,
        "help_text": help_text,
    }


def _table_column(
    *,
    key: str,
    label: str,
    value_type: str = "text",
) -> dict[str, str]:
    return {
        "key": key,
        "label": label,
        "value_type": value_type,
    }


def _sample_key_record(
    *,
    key_id: str = "ck_001",
    name: str = "Primary Customer Key",
    status: str = "active",
    created_at: str = "2026-04-23T12:00:00Z",
    last_rotated_at: str = "2026-04-23T12:00:00Z",
) -> dict[str, Any]:
    return {
        "key_id": key_id,
        "name": name,
        "status": status,
        "created_at": created_at,
        "last_rotated_at": last_rotated_at,
    }


@router.get("")
def customer_keys_index(
    highlight: str | None = Query(default=None),
    status: str = Query(default="active"),
) -> dict[str, Any]:
    normalized_status = status if status in {"active", "revoked", "all"} else "active"

    return {
        "page": "customer-keys",
        "title": "Customer API Keys",
        "summary": ("Manage customer-scoped API keys, inspect lifecycle operations, and route into rotation, revocation, and detail workflows."),
        "selected": {
            "highlight": highlight,
            "status": normalized_status,
        },
        "metrics": [
            _metric(
                metric_id="lifecycle_operations",
                label="Lifecycle Operations",
                value=5,
                tone="neutral",
                help_text="List, create, inspect, rotate, and revoke are exposed on this page.",
            ),
            _metric(
                metric_id="raw_key_visibility",
                label="Raw Key Visibility",
                value="once",
                tone="warning",
                help_text="Raw key material should only be shown once during create or rotate flows.",
            ),
            _metric(
                metric_id="rotation_supported",
                label="Rotation Supported",
                value=True,
                tone="positive",
                help_text="Existing keys can be rotated without changing the page surface.",
            ),
            _metric(
                metric_id="revocation_supported",
                label="Revocation Supported",
                value=True,
                tone="positive",
                help_text="Keys can be revoked directly from the management flow.",
            ),
        ],
        "filters": [
            _field(
                name="status",
                label="Status Filter",
                field_type="select",
                required=False,
                default=normalized_status,
                help_text="Filter the page context to active, revoked, or all keys.",
            ),
            _field(
                name="highlight",
                label="Highlight Key",
                field_type="text",
                required=False,
                default=highlight,
                placeholder="ck_001",
                help_text="Optionally emphasize a specific key in the UI.",
            ),
        ],
        "sections": [
            _section(
                section_id="list-keys",
                title="List Keys",
                description="View all customer API keys that belong to the authenticated principal.",
                method="GET",
                path="/customerkeys",
                notes=[
                    "Use this flow as the default landing dataset for key management.",
                    "Statuses should distinguish active and revoked keys clearly.",
                    "Prefer linking each record into a dedicated detail page when available.",
                ],
                example_response_shape={
                    "items": [
                        _sample_key_record(),
                        _sample_key_record(
                            key_id="ck_002",
                            name="Secondary Integration Key",
                            status="revoked",
                            created_at="2026-04-21T08:30:00Z",
                            last_rotated_at="2026-04-22T10:15:00Z",
                        ),
                    ],
                },
            ),
            _section(
                section_id="create-key",
                title="Create Key",
                description="Create a new customer API key and return the raw key once.",
                method="POST",
                path="/customerkeys",
                payload={"name": "Primary Customer Key"},
                notes=[
                    "The raw key must be captured immediately because it should not be re-shown later.",
                    "Creation flows should encourage clear human-readable names.",
                    "New keys should become eligible for detail and rotation flows immediately.",
                ],
                example_response_shape={
                    "key_id": "ck_003",
                    "name": "Primary Customer Key",
                    "status": "active",
                    "raw_key": "ic_live_xxxxxxxxx",
                },
            ),
            _section(
                section_id="inspect-key",
                title="Inspect Key",
                description="View metadata for a specific customer API key.",
                method="GET",
                path="/customerkeys/{key_id}",
                notes=[
                    "Detail views should avoid exposing raw key material after initial creation.",
                    "Metadata should emphasize lifecycle state, timestamps, and operator-safe actions.",
                ],
                example_response_shape=_sample_key_record(),
            ),
            _section(
                section_id="rotate-key",
                title="Rotate Key",
                description="Rotate an existing customer API key and return a new raw key once.",
                method="POST",
                path="/customerkeys/{key_id}/rotate",
                notes=[
                    "Rotation should preserve management continuity while invalidating the old secret.",
                    "The newly returned raw key should be copied and stored by the operator immediately.",
                ],
                example_response_shape={
                    "key_id": "ck_001",
                    "name": "Primary Customer Key",
                    "status": "active",
                    "raw_key": "ic_live_rotated_xxxxxxxxx",
                },
            ),
            _section(
                section_id="revoke-key",
                title="Revoke Key",
                description="Revoke an existing customer API key.",
                method="POST",
                path="/customerkeys/{key_id}/revoke",
                notes=[
                    "Revocation should be treated as a high-confidence lifecycle action.",
                    "Revoked keys should remain visible in history-oriented UI states.",
                ],
                example_response_shape={
                    "key_id": "ck_001",
                    "name": "Primary Customer Key",
                    "status": "revoked",
                },
            ),
        ],
        "table": {
            "title": "Managed Keys",
            "columns": [
                _table_column(key="key_id", label="Key ID"),
                _table_column(key="name", label="Name"),
                _table_column(key="status", label="Status"),
                _table_column(key="created_at", label="Created At"),
                _table_column(key="last_rotated_at", label="Last Rotated"),
            ],
            "rows": [
                _sample_key_record(),
                _sample_key_record(
                    key_id="ck_002",
                    name="Portal Automation Key",
                    status=normalized_status if normalized_status != "all" else "active",
                    created_at="2026-04-20T16:45:00Z",
                    last_rotated_at="2026-04-22T09:00:00Z",
                ),
            ],
        },
        "actions": [
            {
                "id": "list",
                "title": "Load Key Inventory",
                "method": "GET",
                "path": "/ui/customerkeys/list",
                "description": "Fetch the live customer key inventory for the current principal.",
            },
            {
                "id": "create",
                "title": "Create New Key",
                "method": "POST",
                "path": "/ui/customerkeys/create",
                "payload": {"name": "Primary Customer Key"},
                "description": "Create a new key and return the raw secret once.",
            },
            {
                "id": "detail",
                "title": "Open Key Detail",
                "method": "GET",
                "path": "/ui/customerkeys/{key_id}",
                "description": "Inspect metadata for a single customer key.",
            },
            {
                "id": "rotate",
                "title": "Rotate Existing Key",
                "method": "POST",
                "path": "/ui/customerkeys/{key_id}/rotate",
                "description": "Rotate an existing key and return the new raw secret once.",
            },
            {
                "id": "revoke",
                "title": "Revoke Existing Key",
                "method": "POST",
                "path": "/ui/customerkeys/{key_id}/revoke",
                "description": "Revoke a key while preserving lifecycle visibility.",
            },
        ],
        "examples": [
            {
                "name": "Create primary key",
                "request": {
                    "method": "POST",
                    "path": "/ui/customerkeys/create",
                    "body": {"name": "Primary Customer Key"},
                },
            },
            {
                "name": "Rotate portal key",
                "request": {
                    "method": "POST",
                    "path": "/ui/customerkeys/ck_002/rotate",
                },
            },
            {
                "name": "Revoke deprecated key",
                "request": {
                    "method": "POST",
                    "path": "/ui/customerkeys/ck_legacy/revoke",
                },
            },
        ],
        "related_pages": [
            {
                "id": "customer-key-detail",
                "title": "Open Customer Key Detail",
                "method": "GET",
                "path": "/ui/customerkeydetail",
                "query": {
                    "key_id": highlight or "ck_001",
                },
            },
            {
                "id": "request-context",
                "title": "Open Request Context",
                "method": "GET",
                "path": "/ui/requestcontext",
                "query": {
                    "source": "ui-console",
                    "mode": "enforce",
                },
            },
            {
                "id": "telemetry-access-summary",
                "title": "Open Telemetry Access Summary",
                "method": "GET",
                "path": "/ui/telemetryaccesssummary",
                "query": {
                    "period": "24h",
                },
            },
        ],
    }


@router.get("/list", response_model=CustomerApiKeyListResponse)
def customer_keys_list() -> CustomerApiKeyListResponse:
    return list_customer_keys()


@router.post("/create", response_model=CustomerApiKeyCreatedResponse)
def customer_keys_create(body: CustomerApiKeyCreateRequest) -> CustomerApiKeyCreatedResponse:
    return create_customer_key(body)


@router.get("/{key_id}", response_model=CustomerApiKeyResponse)
def customer_keys_detail(key_id: str) -> CustomerApiKeyResponse:
    return get_customer_key(key_id)


@router.post("/{key_id}/rotate", response_model=CustomerApiKeyRotateResponse)
def customer_keys_rotate(key_id: str) -> CustomerApiKeyRotateResponse:
    return rotate_customer_key(key_id)


@router.post("/{key_id}/revoke", response_model=CustomerApiKeyResponse)
def customer_keys_revoke(key_id: str) -> CustomerApiKeyResponse:
    return revoke_customer_key(key_id)
