from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, status

from api.customerkeys import (
    CustomerApiKeyCreateRequest,
    CustomerApiKeyResponse,
    CustomerApiKeyRotateResponse,
    create_customer_key,
    get_customer_key,
    revoke_customer_key,
    rotate_customer_key,
)
from core.auth import AuthPrincipal, resolve_api_key

router = APIRouter(prefix="/ui/customerkeys", tags=["ui-customer-key-detail"])


def _action(
    *,
    id: str,
    title: str,
    description: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "description": description,
        "method": method,
        "path": path,
        "payload": payload,
    }


@router.get(
    "/{key_id}/detail",
    response_model=dict[str, Any],
)
def customer_key_detail_view(
    key_id: str = Path(..., description="Customer API key identifier."),
) -> dict[str, Any]:
    """
    UI metadata endpoint for a single customer key.

    Returns a shape that UI routers can use to render:
    - the key metadata pane
    - allowed actions (rotate, revoke, inspect)
    - example payloads for convenience
    """
    return {
        "page": "customer-key-detail",
        "title": "Customer API Key Detail",
        "summary": "Inspect and manage a single customer-scoped API key.",
        "key_id": key_id,
        "actions": [
            _action(
                id="inspect",
                title="Inspect key",
                description="Fetch the latest metadata for this customer API key.",
                method="GET",
                path=f"/customerkeys/{key_id}",
            ),
            _action(
                id="rotate",
                title="Rotate key",
                description=(
                    "Rotate this customer API key and receive a new raw key value. "
                    "The previous raw key becomes invalid."
                ),
                method="POST",
                path=f"/customerkeys/{key_id}/rotate",
            ),
            _action(
                id="revoke",
                title="Revoke key",
                description=(
                    "Revoke this customer API key. Once revoked, it can no longer be used "
                    "for authentication."
                ),
                method="POST",
                path=f"/customerkeys/{key_id}/revoke",
            ),
        ],
    }


@router.get(
    "/{key_id}",
    response_model=CustomerApiKeyResponse,
)
def ui_get_customer_key(
    key_id: str = Path(..., description="Customer API key identifier."),
) -> CustomerApiKeyResponse:
    """
    Thin UI-facing wrapper around the core get_customer_key endpoint.

    This exists so the UI router namespace stays consistent (`/ui/customerkeys/...`)
    while delegating all logic to the core API implementation.
    """
    return get_customer_key(key_id)


@router.post(
    "/{key_id}/rotate",
    response_model=CustomerApiKeyRotateResponse,
    status_code=status.HTTP_200_OK,
)
def ui_rotate_customer_key(
    key_id: str = Path(..., description="Customer API key identifier."),
) -> CustomerApiKeyRotateResponse:
    """
    UI-facing rotate endpoint that delegates to the core rotate_customer_key.

    The raw key is returned in the response exactly once and should be treated
    as sensitive.
    """
    return rotate_customer_key(key_id)


@router.post(
    "/{key_id}/revoke",
    response_model=CustomerApiKeyResponse,
    status_code=status.HTTP_200_OK,
)
def ui_revoke_customer_key(
    key_id: str = Path(..., description="Customer API key identifier."),
) -> CustomerApiKeyResponse:
    """
    UI-facing revoke endpoint that delegates to the core revoke_customer_key.

    The operation is idempotent; revoking an already-revoked key simply returns
    the current record.
    """
    return revoke_customer_key(key_id)


@router.post(
    "/create-and-detail",
    response_model=CustomerApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
def ui_create_customer_key_and_return_detail(
    body: CustomerApiKeyCreateRequest,
    principal: AuthPrincipal = Depends(resolve_api_key),
) -> CustomerApiKeyResponse:
    """
    Convenience endpoint primarily for UI flows that need to:
    - create a new customer key
    - immediately display the full persisted record (without raw key)

    It calls the core create_customer_key, then fetches the stored record to
    ensure the UI is working with the canonical view from the registry.
    """
    created = create_customer_key(body, principal)  # type: ignore[arg-type]

    if not created.key_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Customer key was created but key_id is missing.",
        )

    # Fetch the canonical record (without raw key) for display
    return get_customer_key(created.key_id)