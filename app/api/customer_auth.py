from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header

from app.dependencies.customer_auth import (
    require_customer_auth,
    require_customer_org_access,
    require_customer_permission,
    require_customer_read,
    require_customer_session_access,
    require_customer_write,
)
from app.dependencies.org_context import get_org_context
from app.dependencies.permissions import require_any_permission

router = APIRouter(prefix="/api/customer-auth", tags=["customer-auth"])


@router.get("/context")
async def get_customer_context_endpoint(
    context=Depends(require_customer_auth),
) -> dict[str, Any]:
    return {
        "authenticated": True,
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "org_id": context.org_id,
        "roles": list(context.roles),
        "permissions": list(context.permissions),
    }


@router.get("/read")
async def get_customer_read_endpoint(
    context=Depends(require_customer_read),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/write")
async def get_customer_write_endpoint(
    context=Depends(require_customer_write),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_write",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/sessions")
async def get_customer_session_access_endpoint(
    context=Depends(require_customer_session_access),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_session_access",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/org")
async def get_customer_org_endpoint(
    context=Depends(require_customer_org_access),
    org_context=Depends(get_org_context),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_org",
        "principal_id": context.principal_id,
        "org_id": x_org_id or context.org_id,
        "org_context": org_context.to_dict(),
    }


@router.get("/permissions/any")
async def get_customer_any_permission_endpoint(
    context=Depends(
        require_any_permission(
            "customer:read",
            "customer:write",
            "session:read",
        ),
    ),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_any_permission",
        "principal_id": context.principal_id,
        "permissions": list(context.permissions),
    }


@router.get("/permissions/read")
async def get_customer_permissions_read_endpoint(
    context=Depends(require_customer_permission("permissions:read")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "permissions_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/permissions/customer-read")
async def get_customer_permissions_customer_read_endpoint(
    context=Depends(require_customer_permission("customer:read")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_permission_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }
