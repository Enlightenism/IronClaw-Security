from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header

from app.dependencies.auth import get_auth_context, require_authenticated
from app.dependencies.customer_auth import (
    require_customer_auth,
    require_customer_org_access,
    require_customer_read,
)
from app.dependencies.operator_auth import (
    require_operator_auth,
    require_operator_org_access,
    require_operator_read,
)
from app.dependencies.org_context import get_org_context
from app.dependencies.permissions import require_permissions_read

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/context")
async def get_auth_context_endpoint(
    context=Depends(get_auth_context),
) -> dict[str, Any]:
    return {
        "authenticated": context.authenticated,
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "org_id": context.org_id,
        "roles": list(context.roles),
        "permissions": list(context.permissions),
        "session_id": context.session_id,
        "auth_method": context.auth_method,
        "metadata": dict(context.metadata),
    }


@router.get("/status")
async def get_auth_status_endpoint(
    context=Depends(get_auth_context),
) -> dict[str, Any]:
    return {
        "ok": True,
        "authenticated": context.authenticated,
        "principal_type": context.principal_type,
        "session_id": context.session_id,
    }


@router.get("/me")
async def get_current_principal_endpoint(
    context=Depends(require_authenticated),
) -> dict[str, Any]:
    return {
        "principal": {
            "principal_id": context.principal_id,
            "principal_type": context.principal_type,
            "org_id": context.org_id,
            "roles": list(context.roles),
            "permissions": list(context.permissions),
        }
    }


@router.get("/org")
async def get_current_org_context_endpoint(
    org_context=Depends(get_org_context),
) -> dict[str, Any]:
    return {"org": org_context.to_dict()}


@router.get("/operator")
async def get_operator_auth_endpoint(
    context=Depends(require_operator_auth),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "org_id": context.org_id,
        "roles": list(context.roles),
    }


@router.get("/operator/org")
async def get_operator_org_access_endpoint(
    context=Depends(require_operator_org_access),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_org",
        "principal_id": context.principal_id,
        "org_id": x_org_id or context.org_id,
    }


@router.get("/customer")
async def get_customer_auth_endpoint(
    context=Depends(require_customer_auth),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "org_id": context.org_id,
        "roles": list(context.roles),
    }


@router.get("/customer/org")
async def get_customer_org_access_endpoint(
    context=Depends(require_customer_org_access),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_org",
        "principal_id": context.principal_id,
        "org_id": x_org_id or context.org_id,
    }


@router.get("/permissions")
async def get_permissions_endpoint(
    context=Depends(require_permissions_read),
) -> dict[str, Any]:
    return {
        "principal_id": context.principal_id,
        "permissions": list(context.permissions),
        "roles": list(context.roles),
    }


@router.get("/operator/summary")
async def get_operator_summary_endpoint(
    context=Depends(require_operator_read),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/customer/summary")
async def get_customer_summary_endpoint(
    context=Depends(require_customer_read),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }