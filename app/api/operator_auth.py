from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header

from app.dependencies.operator_auth import (
    require_operator_auth,
    require_operator_manage,
    require_operator_org_access,
    require_operator_permission,
    require_operator_read,
    require_operator_write,
)
from app.dependencies.org_context import get_org_context
from app.dependencies.permissions import require_any_permission


router = APIRouter(prefix="/api/operator-auth", tags=["operator-auth"])


@router.get("/context")
async def get_operator_context_endpoint(
    context=Depends(require_operator_auth),
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
async def get_operator_read_endpoint(
    context=Depends(require_operator_read),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/write")
async def get_operator_write_endpoint(
    context=Depends(require_operator_write),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_write",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/manage")
async def get_operator_manage_endpoint(
    context=Depends(require_operator_manage),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_manage",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/org")
async def get_operator_org_endpoint(
    context=Depends(require_operator_org_access),
    org_context=Depends(get_org_context),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_org",
        "principal_id": context.principal_id,
        "org_id": x_org_id or context.org_id,
        "org_context": org_context.to_dict(),
    }


@router.get("/permissions/any")
async def get_operator_any_permission_endpoint(
    context=Depends(
        require_any_permission(
            "operator:read",
            "operator:write",
            "operator:manage",
        )
    ),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_any_permission",
        "principal_id": context.principal_id,
        "permissions": list(context.permissions),
    }


@router.get("/permissions/read")
async def get_operator_permissions_read_endpoint(
    context=Depends(require_operator_permission("permissions:read")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "permissions_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/permissions/write")
async def get_operator_permissions_write_endpoint(
    context=Depends(require_operator_permission("permissions:write")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "permissions_write",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }