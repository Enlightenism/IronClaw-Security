from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header

from app.dependencies.auth import require_authenticated
from app.dependencies.operator_auth import (
    require_operator_auth,
    require_operator_manage,
    require_operator_permission,
    require_operator_read,
)
from app.dependencies.org_context import get_org_context
from app.dependencies.permissions import (
    require_all_permissions,
    require_any_permission,
    require_permissions_read,
    require_permissions_write,
)

router = APIRouter(prefix="/api/access-control", tags=["access-control"])


@router.get("/context")
async def get_access_control_context_endpoint(
    context=Depends(require_authenticated),
) -> dict[str, Any]:
    return {
        "authenticated": True,
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "org_id": context.org_id,
        "roles": list(context.roles),
        "permissions": list(context.permissions),
        "session_id": context.session_id,
    }


@router.get("/read")
async def get_access_control_read_endpoint(
    context=Depends(require_any_permission("permissions:read", "operator:read")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/write")
async def get_access_control_write_endpoint(
    context=Depends(require_permissions_write),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_write",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/operator")
async def get_access_control_operator_endpoint(
    context=Depends(require_operator_auth),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_operator",
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "org_id": context.org_id,
        "roles": list(context.roles),
    }


@router.get("/operator/manage")
async def get_access_control_operator_manage_endpoint(
    context=Depends(require_operator_manage),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_operator_manage",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/permissions")
async def get_access_control_permissions_endpoint(
    context=Depends(require_permissions_read),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_permissions",
        "principal_id": context.principal_id,
        "permissions": list(context.permissions),
        "roles": list(context.roles),
    }


@router.get("/permissions/all")
async def get_access_control_all_permissions_endpoint(
    context=Depends(require_all_permissions("permissions:read", "operator:read")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_all_permissions",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/permissions/operator-write")
async def get_access_control_operator_write_permission_endpoint(
    context=Depends(require_operator_permission("operator:write")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_operator_write_permission",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
    }


@router.get("/org")
async def get_access_control_org_endpoint(
    context=Depends(require_operator_read),
    org_context=Depends(get_org_context),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "access_control_org",
        "principal_id": context.principal_id,
        "org_id": x_org_id or context.org_id,
        "org_context": org_context.to_dict(),
    }