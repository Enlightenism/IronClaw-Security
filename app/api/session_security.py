from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header

from app.dependencies.auth import require_authenticated
from app.dependencies.customer_auth import require_customer_session_access
from app.dependencies.operator_auth import require_operator_manage, require_operator_read
from app.dependencies.org_context import get_org_context
from app.dependencies.permissions import require_any_permission

router = APIRouter(prefix="/api/session-security", tags=["session-security"])


@router.get("/context")
async def get_session_security_context_endpoint(
    context=Depends(require_authenticated),
) -> dict[str, Any]:
    return {
        "authenticated": True,
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "org_id": context.org_id,
        "session_id": context.session_id,
        "auth_method": context.auth_method,
        "roles": list(context.roles),
        "permissions": list(context.permissions),
    }


@router.get("/read")
async def get_session_security_read_endpoint(
    context=Depends(require_any_permission("session:read", "operator:read")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "session_security_read",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
        "session_id": context.session_id,
    }


@router.get("/manage")
async def get_session_security_manage_endpoint(
    context=Depends(require_operator_manage),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "session_security_manage",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
        "session_id": context.session_id,
    }


@router.get("/customer")
async def get_customer_session_security_endpoint(
    context=Depends(require_customer_session_access),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_session_security",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
        "session_id": context.session_id,
    }


@router.get("/operator")
async def get_operator_session_security_endpoint(
    context=Depends(require_operator_read),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_session_security",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
        "session_id": context.session_id,
    }


@router.get("/org")
async def get_session_security_org_endpoint(
    context=Depends(require_any_permission("session:read", "operator:read")),
    org_context=Depends(get_org_context),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "session_security_org",
        "principal_id": context.principal_id,
        "org_id": x_org_id or context.org_id,
        "session_id": context.session_id,
        "org_context": org_context.to_dict(),
    }


@router.get("/summary")
async def get_session_security_summary_endpoint(
    context=Depends(require_any_permission("session:read", "session:write", "operator:manage")),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "session_security_summary",
        "principal_id": context.principal_id,
        "org_id": context.org_id,
        "session_id": context.session_id,
        "roles": list(context.roles),
        "permissions": list(context.permissions),
    }
