from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, Query

from app.core.auth import AuthContext
from app.dependencies.auth import get_auth_context, require_authenticated
from app.dependencies.customer_auth import require_customer_org_access
from app.dependencies.operator_auth import require_operator_org_access, require_operator_read
from app.dependencies.org_context import OrgContext, get_org_context, require_explicit_org_context

router = APIRouter(prefix="/api/org-context", tags=["org-context"])


@router.get("/context")
async def get_org_context_endpoint(
    context: AuthContext = Depends(get_auth_context),
    org_context: OrgContext = Depends(get_org_context),
) -> dict[str, Any]:
    if not context.authenticated:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Missing API key")
    return {
        "org": org_context.to_dict(),
    }


@router.get("/explicit")
async def get_explicit_org_context_endpoint(
    org_context: OrgContext = Depends(require_explicit_org_context()),
) -> dict[str, Any]:
    return {
        "org": org_context.to_dict(),
        "explicit": True,
    }


@router.get("/authenticated")
async def get_authenticated_org_context_endpoint(
    context: AuthContext = Depends(require_authenticated),
) -> dict[str, Any]:
    return {
        "authenticated": True,
        "principal_id": context.principal_id,
        "principal_type": context.principal_type,
        "actor_org_id": context.org_id,
        "target_org_id": context.org_id,
        "source": "actor",
    }


@router.get("/operator")
async def get_operator_org_context_endpoint(
    context: AuthContext = Depends(require_operator_org_access),
    org_context: OrgContext = Depends(get_org_context),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "operator_org_context",
        "principal_id": context.principal_id,
        "org_id": x_org_id or org_context.target_org_id,
        "org": org_context.to_dict(),
    }


@router.get("/customer")
async def get_customer_org_context_endpoint(
    context: AuthContext = Depends(require_customer_org_access),
    org_context: OrgContext = Depends(get_org_context),
    x_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "customer_org_context",
        "principal_id": context.principal_id,
        "org_id": x_org_id or org_context.target_org_id,
        "org": org_context.to_dict(),
    }


@router.get("/resolve")
async def resolve_org_context_endpoint(
    context: AuthContext = Depends(require_operator_read),
    org_context: OrgContext = Depends(get_org_context),
    x_org_id: str | None = Header(default=None),
    org_id: str | None = Query(default=None),
) -> dict[str, Any]:
    return {
        "authorized": True,
        "scope": "resolve_org_context",
        "principal_id": context.principal_id,
        "actor_org_id": context.org_id,
        "requested_org_id": x_org_id or org_id,
        "resolved_org": org_context.to_dict(),
    }