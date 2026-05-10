from __future__ import annotations

from typing import Any, Mapping

from fastapi import Depends, Header, Request

from app.core.access_control import require_access
from app.core.auth import (
    AuthContext,
    get_api_key,
    get_auth_context,
    require_api_key,
)
from app.core.org_isolation import require_same_org
from app.core.permissions import require_permission


# ---------------------------------------------------------------------------
# Re-exports — canonical implementations live in app.core.auth
# ---------------------------------------------------------------------------

__all__ = [
    "AuthContext",
    "get_api_key",
    "get_auth_context",
    "require_api_key",
    "get_authenticated_auth_context",
    "require_authenticated",
    "require_permission_dependency",
    "require_access_dependency",
    "require_same_org_dependency",
]


# ---------------------------------------------------------------------------
# Internal helpers (local only — not re-exported)
# ---------------------------------------------------------------------------


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_lower(value: object) -> str:
    return _clean(value).lower()


def _normalize_metadata(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


# ---------------------------------------------------------------------------
# Compound dependencies that wrap the canonical get_auth_context
# ---------------------------------------------------------------------------


async def get_authenticated_auth_context(
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    require_access(
        context,
        action="authenticated_context",
    )
    return context


async def require_authenticated(
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    require_access(
        context,
        action="authenticated",
    )
    return context


def require_permission_dependency(permission: str):
    async def dependency(
        context: AuthContext = Depends(get_auth_context),
    ) -> AuthContext:
        require_permission(
            context,
            permission,
            metadata={"dependency": "require_permission_dependency"},
        )
        return context

    return dependency


def require_access_dependency(
    *,
    action: str,
    permission: str | None = None,
    roles: tuple[str, ...] | list[str] | set[str] | None = None,
):
    async def dependency(
        context: AuthContext = Depends(get_auth_context),
    ) -> AuthContext:
        require_access(
            context,
            action=action,
            required_permission=permission,
            required_roles=roles,
            metadata={"dependency": "require_access_dependency"},
        )
        return context

    return dependency


async def require_same_org_dependency(
    x_org_id: str | None = Header(default=None),
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    target_org_id = _clean(x_org_id) or context.org_id
    require_same_org(
        context,
        target_org_id=target_org_id,
        metadata={"dependency": "require_same_org_dependency"},
    )
    return context