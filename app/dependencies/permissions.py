from __future__ import annotations

from fastapi import Request

from app.core.auth import AuthContext
from app.core.permissions import evaluate_permission, require_permission
from app.dependencies.auth import build_auth_context


async def require_permissions_read(request: Request) -> AuthContext:
    context = build_auth_context(request)
    require_permission(
        context,
        "permissions:read",
        metadata={"dependency": "require_permissions_read"},
    )
    return context


async def require_permissions_write(request: Request) -> AuthContext:
    context = build_auth_context(request)
    require_permission(
        context,
        "permissions:write",
        metadata={"dependency": "require_permissions_write"},
    )
    return context


def require_permission_dependency(permission: str):
    async def dependency(request: Request) -> AuthContext:
        context = build_auth_context(request)
        require_permission(
            context,
            permission,
            metadata={
                "dependency": "require_permission_dependency",
                "permission": permission,
            },
        )
        return context

    return dependency


def require_any_permission(*permissions: str):
    normalized_permissions = tuple(
        permission.strip().lower()
        for permission in permissions
        if isinstance(permission, str) and permission.strip()
    )

    async def dependency(request: Request) -> AuthContext:
        context = build_auth_context(request)

        for permission in normalized_permissions:
            decision = evaluate_permission(
                context,
                permission,
                metadata={
                    "dependency": "require_any_permission",
                    "permission": permission,
                },
            )
            if decision.allowed:
                return context

        fallback_permission = normalized_permissions[0] if normalized_permissions else ""
        require_permission(
            context,
            fallback_permission,
            metadata={
                "dependency": "require_any_permission",
                "permissions": ",".join(normalized_permissions),
            },
        )
        return context

    return dependency


def require_all_permissions(*permissions: str):
    normalized_permissions = tuple(
        permission.strip().lower()
        for permission in permissions
        if isinstance(permission, str) and permission.strip()
    )

    async def dependency(request: Request) -> AuthContext:
        context = build_auth_context(request)
        for permission in normalized_permissions:
            require_permission(
                context,
                permission,
                metadata={
                    "dependency": "require_all_permissions",
                    "permission": permission,
                },
            )
        return context

    return dependency