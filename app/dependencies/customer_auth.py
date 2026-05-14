from __future__ import annotations

from fastapi import Depends, Header

from app.core.access_control import require_access
from app.core.auth import AuthContext, get_auth_context
from app.core.org_isolation import require_same_org


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


async def require_customer_auth(
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    require_access(
        context,
        action="customer_authenticated",
        required_roles=("customer_admin", "customer_user"),
        metadata={"dependency": "require_customer_auth"},
    )
    if context.principal_type != "customer":
        require_access(
            context,
            action="customer_principal_required",
            required_roles=("platform_admin", "system_admin", "operator_admin"),
            metadata={"dependency": "require_customer_auth", "reason": "principal_type_mismatch"},
        )
    return context


async def require_customer_read(
    context: AuthContext = Depends(require_customer_auth),
) -> AuthContext:
    require_access(
        context,
        action="customer_read",
        required_permission="customer:read",
        metadata={"dependency": "require_customer_read"},
    )
    return context


async def require_customer_write(
    context: AuthContext = Depends(require_customer_auth),
) -> AuthContext:
    require_access(
        context,
        action="customer_write",
        required_permission="customer:write",
        metadata={"dependency": "require_customer_write"},
    )
    return context


async def require_customer_session_access(
    context: AuthContext = Depends(require_customer_auth),
) -> AuthContext:
    require_access(
        context,
        action="customer_session_access",
        required_permission="session:read",
        metadata={"dependency": "require_customer_session_access"},
    )
    return context


async def require_customer_org_access(
    x_org_id: str | None = Header(default=None),
    context: AuthContext = Depends(require_customer_read),
) -> AuthContext:
    target_org_id = _clean(x_org_id) or context.org_id
    require_same_org(
        context,
        target_org_id=target_org_id,
        metadata={"dependency": "require_customer_org_access"},
    )
    return context


def require_customer_permission(permission: str):
    async def dependency(
        context: AuthContext = Depends(require_customer_auth),
    ) -> AuthContext:
        require_access(
            context,
            action="customer_permission",
            required_permission=permission,
            metadata={
                "dependency": "require_customer_permission",
                "permission": permission,
            },
        )
        return context

    return dependency
