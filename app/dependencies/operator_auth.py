from __future__ import annotations

from fastapi import Depends, Header

from app.core.access_control import require_access
from app.core.auth import AuthContext, get_auth_context
from app.core.org_isolation import require_same_org


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


async def require_operator_auth(
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    require_access(
        context,
        action="operator_authenticated",
        required_roles=(
            "platform_admin",
            "system_admin",
            "operator_admin",
            "operator_analyst",
            "auditor",
        ),
        metadata={"dependency": "require_operator_auth"},
    )
    if context.principal_type != "operator":
        require_access(
            context,
            action="operator_principal_required",
            required_roles=("platform_admin", "system_admin", "operator_admin"),
            metadata={"dependency": "require_operator_auth", "reason": "principal_type_mismatch"},
        )
    return context


async def require_operator_read(
    context: AuthContext = Depends(require_operator_auth),
) -> AuthContext:
    require_access(
        context,
        action="operator_read",
        required_permission="operator:read",
        metadata={"dependency": "require_operator_read"},
    )
    return context


async def require_operator_write(
    context: AuthContext = Depends(require_operator_auth),
) -> AuthContext:
    require_access(
        context,
        action="operator_write",
        required_permission="operator:write",
        metadata={"dependency": "require_operator_write"},
    )
    return context


async def require_operator_manage(
    context: AuthContext = Depends(require_operator_auth),
) -> AuthContext:
    require_access(
        context,
        action="operator_manage",
        required_permission="operator:manage",
        metadata={"dependency": "require_operator_manage"},
    )
    return context


async def require_operator_org_access(
    x_org_id: str | None = Header(default=None),
    context: AuthContext = Depends(require_operator_read),
) -> AuthContext:
    target_org_id = _clean(x_org_id) or context.org_id
    require_same_org(
        context,
        target_org_id=target_org_id,
        metadata={"dependency": "require_operator_org_access"},
    )
    return context


def require_operator_permission(permission: str):
    async def dependency(
        context: AuthContext = Depends(require_operator_auth),
    ) -> AuthContext:
        require_access(
            context,
            action="operator_permission",
            required_permission=permission,
            metadata={
                "dependency": "require_operator_permission",
                "permission": permission,
            },
        )
        return context

    return dependency
