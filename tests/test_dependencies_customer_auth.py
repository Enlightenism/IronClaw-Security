from __future__ import annotations

import pytest

from app.core.auth import AuthContext
from app.core.errors import AppError
from app.dependencies.customer_auth import (
    require_customer_auth,
    require_customer_org_access,
    require_customer_permission,
    require_customer_read,
    require_customer_session_access,
    require_customer_write,
)


def _context(
    *,
    principal_type: str = "customer",
    org_id: str | None = "org-123",
    permissions: tuple[str, ...] = ("customer:read",),
    roles: tuple[str, ...] = ("customer_user",),
    authenticated: bool = True,
) -> AuthContext:
    return AuthContext(
        api_key=None,
        principal_type=principal_type,
        principal_id="user-123",
        session_id="session-123",
        org_id=org_id,
        permissions=permissions,
        roles=roles,
        authenticated=authenticated,
        auth_source="supabase_jwt",
        auth_method="bearer_jwt",
        key_type="personal",
        metadata={"header": "Authorization"},
    )


@pytest.mark.anyio
async def test_require_customer_auth_allows_customer_user() -> None:
    context = _context()

    result = await require_customer_auth(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_auth_allows_customer_admin() -> None:
    context = _context(roles=("customer_admin",))

    result = await require_customer_auth(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_auth_rejects_non_customer_principal_without_platform_role() -> None:
    context = _context(principal_type="user")

    with pytest.raises(AppError) as exc_info:
        await require_customer_auth(context=context)

    assert exc_info.value.message == "Access denied"


@pytest.mark.anyio
async def test_require_customer_auth_allows_platform_override_role_for_non_customer_principal() -> None:
    context = _context(
        principal_type="platform",
        roles=("customer_user", "platform_admin"),
    )

    result = await require_customer_auth(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_read_allows_customer_read_permission() -> None:
    context = _context(permissions=("customer:read",))

    result = await require_customer_read(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_read_uses_customer_auth_baseline_when_permission_present() -> None:
    context = _context(permissions=())

    result = await require_customer_read(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_write_allows_customer_write_permission() -> None:
    context = _context(
        permissions=("customer:read", "customer:write"),
    )

    result = await require_customer_write(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_write_rejects_missing_customer_write_permission() -> None:
    context = _context(permissions=("customer:read",))

    with pytest.raises(AppError) as exc_info:
        await require_customer_write(context=context)

    assert exc_info.value.message == "Access denied"


@pytest.mark.anyio
async def test_require_customer_session_access_allows_session_read_permission() -> None:
    context = _context(
        permissions=("customer:read", "session:read"),
    )

    result = await require_customer_session_access(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_session_access_uses_customer_auth_baseline_when_permission_present() -> None:
    context = _context(permissions=("customer:read",))

    result = await require_customer_session_access(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_org_access_allows_matching_header_org() -> None:
    context = _context(org_id="org-123")

    result = await require_customer_org_access(x_org_id="org-123", context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_org_access_allows_context_org_when_header_missing() -> None:
    context = _context(org_id="org-123")

    result = await require_customer_org_access(x_org_id=None, context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_org_access_rejects_mismatched_org() -> None:
    context = _context(org_id="org-123")

    with pytest.raises(AppError) as exc_info:
        await require_customer_org_access(x_org_id="org-999", context=context)

    assert exc_info.value.message == "Organization isolation policy denied access"


@pytest.mark.anyio
async def test_require_customer_permission_allows_requested_permission() -> None:
    dependency = require_customer_permission("customer:write")
    context = _context(permissions=("customer:read", "customer:write"))

    result = await dependency(context=context)

    assert result is context


@pytest.mark.anyio
async def test_require_customer_permission_rejects_missing_requested_permission() -> None:
    dependency = require_customer_permission("customer:write")
    context = _context(permissions=("customer:read",))

    with pytest.raises(AppError) as exc_info:
        await dependency(context=context)

    assert exc_info.value.message == "Access denied"
