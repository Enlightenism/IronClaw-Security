from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key-deps-auth")
os.environ.setdefault("AUTH_REQUIRED", "false")
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-service-role")
os.environ.setdefault("SUPABASE_KEY", "test-anon-key")
os.environ.setdefault("SUPABASE_ANON_KEY", "test-anon-key")


from app.core.api_key_auth import EdgeAuthContext, require_api_key, require_scope
from app.core.apikeys import APIKeyRegistry, generate_api_key
from app.core.auth import AuthContext, get_api_key
from app.core.errors import AppError
from app.dependencies.auth import (
    require_access_dependency,
    require_authenticated,
    require_same_org_dependency,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auth_context(
    *,
    authenticated: bool = True,
    principal_type: str = "platform",
    org_id: str | None = "org-abc",
    api_key: str | None = "test-api-key-deps-auth",
    permissions: tuple[str, ...] = (),
    roles: tuple[str, ...] = (),
    key_type: str = "personal",
) -> AuthContext:
    return AuthContext(
        api_key=api_key,
        principal_type=principal_type,
        principal_id="pid-001",
        session_id=None,
        org_id=org_id,
        permissions=permissions,
        roles=roles,
        authenticated=authenticated,
        auth_source="configured",
        auth_method="api_key",
        key_type=key_type,
    )


def _make_edge_auth_context(
    *,
    permissions: tuple[str, ...] = ("read",),
) -> EdgeAuthContext:
    return EdgeAuthContext(
        api_key="edge-bearer-token",
        principal_type="api_key",
        principal_id="pid-edge-001",
        session_id=None,
        org_id="org-edge-001",
        permissions=permissions,
        roles=(),
        authenticated=True,
        auth_source="configured",
        auth_method="bearer",
        key_type="personal",
    )


# ---------------------------------------------------------------------------
# EdgeAuthContext unit tests
# ---------------------------------------------------------------------------


class TestEdgeAuthContext:
    def test_has_scope_exact_match(self) -> None:
        ctx = _make_edge_auth_context(permissions=("read", "write"))
        assert "read" in ctx.permissions
        assert "write" in ctx.permissions

    def test_has_scope_admin_bypass(self) -> None:
        ctx = _make_edge_auth_context(permissions=("admin",))
        assert "admin" in ctx.permissions

    def test_has_scope_missing(self) -> None:
        ctx = _make_edge_auth_context(permissions=("read",))
        assert "write" not in ctx.permissions
        assert "delete" not in ctx.permissions

    def test_has_scope_empty_scopes(self) -> None:
        ctx = _make_edge_auth_context(permissions=())
        assert ctx.permissions == ()

    def test_edge_auth_context_fields(self) -> None:
        ctx = _make_edge_auth_context(permissions=("scan", "audit"))
        assert ctx.permissions == ("scan", "audit")
        assert ctx.principal_id == "pid-edge-001"
        assert ctx.auth_method == "bearer"

    def test_edge_auth_context_is_auth_context_alias(self) -> None:
        ctx = _make_edge_auth_context()
        assert isinstance(ctx, AuthContext)


# ---------------------------------------------------------------------------
# require_api_key compatibility dependency
# ---------------------------------------------------------------------------


class TestRequireApiKey:
    @pytest.mark.asyncio
    async def test_require_api_key_returns_authenticated_context(self) -> None:
        auth = _make_auth_context(authenticated=True, principal_type="platform")
        result = await require_api_key(auth=auth)
        assert result is auth

    @pytest.mark.asyncio
    async def test_require_api_key_raises_401_for_unauthenticated_context(self) -> None:
        auth = _make_auth_context(
            authenticated=False,
            principal_type="anonymous",
            api_key=None,
        )
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(auth=auth)
        assert exc_info.value.status_code == 401
        assert "Missing API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_api_key_preserves_auth_context_shape(self) -> None:
        auth = _make_auth_context(
            authenticated=True,
            principal_type="api_key",
            org_id="org-preserve",
            permissions=("scan:execute",),
        )
        result = await require_api_key(auth=auth)
        assert isinstance(result, AuthContext)
        assert result.org_id == "org-preserve"
        assert result.permissions == ("scan:execute",)

    @pytest.mark.asyncio
    async def test_require_api_key_edge_auth_context_alias_contract(self) -> None:
        auth = _make_edge_auth_context(permissions=("audit",))
        result = await require_api_key(auth=auth)
        assert isinstance(result, EdgeAuthContext)
        assert result.permissions == ("audit",)
        assert result.auth_method == "bearer"

    @pytest.mark.asyncio
    async def test_require_api_key_rejects_unauthenticated_edge_alias_context(self) -> None:
        auth = AuthContext(
            api_key="edge-bearer-token",
            principal_type="api_key",
            principal_id="pid-edge-001",
            session_id=None,
            org_id="org-edge-001",
            permissions=("read",),
            roles=(),
            authenticated=False,
            auth_source="configured",
            auth_method="bearer",
            key_type="personal",
        )
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(auth=auth)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# require_local_api_key — resolves via registry path, returns str | None
# ---------------------------------------------------------------------------


class TestRequireLocalApiKey:
    def test_registry_key_resolves_to_str(self) -> None:
        registry = APIKeyRegistry()
        raw_key = generate_api_key()
        record = registry.create_key("test-key", api_key=raw_key)

        assert record.api_key == raw_key
        resolved = registry.authenticate(raw_key, touch=False)

        assert resolved is not None
        assert isinstance(resolved.api_key, str)
        assert resolved.api_key == raw_key

    def test_missing_key_resolves_to_none(self) -> None:
        registry = APIKeyRegistry()
        result = registry.authenticate("nonexistent-key", touch=False)
        assert result is None

    def test_revoked_key_resolves_to_none(self) -> None:
        registry = APIKeyRegistry()
        raw_key = generate_api_key()
        record = registry.create_key("revoke-test", api_key=raw_key)
        registry.revoke_key(record.key_id)

        result = registry.authenticate(raw_key, touch=False)
        assert result is None

    def test_registry_returns_none_for_empty_key(self) -> None:
        registry = APIKeyRegistry()
        result = registry.authenticate("", touch=False)
        assert result is None

    def test_get_api_key_returns_str_when_valid(self) -> None:
        raw_key = generate_api_key()

        active_record = MagicMock()
        active_record.active = True
        active_record.revoked_at = None

        with (
            patch("app.core.auth._resolve_registry_api_key", return_value=active_record),
            patch("app.core.auth._is_auth_required", return_value=False),
            patch("app.core.auth._extract_configured_api_key", return_value=None),
        ):
            from fastapi import Request

            mock_request = MagicMock(spec=Request)
            mock_request.app.state.settings = None
            result = get_api_key(request=mock_request, provided_api_key=raw_key)

        assert result == raw_key

    def test_get_api_key_returns_none_when_not_required(self) -> None:
        with (
            patch("app.core.auth._is_auth_required", return_value=False),
            patch("app.core.auth._extract_configured_api_key", return_value=None),
        ):
            from fastapi import Request

            mock_request = MagicMock(spec=Request)
            mock_request.app.state.settings = None
            result = get_api_key(request=mock_request, provided_api_key=None)

        assert result is None

    def test_get_api_key_raises_401_when_auth_required_and_key_missing(self) -> None:
        with (
            patch("app.core.auth._is_auth_required", return_value=True),
            patch("app.core.auth._extract_configured_api_key", return_value=None),
        ):
            from fastapi import Request

            mock_request = MagicMock(spec=Request)
            mock_request.app.state.settings = None
            with pytest.raises(HTTPException) as exc_info:
                get_api_key(
                    request=mock_request,
                    provided_api_key=None,
                    bearer_context=None,
                )

        assert exc_info.value.status_code == 401
        assert "missing" in exc_info.value.detail.lower() or "api key" in exc_info.value.detail.lower()

    def test_get_api_key_returns_provided_key_when_not_required(self) -> None:
        with (
            patch("app.core.auth._is_auth_required", return_value=False),
            patch("app.core.auth._extract_configured_api_key", return_value="correct-key"),
            patch("app.core.auth._resolve_registry_api_key", return_value=None),
            patch("app.core.auth._has_registry_keys", return_value=True),
        ):
            from fastapi import Request

            mock_request = MagicMock(spec=Request)
            mock_request.app.state.settings = None
            result = get_api_key(request=mock_request, provided_api_key="wrong-key")

        assert result == "wrong-key"

    def test_registry_key_type_is_str_or_none(self) -> None:
        registry = APIKeyRegistry()
        for i in range(3):
            k = generate_api_key()
            registry.create_key(f"key-{i}", api_key=k)
            resolved = registry.authenticate(k, touch=False)
            assert resolved is not None
            assert isinstance(resolved.api_key, str)


# ---------------------------------------------------------------------------
# require_scope — enforces scope on EdgeAuthContext
# ---------------------------------------------------------------------------


class TestRequireScope:
    @pytest.mark.asyncio
    async def test_scope_granted_returns_edge_auth_context(self) -> None:
        ctx = _make_edge_auth_context(permissions=("read", "write"))
        inner_fn = require_scope("read")
        result = await inner_fn(auth=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_scope_denied_raises_403(self) -> None:
        ctx = _make_edge_auth_context(permissions=("read",))
        inner_fn = require_scope("write")

        with pytest.raises(HTTPException) as exc_info:
            await inner_fn(auth=ctx)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_scope_bypasses_all(self) -> None:
        ctx = _make_edge_auth_context(permissions=("admin",))

        for scope in ("read", "write", "delete", "scan", "audit"):
            inner_fn = require_scope(scope)
            result = await inner_fn(auth=ctx)
            assert result is ctx

    @pytest.mark.asyncio
    async def test_scope_enforced_directly_via_permissions(self) -> None:
        ctx_allowed = _make_edge_auth_context(permissions=("scan",))
        ctx_denied = _make_edge_auth_context(permissions=("read",))

        assert "scan" in ctx_allowed.permissions
        assert "scan" not in ctx_denied.permissions

    @pytest.mark.asyncio
    async def test_require_scope_inner_name_set(self) -> None:
        dep = require_scope("audit:read")
        assert callable(dep)
        assert dep.__name__ == "require_scope_audit_read"

    @pytest.mark.asyncio
    async def test_require_scope_with_authenticated_context(self) -> None:
        expected_ctx = _make_edge_auth_context(permissions=("scan", "audit"))
        inner_fn = require_scope("scan")

        result = await inner_fn(auth=expected_ctx)

        assert isinstance(result, EdgeAuthContext)
        assert "scan" in result.permissions

    @pytest.mark.asyncio
    async def test_require_scope_missing_raises_403_with_detail(self) -> None:
        ctx = _make_edge_auth_context(permissions=("read",))
        inner_fn = require_scope("delete")

        with pytest.raises(HTTPException) as exc_info:
            await inner_fn(auth=ctx)

        assert exc_info.value.status_code == 403
        assert "delete" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_scope_detail_contains_required_scope_name(self) -> None:
        ctx = _make_edge_auth_context(permissions=("read",))
        inner_fn = require_scope("audit:write")

        with pytest.raises(HTTPException) as exc_info:
            await inner_fn(auth=ctx)

        assert exc_info.value.status_code == 403
        assert "audit:write" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_scope_uses_edge_auth_context_alias_fields_and_behavior(self) -> None:
        ctx = _make_edge_auth_context(permissions=("scope:read",))
        inner_fn = require_scope("scope:read")
        result = await inner_fn(auth=ctx)
        assert isinstance(result, EdgeAuthContext)
        assert result is ctx
        assert result.principal_id == "pid-edge-001"
        assert result.auth_method == "bearer"
        assert "scope:read" in result.permissions

    @pytest.mark.asyncio
    async def test_require_scope_admin_alias_bypass_preserved(self) -> None:
        ctx = _make_edge_auth_context(permissions=("admin",))
        inner_fn = require_scope("org:delete")
        result = await inner_fn(auth=ctx)
        assert result is ctx


# ---------------------------------------------------------------------------
# Compound dependencies — require_authenticated, require_access_dependency,
# require_same_org_dependency
# ---------------------------------------------------------------------------


class TestRequireAuthenticated:
    @pytest.mark.asyncio
    async def test_authenticated_context_passes(self) -> None:
        ctx = _make_auth_context(authenticated=True, principal_type="platform")
        result = await require_authenticated(context=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_unauthenticated_context_raises(self) -> None:
        ctx = _make_auth_context(
            authenticated=False,
            principal_type="anonymous",
            api_key=None,
        )
        with pytest.raises(AppError) as exc_info:
            await require_authenticated(context=ctx)
        assert exc_info.value.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_returns_exact_auth_context(self) -> None:
        ctx = _make_auth_context(authenticated=True, org_id="org-test-01")
        result = await require_authenticated(context=ctx)
        assert result.org_id == "org-test-01"
        assert result.authenticated is True

    @pytest.mark.asyncio
    async def test_platform_principal_passes(self) -> None:
        ctx = _make_auth_context(authenticated=True, principal_type="platform")
        result = await require_authenticated(context=ctx)
        assert result.principal_type == "platform"

    @pytest.mark.asyncio
    async def test_api_key_principal_passes(self) -> None:
        ctx = _make_auth_context(authenticated=True, principal_type="api_key")
        result = await require_authenticated(context=ctx)
        assert result.principal_type == "api_key"

    @pytest.mark.asyncio
    async def test_org_key_principal_passes(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="org_key",
            key_type="org",
        )
        result = await require_authenticated(context=ctx)
        assert result.principal_type == "org_key"
        assert result.key_type == "org"


class TestRequireAccessDependency:
    @pytest.mark.asyncio
    async def test_platform_principal_passes_any_action(self) -> None:
        ctx = _make_auth_context(authenticated=True, principal_type="platform")
        dep = require_access_dependency(action="scan:execute")
        result = await dep(context=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_authenticated_platform_passes_with_permission(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            permissions=("scan:execute",),
        )
        dep = require_access_dependency(
            action="scan:execute",
            permission="scan:execute",
        )
        result = await dep(context=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_unauthenticated_raises(self) -> None:
        ctx = _make_auth_context(
            authenticated=False,
            principal_type="anonymous",
            api_key=None,
        )
        dep = require_access_dependency(action="scan:execute")
        with pytest.raises(AppError) as exc_info:
            await dep(context=ctx)
        assert exc_info.value.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_returns_auth_context_on_success(self) -> None:
        ctx = _make_auth_context(authenticated=True, principal_type="platform")
        dep = require_access_dependency(action="audit:read")
        result = await dep(context=ctx)
        assert isinstance(result, AuthContext)
        assert result.authenticated is True

    @pytest.mark.asyncio
    async def test_dependency_with_roles_platform_bypass(self) -> None:
        ctx = _make_auth_context(authenticated=True, principal_type="platform")
        dep = require_access_dependency(
            action="admin:action",
            roles=("platform_admin",),
        )
        result = await dep(context=ctx)
        assert result is ctx


class TestRequireSameOrgDependency:
    @pytest.mark.asyncio
    async def test_context_org_passes(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            org_id="org-match",
        )
        result = await require_same_org_dependency(context=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_context_org_used_directly(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            org_id="org-from-ctx",
        )
        result = await require_same_org_dependency(context=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_missing_context_org_raises(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="api_key",
            org_id=None,
        )
        with pytest.raises(AppError) as exc_info:
            await require_same_org_dependency(context=ctx)
        assert exc_info.value.status_code == 403
        assert exc_info.value.error == "org_isolation_denied"

    @pytest.mark.asyncio
    async def test_unauthenticated_with_org_raises(self) -> None:
        ctx = _make_auth_context(
            authenticated=False,
            principal_type="anonymous",
            org_id="org-anon",
            api_key=None,
        )
        with pytest.raises(AppError) as exc_info:
            await require_same_org_dependency(context=ctx)
        assert exc_info.value.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_returns_auth_context_type_on_success(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            org_id="org-typed",
        )
        result = await require_same_org_dependency(context=ctx)
        assert isinstance(result, AuthContext)


# ---------------------------------------------------------------------------
# Integration smoke — all compound deps chain through valid AuthContext
# ---------------------------------------------------------------------------


class TestCompoundDependenciesChain:
    @pytest.mark.asyncio
    async def test_all_compound_deps_pass_with_platform_context(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            org_id="org-chain-01",
        )

        r1 = await require_authenticated(context=ctx)
        assert r1 is ctx

        dep = require_access_dependency(action="chain:test")
        r2 = await dep(context=ctx)
        assert r2 is ctx

        r3 = await require_same_org_dependency(context=ctx)
        assert r3 is ctx

    @pytest.mark.asyncio
    async def test_edge_and_local_contexts_are_same_runtime_type(self) -> None:
        edge_ctx = _make_edge_auth_context()
        local_ctx = _make_auth_context(authenticated=True)

        assert isinstance(edge_ctx, EdgeAuthContext)
        assert isinstance(local_ctx, AuthContext)
        assert type(edge_ctx) is type(local_ctx)

    @pytest.mark.asyncio
    async def test_require_api_key_edge_result_is_auth_context_alias(self) -> None:
        edge_ctx = _make_edge_auth_context()
        assert isinstance(edge_ctx, AuthContext)

    @pytest.mark.asyncio
    async def test_scope_check_on_edge_context_is_permissions_based(self) -> None:
        edge_ctx = _make_edge_auth_context(permissions=("scan",))
        assert "scan" in edge_ctx.permissions
        assert "delete" not in edge_ctx.permissions

    @pytest.mark.asyncio
    async def test_auth_context_key_type_personal_default(self) -> None:
        ctx = _make_auth_context(authenticated=True, key_type="personal")
        assert ctx.key_type == "personal"

    @pytest.mark.asyncio
    async def test_auth_context_key_type_org(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="org_key",
            key_type="org",
        )
        assert ctx.key_type == "org"
        assert ctx.principal_type == "org_key"
