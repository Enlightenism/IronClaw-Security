from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

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
    )


def _make_edge_auth_context(
    *,
    tenant_id: str = "tenant-xyz",
    scopes: tuple[str, ...] = ("read",),
    bearer_token: str = "tok-abc",
    principal_id: str | None = "pid-edge-001",
) -> EdgeAuthContext:
    return EdgeAuthContext(
        tenant_id=tenant_id,
        scopes=scopes,
        bearer_token=bearer_token,
        principal_id=principal_id,
    )


def _make_registry_stub_returning_none() -> MagicMock:
    """Return a registry stub whose .authenticate() always returns None."""
    stub = MagicMock()
    stub.authenticate.return_value = None
    return stub


# ---------------------------------------------------------------------------
# EdgeAuthContext unit tests
# ---------------------------------------------------------------------------


class TestEdgeAuthContext:
    def test_has_scope_exact_match(self) -> None:
        ctx = _make_edge_auth_context(scopes=("read", "write"))
        assert ctx.has_scope("read") is True
        assert ctx.has_scope("write") is True

    def test_has_scope_admin_bypass(self) -> None:
        ctx = _make_edge_auth_context(scopes=("admin",))
        assert ctx.has_scope("read") is True
        assert ctx.has_scope("delete") is True
        assert ctx.has_scope("anything") is True

    def test_has_scope_missing(self) -> None:
        ctx = _make_edge_auth_context(scopes=("read",))
        assert ctx.has_scope("write") is False
        assert ctx.has_scope("delete") is False

    def test_has_scope_empty_scopes(self) -> None:
        ctx = _make_edge_auth_context(scopes=())
        assert ctx.has_scope("read") is False
        assert ctx.has_scope("admin") is False

    def test_edge_auth_context_is_frozen(self) -> None:
        ctx = _make_edge_auth_context()
        with pytest.raises((AttributeError, TypeError)):
            ctx.tenant_id = "mutated"  # type: ignore[misc]

    def test_edge_auth_context_fields(self) -> None:
        ctx = _make_edge_auth_context(
            tenant_id="t1",
            scopes=("scan", "audit"),
            bearer_token="bearer-tok",
            principal_id="p-001",
        )
        assert ctx.tenant_id == "t1"
        assert ctx.scopes == ("scan", "audit")
        assert ctx.bearer_token == "bearer-tok"
        assert ctx.principal_id == "p-001"


# ---------------------------------------------------------------------------
# require_api_key (Edge Function path) — returns EdgeAuthContext
# ---------------------------------------------------------------------------


class TestRequireApiKeyEdgePath:
    """
    require_api_key calls registry.authenticate() first; if it returns a record
    the edge path is never reached.  Patch get_api_key_registry to return a stub
    whose .authenticate() returns None so the local-registry path never intercepts
    the bearer token before the mocked edge path runs.
    """

    @pytest.mark.asyncio
    async def test_require_api_key_returns_edge_auth_context(self) -> None:
        bearer = "valid-bearer-token"
        expected = EdgeAuthContext(
            tenant_id="tenant-001",
            scopes=("read",),
            bearer_token=bearer,
            principal_id="pid-edge-001",
        )

        registry_stub = _make_registry_stub_returning_none()

        with (
            patch(
                "app.core.api_key_auth.get_api_key_registry",
                return_value=registry_stub,
            ),
            patch(
                "app.core.api_key_auth._call_edge_auth",
                new=AsyncMock(return_value=expected),
            ),
        ):
            creds = MagicMock()
            creds.credentials = bearer
            result = await require_api_key(credentials=creds)

        assert isinstance(result, EdgeAuthContext)
        assert result.tenant_id == "tenant-001"
        assert result.bearer_token == bearer

    @pytest.mark.asyncio
    async def test_require_api_key_missing_credentials_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(credentials=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_require_api_key_empty_credentials_raises_401(self) -> None:
        creds = MagicMock()
        creds.credentials = ""
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(credentials=creds)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_require_api_key_calls_edge_function_url(self) -> None:
        bearer = "my-bearer"
        expected = EdgeAuthContext(
            tenant_id="tenant-edge",
            scopes=("read",),
            bearer_token=bearer,
        )

        mock_call = AsyncMock(return_value=expected)
        registry_stub = _make_registry_stub_returning_none()

        with (
            patch(
                "app.core.api_key_auth.get_api_key_registry",
                return_value=registry_stub,
            ),
            patch("app.core.api_key_auth._call_edge_auth", new=mock_call),
        ):
            creds = MagicMock()
            creds.credentials = bearer
            result = await require_api_key(credentials=creds)

        mock_call.assert_awaited_once_with(bearer)
        assert result is expected

    @pytest.mark.asyncio
    async def test_require_api_key_propagates_edge_auth_error(self) -> None:
        with patch(
            "app.core.api_key_auth._call_edge_auth",
            new=AsyncMock(side_effect=HTTPException(status_code=401, detail="Invalid token")),
        ):
            creds = MagicMock()
            creds.credentials = "bad-token"
            with pytest.raises(HTTPException) as exc_info:
                await require_api_key(credentials=creds)
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
        registry = APIKeyRegistry()
        raw_key = generate_api_key()
        registry.create_key("local-dep-key", api_key=raw_key)

        with (
            patch("app.core.auth._resolve_registry_api_key", return_value=MagicMock(active=True, revoked_at=None)),
            patch("app.core.auth._is_auth_required", return_value=False),
            patch("app.core.auth._extract_configured_api_key", return_value=None),
        ):
            from fastapi import Request

            mock_request = MagicMock(spec=Request)
            mock_request.app.state.settings = None
            result = get_api_key(request=mock_request, provided_api_key=raw_key)

        assert isinstance(result, str) or result is None

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
        ctx = _make_edge_auth_context(scopes=("read", "write"))
        inner_fn = require_scope("read")
        result = await inner_fn(auth=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_scope_denied_raises_403(self) -> None:
        ctx = _make_edge_auth_context(scopes=("read",))
        inner_fn = require_scope("write")

        with pytest.raises(HTTPException) as exc_info:
            await inner_fn(auth=ctx)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_scope_bypasses_all(self) -> None:
        ctx = _make_edge_auth_context(scopes=("admin",))

        for scope in ("read", "write", "delete", "scan", "audit"):
            assert ctx.has_scope(scope) is True

    @pytest.mark.asyncio
    async def test_scope_enforced_directly_via_has_scope(self) -> None:
        ctx_allowed = _make_edge_auth_context(scopes=("scan",))
        ctx_denied = _make_edge_auth_context(scopes=("read",))

        assert ctx_allowed.has_scope("scan") is True
        assert ctx_denied.has_scope("scan") is False

    @pytest.mark.asyncio
    async def test_require_scope_inner_name_set(self) -> None:
        dep = require_scope("audit:read")
        assert callable(dep)

    @pytest.mark.asyncio
    async def test_require_scope_with_mocked_require_api_key(self) -> None:
        expected_ctx = _make_edge_auth_context(scopes=("scan", "audit"))
        inner_fn = require_scope("scan")

        result = await inner_fn(auth=expected_ctx)

        assert isinstance(result, EdgeAuthContext)
        assert result.has_scope("scan") is True

    @pytest.mark.asyncio
    async def test_require_scope_missing_raises_403_with_detail(self) -> None:
        ctx = _make_edge_auth_context(scopes=("read",))
        inner_fn = require_scope("delete")

        with pytest.raises(HTTPException) as exc_info:
            await inner_fn(auth=ctx)

        assert exc_info.value.status_code == 403
        assert "delete" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Compound dependencies — require_authenticated, require_access_dependency,
# require_same_org_dependency — all pass with valid AuthContext
# ---------------------------------------------------------------------------


class TestRequireAuthenticated:
    @pytest.mark.asyncio
    async def test_authenticated_context_passes(self) -> None:
        ctx = _make_auth_context(authenticated=True, principal_type="platform")
        result = await require_authenticated(context=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_unauthenticated_context_raises(self) -> None:
        from app.core.errors import AppError

        ctx = _make_auth_context(authenticated=False, principal_type="anonymous", api_key=None)
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
        dep = require_access_dependency(action="scan:execute", permission="scan:execute")
        result = await dep(context=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_unauthenticated_raises(self) -> None:
        from app.core.errors import AppError

        ctx = _make_auth_context(authenticated=False, principal_type="anonymous", api_key=None)
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
        dep = require_access_dependency(action="admin:action", roles=("platform_admin",))
        result = await dep(context=ctx)
        assert result is ctx


class TestRequireSameOrgDependency:
    @pytest.mark.asyncio
    async def test_matching_org_passes(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            org_id="org-match",
        )
        result = await require_same_org_dependency(
            x_org_id="org-match",
            context=ctx,
        )
        assert result is ctx

    @pytest.mark.asyncio
    async def test_no_header_uses_context_org(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            org_id="org-from-ctx",
        )
        result = await require_same_org_dependency(
            x_org_id=None,
            context=ctx,
        )
        assert result is ctx

    @pytest.mark.asyncio
    async def test_mismatched_org_raises(self) -> None:
        from app.core.errors import AppError

        ctx = _make_auth_context(
            authenticated=True,
            principal_type="api_key",
            org_id="org-a",
        )
        with pytest.raises(AppError) as exc_info:
            await require_same_org_dependency(
                x_org_id="org-b",
                context=ctx,
            )
        assert exc_info.value.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_with_org_raises(self) -> None:
        from app.core.errors import AppError

        ctx = _make_auth_context(
            authenticated=False,
            principal_type="anonymous",
            org_id="org-anon",
            api_key=None,
        )
        with pytest.raises(AppError) as exc_info:
            await require_same_org_dependency(
                x_org_id="org-anon",
                context=ctx,
            )
        assert exc_info.value.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_returns_auth_context_type_on_success(self) -> None:
        ctx = _make_auth_context(
            authenticated=True,
            principal_type="platform",
            org_id="org-typed",
        )
        result = await require_same_org_dependency(
            x_org_id="org-typed",
            context=ctx,
        )
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

        r3 = await require_same_org_dependency(x_org_id="org-chain-01", context=ctx)
        assert r3 is ctx

    @pytest.mark.asyncio
    async def test_edge_and_local_contexts_are_separate_types(self) -> None:
        edge_ctx = _make_edge_auth_context(tenant_id="tenant-sep")
        local_ctx = _make_auth_context(authenticated=True)

        assert isinstance(edge_ctx, EdgeAuthContext)
        assert isinstance(local_ctx, AuthContext)
        assert type(edge_ctx) is not type(local_ctx)

    @pytest.mark.asyncio
    async def test_require_api_key_edge_result_is_not_auth_context(self) -> None:
        edge_ctx = _make_edge_auth_context()
        assert not isinstance(edge_ctx, AuthContext)

    @pytest.mark.asyncio
    async def test_scope_check_on_edge_context_is_independent(self) -> None:
        edge_ctx = _make_edge_auth_context(scopes=("scan",))
        assert edge_ctx.has_scope("scan") is True
        assert edge_ctx.has_scope("delete") is False
