from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
import httpx
import pytest

from app.core.api_key_auth import (
    EdgeAuthContext,
    _call_edge_auth,
    require_scope,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_TOKEN = "test-bearer-token-abc123"
_TENANT_ID = "tenant-001"
_SCOPES = ["scan:read", "scan:write"]


def _mock_response(status_code: int, body: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = body or {}
    return resp


def _patch_httpx(mock_response: MagicMock):
    """Patch httpx.AsyncClient.post to return a controlled response."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)
    return patch("httpx.AsyncClient", return_value=mock_client)


def _patch_httpx_raises(exc: BaseException):
    """Patch httpx.AsyncClient.post to raise a controlled exception."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=exc)
    return patch("httpx.AsyncClient", return_value=mock_client)


# ---------------------------------------------------------------------------
# _call_edge_auth — 200 with valid body → EdgeAuthContext
# ---------------------------------------------------------------------------


class TestCallEdgeAuthValid:
    @pytest.mark.asyncio
    async def test_200_valid_body_returns_edge_auth_context(self):
        resp = _mock_response(200, {"tenant_id": _TENANT_ID, "scopes": _SCOPES})
        with _patch_httpx(resp):
            ctx = await _call_edge_auth(_VALID_TOKEN)
        assert isinstance(ctx, EdgeAuthContext)

    @pytest.mark.asyncio
    async def test_200_tenant_id_set_correctly(self):
        resp = _mock_response(200, {"tenant_id": _TENANT_ID, "scopes": _SCOPES})
        with _patch_httpx(resp):
            ctx = await _call_edge_auth(_VALID_TOKEN)
        assert ctx.tenant_id == _TENANT_ID

    @pytest.mark.asyncio
    async def test_200_scopes_set_correctly(self):
        resp = _mock_response(200, {"tenant_id": _TENANT_ID, "scopes": _SCOPES})
        with _patch_httpx(resp):
            ctx = await _call_edge_auth(_VALID_TOKEN)
        assert set(ctx.scopes) == set(_SCOPES)

    @pytest.mark.asyncio
    async def test_200_bearer_token_preserved(self):
        resp = _mock_response(200, {"tenant_id": _TENANT_ID, "scopes": _SCOPES})
        with _patch_httpx(resp):
            ctx = await _call_edge_auth(_VALID_TOKEN)
        assert ctx.bearer_token == _VALID_TOKEN

    @pytest.mark.asyncio
    async def test_200_principal_id_populated_when_present(self):
        resp = _mock_response(200, {"tenant_id": _TENANT_ID, "scopes": _SCOPES, "principal_id": "user-xyz"})
        with _patch_httpx(resp):
            ctx = await _call_edge_auth(_VALID_TOKEN)
        assert ctx.principal_id == "user-xyz"

    @pytest.mark.asyncio
    async def test_200_principal_id_none_when_absent(self):
        resp = _mock_response(200, {"tenant_id": _TENANT_ID, "scopes": _SCOPES})
        with _patch_httpx(resp):
            ctx = await _call_edge_auth(_VALID_TOKEN)
        assert ctx.principal_id is None


# ---------------------------------------------------------------------------
# _call_edge_auth — 200 missing tenant_id → HTTP 401
# ---------------------------------------------------------------------------


class TestCallEdgeAuthMissingTenantId:
    @pytest.mark.asyncio
    async def test_200_missing_tenant_id_raises_401(self):
        resp = _mock_response(200, {"scopes": _SCOPES})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_200_empty_tenant_id_raises_401(self):
        resp = _mock_response(200, {"tenant_id": "", "scopes": _SCOPES})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_200_null_tenant_id_raises_401(self):
        resp = _mock_response(200, {"tenant_id": None, "scopes": _SCOPES})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_200_missing_tenant_id_detail_contains_tenant_id(self):
        resp = _mock_response(200, {"scopes": _SCOPES})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert "tenant_id" in exc_info.value.detail


# ---------------------------------------------------------------------------
# _call_edge_auth — non-200 response → HTTP 401
# ---------------------------------------------------------------------------


class TestCallEdgeAuthNon200:
    @pytest.mark.asyncio
    async def test_401_response_raises_401(self):
        resp = _mock_response(401, {})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_403_response_raises_401(self):
        resp = _mock_response(403, {})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_500_response_raises_401(self):
        resp = _mock_response(500, {})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_404_response_raises_401(self):
        resp = _mock_response(404, {})
        with _patch_httpx(resp):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# _call_edge_auth — TimeoutException → HTTP 401 with "timeout" detail
# ---------------------------------------------------------------------------


class TestCallEdgeAuthTimeout:
    @pytest.mark.asyncio
    async def test_timeout_raises_401(self):
        with _patch_httpx_raises(httpx.TimeoutException("timed out")):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_timeout_detail_contains_timeout(self):
        with _patch_httpx_raises(httpx.TimeoutException("timed out")):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert "timeout" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_timeout_has_www_authenticate_header(self):
        with _patch_httpx_raises(httpx.TimeoutException("timed out")):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.headers.get("WWW-Authenticate") == "Bearer"


# ---------------------------------------------------------------------------
# _call_edge_auth — RequestError → HTTP 401 with "unreachable" detail
# ---------------------------------------------------------------------------


class TestCallEdgeAuthRequestError:
    @pytest.mark.asyncio
    async def test_request_error_raises_401(self):
        with _patch_httpx_raises(httpx.ConnectError("connection refused")):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_request_error_detail_contains_unreachable(self):
        with _patch_httpx_raises(httpx.ConnectError("connection refused")):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert "unreachable" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_request_error_has_www_authenticate_header(self):
        with _patch_httpx_raises(httpx.ConnectError("connection refused")):
            with pytest.raises(HTTPException) as exc_info:
                await _call_edge_auth(_VALID_TOKEN)
        assert exc_info.value.headers.get("WWW-Authenticate") == "Bearer"


# ---------------------------------------------------------------------------
# require_api_key — missing Authorization header → HTTP 401
# ---------------------------------------------------------------------------


class TestRequireApiKeyMissingHeader:
    @pytest.mark.asyncio
    async def test_missing_credentials_raises_401(self):
        from app.core.api_key_auth import require_api_key

        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(credentials=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_credentials_detail_mentions_bearer(self):
        from app.core.api_key_auth import require_api_key

        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(credentials=None)
        assert "bearer" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_empty_credentials_raises_401(self):
        from fastapi.security import HTTPAuthorizationCredentials

        from app.core.api_key_auth import require_api_key

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="")
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(credentials=creds)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# require_scope — matching scope passes
# ---------------------------------------------------------------------------


class TestRequireScopeMatch:
    @pytest.mark.asyncio
    async def test_matching_scope_returns_auth_context(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("scan:read", "scan:write"),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("scan:read")
        result = await dep(auth=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_matching_scope_does_not_raise(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("scan:read",),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("scan:read")
        try:
            await dep(auth=ctx)
        except HTTPException:
            pytest.fail("require_scope raised unexpectedly for matching scope")


# ---------------------------------------------------------------------------
# require_scope — mismatched scope → HTTP 403
# ---------------------------------------------------------------------------


class TestRequireScopeMismatch:
    @pytest.mark.asyncio
    async def test_mismatched_scope_raises_403(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("scan:read",),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("admin:write")
        with pytest.raises(HTTPException) as exc_info:
            await dep(auth=ctx)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_mismatched_scope_detail_contains_scope_name(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("scan:read",),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("admin:write")
        with pytest.raises(HTTPException) as exc_info:
            await dep(auth=ctx)
        assert "admin:write" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_empty_scopes_raises_403(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=(),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("scan:read")
        with pytest.raises(HTTPException) as exc_info:
            await dep(auth=ctx)
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# require_scope — admin scope bypasses all scope checks
# ---------------------------------------------------------------------------


class TestRequireScopeAdminBypass:
    @pytest.mark.asyncio
    async def test_admin_scope_bypasses_any_required_scope(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("admin",),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("scan:write")
        result = await dep(auth=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_admin_scope_bypasses_arbitrary_scope(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("admin",),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("superuser:delete:everything")
        result = await dep(auth=ctx)
        assert result is ctx

    @pytest.mark.asyncio
    async def test_admin_scope_does_not_raise(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("admin",),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("any:scope:at:all")
        try:
            await dep(auth=ctx)
        except HTTPException:
            pytest.fail("admin scope raised HTTPException — bypass logic broken")

    @pytest.mark.asyncio
    async def test_admin_among_multiple_scopes_bypasses(self):
        ctx = EdgeAuthContext(
            tenant_id=_TENANT_ID,
            scopes=("scan:read", "admin", "telemetry:read"),
            bearer_token=_VALID_TOKEN,
        )
        dep = require_scope("audit:write")
        result = await dep(auth=ctx)
        assert result is ctx


# ---------------------------------------------------------------------------
# EdgeAuthContext.has_scope unit tests
# ---------------------------------------------------------------------------


class TestEdgeAuthContextHasScope:
    def test_has_scope_true_for_exact_match(self):
        ctx = EdgeAuthContext(tenant_id=_TENANT_ID, scopes=("scan:read",), bearer_token=_VALID_TOKEN)
        assert ctx.has_scope("scan:read") is True

    def test_has_scope_false_for_missing_scope(self):
        ctx = EdgeAuthContext(tenant_id=_TENANT_ID, scopes=("scan:read",), bearer_token=_VALID_TOKEN)
        assert ctx.has_scope("scan:write") is False

    def test_has_scope_true_when_admin_present(self):
        ctx = EdgeAuthContext(tenant_id=_TENANT_ID, scopes=("admin",), bearer_token=_VALID_TOKEN)
        assert ctx.has_scope("any:scope") is True

    def test_has_scope_false_for_empty_scopes(self):
        ctx = EdgeAuthContext(tenant_id=_TENANT_ID, scopes=(), bearer_token=_VALID_TOKEN)
        assert ctx.has_scope("scan:read") is False
