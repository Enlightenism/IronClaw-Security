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
from app.core.apikeys import (
    APIKeyRecord,
    APIKeyRegistry,
    fingerprint_api_key,
    mask_api_key,
    utc_now_iso,
)
from app.core.auth import (
    AuthContext,
    _coerce_key_type,
    _coerce_org_id,
    _coerce_permissions,
    _coerce_principal_id,
    _coerce_roles,
    _record_is_usable,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_TOKEN = "test-bearer-token-abc123"
_TENANT_ID = "tenant-001"
_SCOPES = ["scan:read", "scan:write"]

_PERSONAL_KEY_RAW = "ic_personal_test_abc123"
_ORG_KEY_RAW = "ic_org_team_test_xyz789"
_ORG_ID = "org-ironclaw-001"


def _mock_response(status_code: int, body: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = body or {}
    return resp


def _patch_httpx(mock_response: MagicMock):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)
    return patch("httpx.AsyncClient", return_value=mock_client)


def _patch_httpx_raises(exc: BaseException):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=exc)
    return patch("httpx.AsyncClient", return_value=mock_client)


def _make_personal_record(
    raw_key: str = _PERSONAL_KEY_RAW,
    active: bool = True,
    revoked: bool = False,
    org_id: str | None = None,
) -> APIKeyRecord:
    return APIKeyRecord(
        key_id="key_personal_001",
        api_key=raw_key,
        masked_key=mask_api_key(raw_key),
        fingerprint=fingerprint_api_key(raw_key),
        display_name="Personal Test Key",
        owner_key="user@ironclaw.test",
        scopes=("scan:read", "scan:write"),
        active=active,
        revoked_at=utc_now_iso() if revoked else None,
        key_type="personal",
        org_id=org_id,
    )


def _make_org_record(
    raw_key: str = _ORG_KEY_RAW,
    org_id: str = _ORG_ID,
    active: bool = True,
    revoked: bool = False,
) -> APIKeyRecord:
    return APIKeyRecord(
        key_id="key_org_001",
        api_key=raw_key,
        masked_key=mask_api_key(raw_key),
        fingerprint=fingerprint_api_key(raw_key),
        display_name="Org Test Key",
        owner_key="team@ironclaw.test",
        scopes=("scan:read", "scan:write", "audit:read"),
        active=active,
        revoked_at=utc_now_iso() if revoked else None,
        key_type="org",
        org_id=org_id,
    )


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
# require_api_key (edge layer) — missing Authorization header → HTTP 401
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


# ---------------------------------------------------------------------------
# _coerce_key_type — personal vs org resolution
# ---------------------------------------------------------------------------


class TestCoerceKeyType:
    def test_personal_record_returns_personal(self):
        record = _make_personal_record()
        assert _coerce_key_type(record) == "personal"

    def test_org_record_returns_org(self):
        record = _make_org_record()
        assert _coerce_key_type(record) == "org"

    def test_none_record_returns_personal(self):
        assert _coerce_key_type(None) == "personal"

    def test_missing_key_type_field_defaults_to_personal(self):
        from dataclasses import replace

        record = _make_personal_record()
        record_no_type = replace(record, key_type="")
        assert _coerce_key_type(record_no_type) == "personal"


# ---------------------------------------------------------------------------
# AuthContext — personal key produces correct principal_type and key_type
# ---------------------------------------------------------------------------


class TestAuthContextPersonalKey:
    def test_personal_key_builds_correct_auth_context(self):
        registry = APIKeyRegistry()
        record = registry.create_key(
            "Unit Test Personal Key",
            owner_key="tester@ironclaw.test",
            scopes=["scan:read"],
            key_type="personal",
        )
        ctx = AuthContext(
            api_key=record.api_key,
            principal_type="api_key",
            principal_id=record.key_id,
            session_id=None,
            org_id=None,
            permissions=record.scopes,
            roles=(),
            authenticated=True,
            auth_source="registry",
            auth_method="registry_api_key",
            key_type=record.key_type,
        )
        assert ctx.key_type == "personal"
        assert ctx.principal_type == "api_key"
        assert ctx.authenticated is True

    def test_personal_key_type_field_is_personal(self):
        record = _make_personal_record()
        assert record.key_type == "personal"

    def test_personal_key_has_no_org_id(self):
        record = _make_personal_record()
        assert record.org_id is None


# ---------------------------------------------------------------------------
# AuthContext — org key produces key_type="org" and principal_type="org_key"
# ---------------------------------------------------------------------------


class TestAuthContextOrgKey:
    def test_org_key_type_is_org(self):
        record = _make_org_record()
        assert record.key_type == "org"

    def test_org_key_carries_org_id(self):
        record = _make_org_record(org_id=_ORG_ID)
        assert record.org_id == _ORG_ID

    def test_org_key_auth_context_has_org_key_principal_type(self):
        record = _make_org_record()
        resolved_key_type = _coerce_key_type(record)
        principal_type = "org_key" if resolved_key_type == "org" else "api_key"
        ctx = AuthContext(
            api_key=record.api_key,
            principal_type=principal_type,
            principal_id=record.key_id,
            session_id=None,
            org_id=record.org_id,
            permissions=record.scopes,
            roles=(),
            authenticated=True,
            auth_source="registry",
            auth_method="registry_api_key",
            key_type=resolved_key_type,
        )
        assert ctx.principal_type == "org_key"
        assert ctx.key_type == "org"
        assert ctx.org_id == _ORG_ID

    def test_multiple_team_members_resolve_same_org_id(self):
        registry = APIKeyRegistry()
        org_record = registry.create_key(
            "Team Alpha Key",
            key_type="org",
            org_id=_ORG_ID,
            scopes=["scan:read", "scan:write"],
        )
        for _ in range(3):
            resolved = _coerce_key_type(org_record)
            assert resolved == "org"
            assert org_record.org_id == _ORG_ID


# ---------------------------------------------------------------------------
# _record_is_usable — active / revoked / expired gate
# ---------------------------------------------------------------------------


class TestRecordIsUsable:
    def test_active_personal_record_is_usable(self):
        record = _make_personal_record(active=True)
        assert _record_is_usable(record) is True

    def test_active_org_record_is_usable(self):
        record = _make_org_record(active=True)
        assert _record_is_usable(record) is True

    def test_inactive_record_is_not_usable(self):
        record = _make_personal_record(active=False)
        assert _record_is_usable(record) is False

    def test_revoked_personal_record_is_not_usable(self):
        record = _make_personal_record(revoked=True)
        assert _record_is_usable(record) is False

    def test_revoked_org_record_is_not_usable(self):
        record = _make_org_record(revoked=True)
        assert _record_is_usable(record) is False

    def test_none_record_is_not_usable(self):
        assert _record_is_usable(None) is False


# ---------------------------------------------------------------------------
# _build_auth_context_from_record — field mapping completeness
# ---------------------------------------------------------------------------


class TestBuildAuthContextFromRecord:
    def test_personal_record_maps_key_type_correctly(self):
        record = _make_personal_record()
        assert _coerce_key_type(record) == "personal"

    def test_org_record_maps_key_type_correctly(self):
        record = _make_org_record()
        assert _coerce_key_type(record) == "org"

    def test_principal_id_resolves_to_key_id(self):
        record = _make_personal_record()
        assert _coerce_principal_id(record) == "key_personal_001"

    def test_permissions_map_from_scopes(self):
        record = _make_personal_record()
        assert set(_coerce_permissions(record)) == {"scan:read", "scan:write"}

    def test_org_permissions_map_from_scopes(self):
        record = _make_org_record()
        perms = set(_coerce_permissions(record))
        assert "scan:read" in perms
        assert "scan:write" in perms
        assert "audit:read" in perms

    def test_org_id_resolves_from_record(self):
        record = _make_org_record(org_id=_ORG_ID)
        fake_request = MagicMock()
        fake_request.app.state = MagicMock(spec=[])
        with patch("app.core.auth._get_settings", return_value=None):
            resolved = _coerce_org_id(fake_request, None, record)
        assert resolved == _ORG_ID

    def test_auth_context_authenticated_true_for_valid_record(self):
        record = _make_personal_record()
        ctx = AuthContext(
            api_key=record.api_key,
            principal_type="api_key",
            principal_id=_coerce_principal_id(record),
            session_id=None,
            org_id=None,
            permissions=_coerce_permissions(record),
            roles=_coerce_roles(record),
            authenticated=True,
            auth_source="registry",
            auth_method="registry_api_key",
            key_type=_coerce_key_type(record),
        )
        assert ctx.authenticated is True
        assert ctx.api_key == record.api_key
        assert ctx.key_type == "personal"
        assert ctx.principal_id == "key_personal_001"

    def test_auth_context_for_org_record_has_all_fields(self):
        record = _make_org_record()
        ctx = AuthContext(
            api_key=record.api_key,
            principal_type="org_key",
            principal_id=_coerce_principal_id(record),
            session_id=None,
            org_id=record.org_id,
            permissions=_coerce_permissions(record),
            roles=_coerce_roles(record),
            authenticated=True,
            auth_source="registry",
            auth_method="registry_api_key",
            key_type=_coerce_key_type(record),
        )
        assert ctx.key_type == "org"
        assert ctx.principal_type == "org_key"
        assert ctx.org_id == _ORG_ID
        assert "scan:read" in ctx.permissions


# ---------------------------------------------------------------------------
# Anonymous context — key_type defaults to "personal"
# ---------------------------------------------------------------------------


class TestAnonymousAuthContext:
    def test_anonymous_context_key_type_is_personal(self):
        ctx = AuthContext(
            api_key=None,
            principal_type="anonymous",
            principal_id=None,
            session_id=None,
            org_id=None,
            authenticated=False,
            auth_source="disabled",
            auth_method=None,
            key_type="personal",
        )
        assert ctx.key_type == "personal"

    def test_anonymous_context_is_not_authenticated(self):
        ctx = AuthContext(
            api_key=None,
            principal_type="anonymous",
            principal_id=None,
            session_id=None,
            org_id=None,
            authenticated=False,
            auth_source="disabled",
            auth_method=None,
            key_type="personal",
        )
        assert ctx.authenticated is False
        assert ctx.principal_type == "anonymous"


# ---------------------------------------------------------------------------
# Registry integration — unknown / revoked / shared org key resolution
# ---------------------------------------------------------------------------


class TestRegistryKeyResolution:
    def test_unknown_key_not_found_in_registry(self):
        registry = APIKeyRegistry()
        result = registry.authenticate("ic_unknown_key_that_was_never_registered", touch=False)
        assert result is None

    def test_revoked_key_authenticate_returns_none(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Revoke Me", key_type="personal")
        registry.revoke_key(record.key_id)
        result = registry.authenticate(record.api_key, touch=False)
        assert result is None

    def test_missing_key_header_results_in_unusable_record(self):
        assert _record_is_usable(None) is False

    def test_org_key_authenticate_succeeds_for_any_team_member(self):
        registry = APIKeyRegistry()
        org_record = registry.create_key(
            "Shared Org Key",
            key_type="org",
            org_id=_ORG_ID,
        )
        shared_key_string = org_record.api_key
        for _ in range(3):
            result = registry.authenticate(shared_key_string, touch=False)
            assert result is not None
            assert result.key_type == "org"
            assert result.org_id == _ORG_ID
