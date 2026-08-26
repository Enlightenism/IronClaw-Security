from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

from app.core.api_key_auth import require_api_key as require_api_key_auth
from app.core.apikeys import (
    APIKeyRecord,
    APIKeyRegistry,
    fingerprint_api_key,
    mask_api_key,
    utc_now_iso,
)
from app.core.auth import (
    API_KEY_HEADER_NAME,
    AUTHORIZATION_HEADER_NAME,
    ORG_ID_HEADER_NAME,
    ORGANIZATION_ID_HEADER_NAME,
    SESSION_ID_HEADER_NAME,
    TENANT_ID_HEADER_NAME,
    AuthContext,
    _coerce_key_type,
    _coerce_org_id,
    _coerce_permissions,
    _coerce_principal_id,
    _coerce_roles,
    _record_is_usable,
    get_auth_context,
    require_api_key,
    require_auth_context,
)
from app.core.errors import AppError, register_exception_handlers

_PERSONAL_KEY_RAW = "ic_personal_test_abc123"
_ORG_KEY_RAW = "ic_org_team_test_xyz789"
_ORG_ID = "org-ironclaw-001"
_CONFIGURED_KEY = "ic_configured_static_key_abc"
_SUPABASE_JWT_SECRET = "super-secret-jwt-signing-key-for-tests"
_BEARER_TOKEN = "test-bearer-token"
_BEARER_PRINCIPAL_ID = "user-123"


_TEST_EC_PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILQtrVqsgUBlx+2WU/ONqBI+Gb/9CWO5Iu/yhlPzJVxmoAoGCCqGSM49
AwEHoUQDQgAERpwUk5Yi5ZO5ri/HP7iaajbhPQ8snugWesnbfp0af61Fq+U2NNmQ
DPmuzaOjuR1oe5rKSQo5GSFypwv7QeIhBw==
-----END EC PRIVATE KEY-----"""


_TEST_EC_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERpwUk5Yi5ZO5ri/HP7iaajbhPQ8s
nugWesnbfp0af61Fq+U2NNmQDPmuzaOjuR1oe5rKSQo5GSFypwv7QeIhBw==
-----END PUBLIC KEY-----"""


_INVALID_BEARER_DETAIL = {
    "error": "invalid_bearer_token",
    "detail": "Invalid Bearer token — algorithm mismatch or signature failure",
    "alg_in_token": "ES256",
    "expected_alg": "ES256",
}
_INVALID_BEARER_DETAIL_WITHOUT_ALG = {
    **_INVALID_BEARER_DETAIL,
    "alg_in_token": None,
}
_MISSING_SUPABASE_JWT_SECRET_DETAIL = "SUPABASE_JWT_SECRET is not configured; configure or use remote validation via SUPABASE_URL + SUPABASE_ANON_KEY"


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


def _make_settings(
    *,
    auth_required: bool = False,
    auth_configured: bool | None = None,
    configured_key: str | None = None,
    supabase_jwt_secret: str | None = None,
    jwt_secret: str | None = None,
    jwt_algorithm: str | None = "HS256",
    jwt_private_key: str | None = None,
    jwt_public_key: str | None = None,
    org_id: str | None = None,
    organization_id: str | None = None,
    default_org_id: str | None = None,
    supabase_url: str | None = None,
    supabase_anon_key: str | None = None,
    supabase_service_role_key: str | None = None,
) -> SimpleNamespace:
    effective_api_key = configured_key
    effective_jwt_secret = jwt_secret
    effective_supabase_jwt_secret = supabase_jwt_secret
    effective_jwt_algorithm = (jwt_algorithm or "").upper()

    if auth_configured is None:
        api_key_auth_configured = bool(effective_api_key)
        bearer_auth_configured = bool(supabase_url) and bool(supabase_anon_key or supabase_service_role_key or effective_supabase_jwt_secret or effective_jwt_secret)
        auth_configured = api_key_auth_configured or bearer_auth_configured
    else:
        api_key_auth_configured = bool(effective_api_key)
        bearer_auth_configured = bool(supabase_url) and bool(supabase_anon_key or supabase_service_role_key or effective_supabase_jwt_secret or effective_jwt_secret)

    effective_auth_required = bool(auth_required and auth_configured)

    return SimpleNamespace(
        auth_required=auth_required,
        AUTH_REQUIRED=auth_required,
        auth_configured=auth_configured,
        effective_auth_required=effective_auth_required,
        ironclaw_api_key=configured_key,
        internal_platform_api_key=None,
        platform_api_key=None,
        admin_api_key=None,
        api_key=None,
        effective_api_key=effective_api_key,
        effective_platform_api_key=None,
        secret_key=None,
        effective_secret_key=None,
        jwt_secret=jwt_secret,
        effective_jwt_secret=effective_jwt_secret,
        supabase_jwt_secret=supabase_jwt_secret,
        SUPABASE_JWT_SECRET=supabase_jwt_secret,
        effective_supabase_jwt_secret=effective_supabase_jwt_secret,
        jwt_algorithm=jwt_algorithm,
        JWT_ALGORITHM=jwt_algorithm,
        effective_jwt_algorithm=effective_jwt_algorithm,
        jwt_private_key=jwt_private_key,
        jwt_public_key=jwt_public_key,
        org_id=org_id,
        organization_id=organization_id,
        default_org_id=default_org_id,
        effective_supabase_url=supabase_url,
        supabase_url=supabase_url,
        effective_supabase_anon_key=supabase_anon_key,
        supabase_anon_key=supabase_anon_key,
        effective_supabase_service_role_key=supabase_service_role_key,
        supabase_service_role_key=supabase_service_role_key,
        bearer_auth_configured=bearer_auth_configured,
        api_key_auth_configured=api_key_auth_configured,
    )


def _make_app(
    *,
    auth_required: bool = False,
    auth_configured: bool | None = None,
    configured_key: str | None = None,
    registry: APIKeyRegistry | None = None,
    supabase_jwt_secret: str | None = None,
    jwt_secret: str | None = None,
    jwt_algorithm: str | None = "HS256",
    jwt_private_key: str | None = None,
    jwt_public_key: str | None = None,
    org_id: str | None = None,
    organization_id: str | None = None,
    default_org_id: str | None = None,
    supabase_url: str | None = None,
    supabase_anon_key: str | None = None,
    supabase_service_role_key: str | None = None,
) -> FastAPI:
    app = FastAPI()
    settings = _make_settings(
        auth_required=auth_required,
        auth_configured=auth_configured,
        configured_key=configured_key,
        supabase_jwt_secret=supabase_jwt_secret,
        jwt_secret=jwt_secret,
        jwt_algorithm=jwt_algorithm,
        jwt_private_key=jwt_private_key,
        jwt_public_key=jwt_public_key,
        org_id=org_id,
        organization_id=organization_id,
        default_org_id=default_org_id,
        supabase_url=supabase_url,
        supabase_anon_key=supabase_anon_key,
        supabase_service_role_key=supabase_service_role_key,
    )
    app.state.settings = settings
    app.state.api_key_registry = registry or APIKeyRegistry()

    register_exception_handlers(app)

    @app.get("/probe/auth-context")
    async def _probe_auth_context(ctx: AuthContext = Depends(get_auth_context)):
        return {
            "authenticated": ctx.authenticated,
            "principal_type": ctx.principal_type,
            "principal_id": ctx.principal_id,
            "auth_source": ctx.auth_source,
            "auth_method": ctx.auth_method,
            "key_type": ctx.key_type,
            "org_id": ctx.org_id,
            "session_id": ctx.session_id,
            "permissions": list(ctx.permissions),
            "roles": list(ctx.roles),
            "metadata": dict(ctx.metadata),
        }

    @app.get("/probe/require-auth")
    async def _probe_require_auth(ctx: AuthContext = Depends(require_auth_context)):
        return {"authenticated": ctx.authenticated}

    @app.get("/probe/api-key-auth")
    async def _probe_api_key_auth(ctx: AuthContext = Depends(require_api_key_auth)):
        return {
            "authenticated": ctx.authenticated,
            "principal_type": ctx.principal_type,
            "principal_id": ctx.principal_id,
            "auth_source": ctx.auth_source,
            "auth_method": ctx.auth_method,
            "key_type": ctx.key_type,
            "org_id": ctx.org_id,
            "permissions": list(ctx.permissions),
            "roles": list(ctx.roles),
        }

    return app


def _anonymous_context() -> AuthContext:
    return AuthContext(
        api_key=None,
        principal_type="anonymous",
        principal_id=None,
        session_id=None,
        org_id=None,
        permissions=(),
        roles=(),
        authenticated=False,
        auth_source="disabled",
        auth_method=None,
        key_type="personal",
    )


def _bearer_context() -> AuthContext:
    return AuthContext(
        api_key=None,
        principal_type="customer",
        principal_id=_BEARER_PRINCIPAL_ID,
        session_id="sess-123",
        org_id="org-123",
        permissions=("scan:read",),
        roles=("member",),
        authenticated=True,
        auth_source="supabase_jwt",
        auth_method="bearer_jwt",
        key_type="personal",
    )


def _encode_bearer_token(
    *,
    sub: str = _BEARER_PRINCIPAL_ID,
    org_id: str | None = "org-123",
    roles: tuple[str, ...] = ("member",),
    permissions: tuple[str, ...] = ("scan:read",),
    principal_type: str = "customer",
    secret: str = _SUPABASE_JWT_SECRET,
    algorithm: str = "HS256",
    extra_claims: dict[str, object] | None = None,
) -> str:
    import jwt

    claims: dict[str, object] = {
        "sub": sub,
        "org_id": org_id,
        "roles": list(roles),
        "permissions": list(permissions),
        "principal_type": principal_type,
        "email": "user@ironclaw.test",
        "role": roles[0] if roles else "member",
        "aal": "aal1",
        "iss": "https://supabase.test/auth/v1",
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, secret, algorithm=algorithm)


class TestGetApiKeyAuthNotRequired:
    def test_no_key_auth_not_required_returns_none(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/auth-context")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is False
        assert data["principal_type"] == "anonymous"

    def test_no_key_auth_not_required_anonymous_auth_source(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get("/probe/auth-context").json()
        assert data["auth_source"] == "disabled"

    def test_invalid_bearer_is_ignored_when_auth_not_required(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=False,
            auth_configured=False,
            registry=registry,
            supabase_jwt_secret=_SUPABASE_JWT_SECRET,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={AUTHORIZATION_HEADER_NAME: "Bearer invalid-token"},
                )
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False


class TestGetApiKeyAuthRequiredMissingKey:
    def test_missing_key_auth_required_raises_401(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/auth-context")
        assert resp.status_code == 401

    def test_missing_key_message_is_normalized(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/auth-context")
        body = resp.json()
        assert body["detail"] == "Missing API key — provide X-API-Key or Bearer token"

    def test_missing_key_message_contains_bearer(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/auth-context")
        assert "Bearer" in resp.json()["detail"]

    def test_missing_key_configured_key_present_raises_401(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/auth-context")
        assert resp.status_code == 401


class TestGetApiKeyInvalidKey:
    def test_invalid_key_raises_401(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: "ic_completely_wrong_key_xyz"},
                )
        assert resp.status_code == 401

    def test_invalid_key_detail_is_invalid_api_key(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: "ic_completely_wrong_key_xyz"},
                )
        body = resp.json()
        assert body.get("error") == "invalid_api_key"
        assert body.get("message") == "Invalid API key"

    def test_wrong_configured_key_raises_401(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: "ic_wrong_static_key"},
                )
        assert resp.status_code == 401

    def test_install_key_value_is_rejected_by_system_auth(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: "ic_install_openclaw_secret_value_123"},
                )
        assert resp.status_code == 401
        assert resp.json().get("error") == "invalid_api_key"
        assert "install key" in resp.json().get("message", "").lower()


class TestGetApiKeyNoKeysConfigured:
    def test_no_keys_configured_raises_503(self):
        empty_registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=None,
            registry=empty_registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=empty_registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: "ic_any_key_doesnt_matter"},
                )
        assert resp.status_code == 503

    def test_no_keys_configured_detail_mentions_api_keys(self):
        empty_registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=None,
            registry=empty_registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=empty_registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: "ic_any_key_doesnt_matter"},
                )
        message = resp.json().get("message", "")
        assert "api keys" in message.lower()

    def test_no_keys_configured_detail_mentions_auth_required(self):
        empty_registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=None,
            registry=empty_registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=empty_registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: "ic_any_key_doesnt_matter"},
                )
        message = resp.json().get("message", "")
        assert "required" in message.lower()


class TestGetAuthContextAnonymous:
    def test_anonymous_context_when_auth_disabled(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/auth-context")
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False

    def test_anonymous_principal_type(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get("/probe/auth-context").json()
        assert data["principal_type"] == "anonymous"

    def test_anonymous_auth_source_is_disabled(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get("/probe/auth-context").json()
        assert data["auth_source"] == "disabled"

    def test_anonymous_key_type_defaults_to_personal(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get("/probe/auth-context").json()
        assert data["key_type"] == "personal"

    def test_anonymous_permissions_empty(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get("/probe/auth-context").json()
        assert data["permissions"] == []


class TestGetAuthContextAuthenticatedPersonalKey:
    def test_valid_personal_key_returns_200(self):
        registry = APIKeyRegistry()
        record = registry.create_key(
            "Test Personal",
            key_type="personal",
            scopes=["scan:read", "scan:write"],
        )
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                )
        assert resp.status_code == 200

    def test_valid_personal_key_authenticated_true(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Personal", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["authenticated"] is True

    def test_valid_personal_key_principal_type_is_api_key(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Personal", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["principal_type"] == "api_key"

    def test_valid_personal_key_key_type_is_personal(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Personal", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["key_type"] == "personal"

    def test_valid_personal_key_auth_source_is_registry(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Personal", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["auth_source"] == "registry"

    def test_valid_personal_key_auth_method_is_registry_api_key(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Personal", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["auth_method"] == "registry_api_key"

    def test_valid_personal_key_permissions_from_scopes(self):
        registry = APIKeyRegistry()
        record = registry.create_key(
            "Test Personal",
            key_type="personal",
            scopes=["scan:read", "scan:write"],
        )
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert set(data["permissions"]) == {"scan:read", "scan:write"}

    def test_valid_personal_key_org_id_none_when_not_set(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Personal", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["org_id"] is None

    def test_valid_personal_key_session_id_propagated(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Personal", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={
                        API_KEY_HEADER_NAME: record.api_key,
                        SESSION_ID_HEADER_NAME: "sess-abc",
                    },
                ).json()
        assert data["session_id"] == "sess-abc"


class TestGetAuthContextAuthenticatedOrgKey:
    def test_valid_org_key_principal_type_is_org_key(self):
        registry = APIKeyRegistry()
        record = registry.create_key(
            "Test Org",
            key_type="org",
            org_id=_ORG_ID,
            scopes=["scan:read", "audit:read"],
        )
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["principal_type"] == "org_key"

    def test_valid_org_key_key_type_is_org(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Org", key_type="org", org_id=_ORG_ID)
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["key_type"] == "org"

    def test_valid_org_key_org_id_propagated(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Test Org", key_type="org", org_id=_ORG_ID)
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert data["org_id"] == _ORG_ID

    def test_valid_org_key_permissions_include_all_scopes(self):
        registry = APIKeyRegistry()
        record = registry.create_key(
            "Test Org",
            key_type="org",
            org_id=_ORG_ID,
            scopes=["scan:read", "scan:write", "audit:read"],
        )
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                ).json()
        assert {"scan:read", "scan:write", "audit:read"}.issubset(set(data["permissions"]))


class TestGetAuthContextConfiguredKey:
    def test_configured_key_returns_authenticated(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: _CONFIGURED_KEY},
                ).json()
        assert data["authenticated"] is True

    def test_configured_key_principal_type_is_platform(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: _CONFIGURED_KEY},
                ).json()
        assert data["principal_type"] == "platform"

    def test_configured_key_auth_source_is_configured(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: _CONFIGURED_KEY},
                ).json()
        assert data["auth_source"] == "configured"

    def test_configured_key_auth_method_is_api_key(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            configured_key=_CONFIGURED_KEY,
            registry=registry,
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                data = client.get(
                    "/probe/auth-context",
                    headers={API_KEY_HEADER_NAME: _CONFIGURED_KEY},
                ).json()
        assert data["auth_method"] == "api_key"


class TestGetAuthContextBearer:
    def test_valid_bearer_token_returns_authenticated_context(self):
        registry = APIKeyRegistry()
        token = _encode_bearer_token()
        app = _make_app(
            auth_required=True,
            registry=registry,
            jwt_secret=_SUPABASE_JWT_SECRET,
            jwt_algorithm="HS256",
            supabase_url="https://supabase.test",
            supabase_anon_key="anon-key",
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={AUTHORIZATION_HEADER_NAME: f"Bearer {token}"},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["principal_type"] == "customer"
        assert data["principal_id"] == _BEARER_PRINCIPAL_ID
        assert data["auth_source"] == "supabase_jwt"
        assert data["auth_method"] == "bearer_jwt"
        assert data["org_id"] == "org-123"
        assert set(data["permissions"]) == {"scan:read"}
        assert set(data["roles"]) == {"member"}

    def test_bearer_token_uses_claim_org_before_headers(self):
        registry = APIKeyRegistry()
        token = _encode_bearer_token(org_id="claim-org-001")
        app = _make_app(
            auth_required=True,
            registry=registry,
            jwt_secret=_SUPABASE_JWT_SECRET,
            jwt_algorithm="HS256",
            supabase_url="https://supabase.test",
            supabase_anon_key="anon-key",
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={
                        AUTHORIZATION_HEADER_NAME: f"Bearer {token}",
                        ORG_ID_HEADER_NAME: "header-org-002",
                    },
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "claim-org-001"
        assert data["metadata"]["org_source"] == "claim:org_id"

    def test_bearer_without_sub_claim_returns_401_when_auth_required(self):
        registry = APIKeyRegistry()
        token = _encode_bearer_token(extra_claims={"sub": None})
        app = _make_app(
            auth_required=True,
            registry=registry,
            jwt_secret=_SUPABASE_JWT_SECRET,
            jwt_algorithm="HS256",
            supabase_url="https://supabase.test",
            supabase_anon_key="anon-key",
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={AUTHORIZATION_HEADER_NAME: f"Bearer {token}"},
                )
        assert resp.status_code == 401
        assert "detail" in resp.json()

    def test_bearer_invalid_token_returns_401_when_auth_required(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            registry=registry,
            jwt_secret=_SUPABASE_JWT_SECRET,
            jwt_algorithm="HS256",
            supabase_url="https://supabase.test",
            supabase_anon_key="anon-key",
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={AUTHORIZATION_HEADER_NAME: "Bearer invalid-token"},
                )
        assert resp.status_code == 401
        assert "detail" in resp.json()

    def test_bearer_missing_secret_returns_401_when_auth_required(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            registry=registry,
            supabase_url="https://supabase.test",
            supabase_anon_key="anon-key",
            jwt_algorithm="HS256",
        )
        missing_secret_token = _encode_bearer_token()
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={AUTHORIZATION_HEADER_NAME: f"Bearer {missing_secret_token}"},
                )
        assert resp.status_code == 401
        assert resp.json()["detail"]["error"] == "invalid_bearer_token"


class TestOrgHeaderResolution:
    def test_org_id_header_propagates_for_anonymous_context(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={ORG_ID_HEADER_NAME: _ORG_ID},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == _ORG_ID
        assert data["metadata"]["org_source"] == ORG_ID_HEADER_NAME

    def test_settings_org_id_used_when_no_header_or_record_org(self):
        registry = APIKeyRegistry()
        app = _make_app(
            auth_required=False,
            auth_configured=False,
            registry=registry,
            default_org_id="default-org-001",
        )
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/auth-context")
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "default-org-001"
        assert data["metadata"]["org_source"] == "settings"

    def test_conflicting_org_headers_return_400(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={
                        ORG_ID_HEADER_NAME: "org-a",
                        TENANT_ID_HEADER_NAME: "org-b",
                    },
                )
        assert resp.status_code == 400
        assert "Conflicting organization scope headers" in resp.json()["detail"]

    def test_same_org_value_across_alias_headers_is_accepted(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/auth-context",
                    headers={
                        ORG_ID_HEADER_NAME: _ORG_ID,
                        ORGANIZATION_ID_HEADER_NAME: _ORG_ID,
                        TENANT_ID_HEADER_NAME: _ORG_ID,
                    },
                )
        assert resp.status_code == 200
        assert resp.json()["org_id"] == _ORG_ID


class TestRequireApiKeyPassthrough:
    def test_require_api_key_returns_valid_key_unchanged(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Passthrough Key", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)

        @app.get("/probe/require-api-key-passthrough")
        async def _probe(key: str | None = Depends(require_api_key)):
            return {"key": key}

        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/require-api-key-passthrough",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                )
        assert resp.status_code == 200
        assert resp.json()["key"] == record.api_key

    def test_require_api_key_returns_none_when_auth_not_required(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)

        @app.get("/probe/require-api-key-none")
        async def _probe(key: str | None = Depends(require_api_key)):
            return {"key": key}

        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/require-api-key-none")
        assert resp.status_code == 200
        assert resp.json()["key"] is None

    def test_require_api_key_returns_none_for_valid_bearer(self):
        registry = APIKeyRegistry()
        token = _encode_bearer_token()
        app = _make_app(
            auth_required=True,
            registry=registry,
            jwt_secret=_SUPABASE_JWT_SECRET,
            jwt_algorithm="HS256",
            supabase_url="https://supabase.test",
            supabase_anon_key="anon-key",
        )

        @app.get("/probe/require-api-key-bearer")
        async def _probe(key: str | None = Depends(require_api_key)):
            return {"key": key}

        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/require-api-key-bearer",
                    headers={AUTHORIZATION_HEADER_NAME: f"Bearer {token}"},
                )
        assert resp.status_code == 200
        assert resp.json()["key"] is None


class TestRequireAuthContext:
    def test_unauthenticated_raises_401(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/require-auth")
        assert resp.status_code == 401

    def test_unauthenticated_detail_is_authentication_required(self):
        registry = APIKeyRegistry()
        app = _make_app(auth_required=False, auth_configured=False, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/probe/require-auth")
        assert resp.json().get("detail") == "Authentication required"

    def test_authenticated_context_passes_through(self):
        registry = APIKeyRegistry()
        record = registry.create_key("Auth Key", key_type="personal")
        app = _make_app(auth_required=True, registry=registry)
        with patch("app.core.auth.get_api_key_registry", return_value=registry):
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get(
                    "/probe/require-auth",
                    headers={API_KEY_HEADER_NAME: record.api_key},
                )
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_unauthenticated_anonymous_context_raises_401(self):
        ctx = AuthContext(
            api_key=None,
            principal_type="anonymous",
            principal_id=None,
            session_id=None,
            org_id=None,
            permissions=(),
            roles=(),
            authenticated=False,
            auth_source="disabled",
            auth_method=None,
            key_type="personal",
        )
        with pytest.raises(HTTPException) as exc_info:
            require_auth_context(context=ctx)
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authentication required"

    def test_preflight_context_passes_through(self):
        ctx = AuthContext(
            api_key=None,
            principal_type="preflight",
            principal_id=None,
            session_id=None,
            org_id=None,
            permissions=(),
            roles=(),
            authenticated=False,
            auth_source="preflight",
            auth_method=None,
            key_type="personal",
        )
        assert require_auth_context(context=ctx) is ctx


class TestApiKeyAuthDependency:
    def test_returns_authenticated_context_from_canonical_auth(self):
        app = _make_app(auth_required=True, registry=APIKeyRegistry())

        async def _override() -> AuthContext:
            return _bearer_context()

        app.dependency_overrides[get_auth_context] = _override

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/probe/api-key-auth")

        app.dependency_overrides.clear()

        assert resp.status_code == 200
        body = resp.json()
        assert body["authenticated"] is True
        assert body["principal_type"] == "customer"
        assert body["auth_source"] == "supabase_jwt"
        assert body["principal_id"] == _BEARER_PRINCIPAL_ID

    def test_missing_auth_returns_normalized_401_payload(self):
        app = _make_app(
            auth_required=True,
            auth_configured=True,
            configured_key=_CONFIGURED_KEY,
            registry=APIKeyRegistry(),
        )
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/probe/api-key-auth")

        assert resp.status_code == 401
        body = resp.json()
        assert body["detail"] == "Missing API key — provide X-API-Key or Bearer token"
        assert "www-authenticate" not in resp.headers

    def test_bearer_failure_from_canonical_auth_is_not_rewritten(self):
        app = _make_app(auth_required=True, registry=APIKeyRegistry())

        async def _override() -> AuthContext:
            raise AppError(
                error="invalid_api_key",
                message="Invalid bearer token",
                status_code=401,
                details={"header": "Authorization"},
            )

        app.dependency_overrides[get_auth_context] = _override

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get(
                "/probe/api-key-auth",
                headers={AUTHORIZATION_HEADER_NAME: "Bearer invalid-token"},
            )

        app.dependency_overrides.clear()

        assert resp.status_code == 401
        body = resp.json()
        assert body["error"] == "invalid_api_key"
        assert body["message"] == "Invalid bearer token"
        assert body["details"] == {"header": "Authorization"}

    @pytest.mark.asyncio
    async def test_require_api_key_auth_returns_authenticated_context(self):
        auth = _bearer_context()
        ctx = await require_api_key_auth(auth=auth)
        assert ctx is auth

    @pytest.mark.asyncio
    async def test_require_api_key_auth_rejects_install_key_context(self):
        auth = AuthContext(
            api_key="ic_install_openclaw_secret_value_123",
            principal_type="customer",
            principal_id="customer-123",
            session_id=None,
            org_id=None,
            permissions=("customer:read",),
            roles=("customer",),
            authenticated=True,
            auth_source="install_key",
            auth_method="install_key",
            key_type="personal",
            metadata={"key_kind": "install_key"},
        )

        with pytest.raises(HTTPException) as exc_info:
            await require_api_key_auth(auth=auth)

        exc = exc_info.value
        assert exc.status_code == 401
        assert "install key" in exc.detail.lower()
        assert "paid customer install-key registry" in exc.detail.lower()

    @pytest.mark.asyncio
    async def test_require_api_key_auth_rejects_install_key_shaped_api_value(self):
        auth = AuthContext(
            api_key="ic_install_claude_code_secret_value_123",
            principal_type="customer",
            principal_id="customer-456",
            session_id=None,
            org_id=None,
            permissions=("customer:read",),
            roles=("customer",),
            authenticated=True,
            auth_source="registry",
            auth_method="registry_api_key",
            key_type="personal",
            metadata={"key_kind": "customer"},
        )

        with pytest.raises(HTTPException) as exc_info:
            await require_api_key_auth(auth=auth)

        exc = exc_info.value
        assert exc.status_code == 401
        assert "install key" in exc.detail.lower()

    @pytest.mark.asyncio
    async def test_require_api_key_auth_raises_401_for_anonymous(self):
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key_auth(auth=_anonymous_context())
        exc = exc_info.value
        assert exc.status_code == 401
        assert exc.detail == "Missing API key — provide X-API-Key or Bearer token"
        assert exc.headers == {"WWW-Authenticate": "Bearer"}


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
        record = _make_personal_record()
        record_no_type = replace(record, key_type="")
        assert _coerce_key_type(record_no_type) == "personal"


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
        fake_request = SimpleNamespace(
            headers={},
            app=SimpleNamespace(state=SimpleNamespace()),
        )
        with patch("app.core.auth._get_settings", return_value=None):
            resolved = _coerce_org_id(fake_request, None, None, None, record)
        assert resolved == (_ORG_ID, "api_key_record")

    def test_org_id_resolves_from_header(self):
        fake_request = SimpleNamespace(
            headers={ORG_ID_HEADER_NAME: _ORG_ID},
            app=SimpleNamespace(state=SimpleNamespace()),
        )
        with patch("app.core.auth._get_settings", return_value=None):
            resolved = _coerce_org_id(fake_request, None, None, None, None)
        assert resolved == (_ORG_ID, ORG_ID_HEADER_NAME)

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
        assert ctx.authenticated is True
        assert ctx.key_type == "org"
        assert ctx.principal_type == "org_key"
        assert ctx.org_id == _ORG_ID
        assert ctx.principal_id == "key_org_001"


class TestCoerceHelpers:
    def test_coerce_permissions_empty_when_none(self):
        assert _coerce_permissions(None) == ()

    def test_coerce_roles_empty_when_none(self):
        assert _coerce_roles(None) == ()

    def test_coerce_principal_id_none_when_none(self):
        assert _coerce_principal_id(None) is None
