import types

from fastapi import HTTPException
import jwt
import pytest
from starlette.requests import Request

from app.core import auth
from app.core.errors import AppError

_MISSING_SUPABASE_JWT_SECRET_DETAIL = "SUPABASE_JWT_SECRET is not configured; configure or use remote validation via SUPABASE_URL + SUPABASE_ANON_KEY"
_INVALID_BEARER_DETAIL = {
    "error": "invalid_bearer_token",
    "detail": "Invalid Bearer token — algorithm mismatch or signature failure",
    "alg_in_token": None,
    "expected_alg": "HS256",
}


class DummyRegistry:
    def __init__(
        self,
        *,
        record=None,
        total=0,
        has_keys=None,
        list_keys_data=None,
        raise_type_error_on_list_keys=False,
        expose_summary=True,
    ):
        self.record = record
        self.total = total
        self._has_keys = has_keys
        self._list_keys_data = list_keys_data
        self._raise_type_error_on_list_keys = raise_type_error_on_list_keys
        self._expose_summary = expose_summary
        self.upserted = None

    def get_by_fingerprint(self, fingerprint):
        return self.record

    def summary(self):
        if not self._expose_summary:
            raise TypeError("summary unavailable")
        return {"total": self.total}

    def has_keys(self):
        if self._has_keys is None:
            raise TypeError("has_keys not configured")
        return self._has_keys

    def list_keys(self, active_only=True):
        if self._raise_type_error_on_list_keys and active_only is True:
            raise TypeError("retry with alternate signature")
        return self._list_keys_data or []

    def upsert_record(self, record):
        self.upserted = record


class DummyRecord:
    def __init__(
        self,
        *,
        active=True,
        revoked_at=None,
        org_id=None,
        organization_id=None,
        tenant_id=None,
        key_type=None,
        kind=None,
        api_key=None,
        principal_type=None,
        permissions=None,
        scopes=None,
        allowed_actions=None,
        roles=None,
        role_names=None,
        grants=None,
        role=None,
        key_id=None,
        id=None,
        client_id=None,
        owner_id=None,
        principal_id=None,
        touched=None,
    ):
        self.active = active
        self.revoked_at = revoked_at
        self.org_id = org_id
        self.organization_id = organization_id
        self.tenant_id = tenant_id
        self.key_type = key_type
        self.kind = kind
        self.api_key = api_key
        self.principal_type = principal_type
        self.permissions = permissions
        self.scopes = scopes
        self.allowed_actions = allowed_actions
        self.roles = roles
        self.role_names = role_names
        self.grants = grants
        self.role = role
        self.key_id = key_id
        self.id = id
        self.client_id = client_id
        self.owner_id = owner_id
        self.principal_id = principal_id
        self._touched = touched

    def touch(self):
        return self._touched


def make_request(
    *,
    headers=None,
    method="GET",
    settings=None,
    state=None,
):
    scope = {
        "type": "http",
        "method": method,
        "path": "/",
        "headers": [(key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in (headers or {}).items()],
        "app": types.SimpleNamespace(state=types.SimpleNamespace(settings=settings)),
    }
    request = Request(scope)
    if state:
        for key, value in state.items():
            setattr(request.state, key, value)
    return request


def test_clean_optional_string():
    assert auth._clean_optional_string(None) is None
    assert auth._clean_optional_string(123) is None
    assert auth._clean_optional_string("   ") is None
    assert auth._clean_optional_string(" value ") == "value"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("off", False),
        ("maybe", None),
        (1, None),
    ],
)
def test_coerce_optional_bool(value, expected):
    assert auth._coerce_optional_bool(value) is expected


def test_is_preflight_request_true_for_cors_options():
    request = make_request(
        method="OPTIONS",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert auth._is_preflight_request(request) is True


def test_is_preflight_request_false_for_normal_request():
    request = make_request(method="GET")
    assert auth._is_preflight_request(request) is False


def test_preflight_auth_context_shape():
    context = auth._preflight_auth_context()
    assert context.principal_type == "preflight"
    assert context.auth_source == "preflight"
    assert context.authenticated is False
    assert context.metadata == {"request_method": "OPTIONS"}


def test_extract_configured_api_key_prefers_effective_api_key():
    settings = types.SimpleNamespace(
        effective_api_key="effective-key",
        platform_api_key="platform-key",
    )
    request = make_request(settings=settings)
    assert auth._extract_configured_api_key(request) == "effective-key"


def test_extract_configured_api_key_falls_through_known_fields():
    settings = types.SimpleNamespace(platform_api_key="platform-key")
    request = make_request(settings=settings)
    assert auth._extract_configured_api_key(request) == "platform-key"


def test_extract_configured_api_key_falls_back_to_effective_platform_api_key():
    settings = types.SimpleNamespace(effective_platform_api_key="effective-platform-key")
    request = make_request(settings=settings)
    assert auth._extract_configured_api_key(request) == "effective-platform-key"


def test_get_secret_key_ignores_default_placeholder():
    settings = types.SimpleNamespace(secret_key="changeme-32-chars-minimum!!!!!")
    request = make_request(settings=settings)
    assert auth.get_secret_key(request) == "changeme-32-chars-minimum!!!!!"


def test_get_secret_key_prefers_effective_secret_key():
    settings = types.SimpleNamespace(
        effective_secret_key="secret-live",
        secret_key="ignored",
    )
    request = make_request(settings=settings)
    assert auth.get_secret_key(request) == "secret-live"


def test_get_jwt_secret_ignores_default_placeholder():
    settings = types.SimpleNamespace(jwt_secret="changeme-jwt-32-chars-minimum!!")
    request = make_request(settings=settings)
    assert auth.get_jwt_secret(request) == "changeme-jwt-32-chars-minimum!!"


def test_get_supabase_jwt_secret_prefers_effective_supabase_secret():
    settings = types.SimpleNamespace(
        effective_supabase_jwt_secret="supabase-secret",
        jwt_secret="fallback-jwt-secret",
    )
    request = make_request(settings=settings)
    assert auth.get_supabase_jwt_secret(request) == "supabase-secret"


def test_get_supabase_jwt_secret_falls_back_to_supabase_jwt_secret_field():
    settings = types.SimpleNamespace(supabase_jwt_secret="supabase-secret")
    request = make_request(settings=settings)
    assert auth.get_supabase_jwt_secret(request) == "supabase-secret"


def test_get_supabase_jwt_secret_falls_back_to_jwt_secret():
    settings = types.SimpleNamespace(jwt_secret="jwt-secret")
    request = make_request(settings=settings)
    assert auth.get_supabase_jwt_secret(request) == "jwt-secret"


def test_get_jwt_algorithm_prefers_effective_value():
    settings = types.SimpleNamespace(effective_jwt_algorithm="hs512")
    request = make_request(settings=settings)
    assert auth._get_jwt_algorithm(request) == "HS512"


def test_touch_record_if_possible_returns_original_when_touch_missing(monkeypatch):
    record = DummyRecord()
    assert auth._touch_record_if_possible(record) is record


def test_touch_record_if_possible_upserts_updated_record(monkeypatch):
    updated = DummyRecord()
    record = DummyRecord(touched=updated)
    registry = DummyRegistry()

    monkeypatch.setattr(auth, "get_api_key_registry", lambda: registry)

    assert auth._touch_record_if_possible(record) is updated
    assert registry.upserted is updated


def test_record_is_usable_checks_active_revoked_and_expiry(monkeypatch):
    monkeypatch.setattr(auth, "is_api_key_expired", lambda record: False)
    assert auth._record_is_usable(DummyRecord(active=True, revoked_at=None)) is True
    assert auth._record_is_usable(DummyRecord(active=False)) is False
    assert auth._record_is_usable(DummyRecord(active=True, revoked_at="revoked")) is False

    monkeypatch.setattr(auth, "is_api_key_expired", lambda record: True)
    assert auth._record_is_usable(DummyRecord(active=True, revoked_at=None)) is False


def test_resolve_registry_api_key_returns_touched_record(monkeypatch):
    updated = DummyRecord()
    record = DummyRecord(touched=updated)
    registry = DummyRegistry(record=record)

    monkeypatch.setattr(auth, "get_api_key_registry", lambda: registry)
    monkeypatch.setattr(auth, "fingerprint_api_key", lambda value: f"fp:{value}")
    monkeypatch.setattr(auth, "is_api_key_expired", lambda r: False)

    resolved = auth._resolve_registry_api_key("  key-123  ")

    assert resolved is updated


def test_cached_registry_record_round_trip():
    request = make_request()
    record = DummyRecord()
    auth._cache_registry_record(request, record)
    assert auth._get_cached_registry_record(request) is record


def test_resolve_registry_api_key_for_request_uses_cache(monkeypatch):
    request = make_request()
    record = DummyRecord()
    auth._cache_registry_record(request, record)

    monkeypatch.setattr(auth, "_resolve_registry_api_key", lambda _: pytest.fail("should not resolve again"))

    assert auth._resolve_registry_api_key_for_request(request, "key") is record


def test_has_registry_keys_from_summary(monkeypatch):
    registry = DummyRegistry(total=2)
    monkeypatch.setattr(auth, "get_api_key_registry", lambda: registry)
    assert auth._has_registry_keys() is True


def test_has_registry_keys_from_has_keys_method(monkeypatch):
    registry = DummyRegistry(total=0, has_keys=True, expose_summary=False)
    monkeypatch.setattr(auth, "get_api_key_registry", lambda: registry)
    assert auth._has_registry_keys() is True


def test_has_registry_keys_from_list_keys_retry(monkeypatch):
    registry = DummyRegistry(
        total=0,
        has_keys=None,
        list_keys_data=["k1"],
        raise_type_error_on_list_keys=True,
        expose_summary=False,
    )
    monkeypatch.setattr(auth, "get_api_key_registry", lambda: registry)
    assert auth._has_registry_keys() is True


def test_has_bearer_auth_config_uses_supabase_secret(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "get_supabase_jwt_secret", lambda req: "secret")
    assert auth._has_bearer_auth_config(request) is True


def test_is_auth_required_false_for_preflight():
    request = make_request(
        method="OPTIONS",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert auth._is_auth_required(request) is False


def test_is_auth_required_uses_effective_flag():
    settings = types.SimpleNamespace(effective_auth_required="true")
    request = make_request(settings=settings)
    assert auth._is_auth_required(request) is True


def test_is_auth_required_uses_auth_required_flag():
    settings = types.SimpleNamespace(auth_required="false")
    request = make_request(settings=settings)
    assert auth._is_auth_required(request) is False


def test_is_auth_required_uses_auth_configured_flag():
    settings = types.SimpleNamespace(auth_configured="true")
    request = make_request(settings=settings)
    assert auth._is_auth_required(request) is True


def test_is_auth_required_true_when_configured_api_key_present():
    settings = types.SimpleNamespace(platform_api_key="platform-key")
    request = make_request(settings=settings)
    assert auth._is_auth_required(request) is True


def test_is_auth_required_true_when_bearer_auth_config_present():
    settings = types.SimpleNamespace(supabase_jwt_secret="secret")
    request = make_request(settings=settings)
    assert auth._is_auth_required(request) is True


def test_constant_time_match():
    assert auth._constant_time_match("a", "a") is True
    assert auth._constant_time_match("a", "b") is False
    assert auth._constant_time_match(None, "a") is False


def test_coerce_roles_permissions_and_principal_id():
    record = DummyRecord(
        roles=["admin", " analyst "],
        permissions=["read", " write "],
        key_id="key-1",
    )
    assert auth._coerce_roles(record) == ("admin", "analyst")
    assert auth._coerce_permissions(record) == ("read", "write")
    assert auth._coerce_principal_id(record) == "key-1"


def test_extract_header_org_candidates_detects_conflicts():
    request = make_request(headers={"X-Org-Id": "org-1", "X-Tenant-Id": "org-2"})

    with pytest.raises(HTTPException) as exc:
        auth._extract_header_org_candidates(request, None, None, None)

    assert exc.value.status_code == 400
    assert "Conflicting organization scope headers provided" in exc.value.detail


def test_extract_header_org_candidates_returns_first_clean_value():
    request = make_request()
    value, source = auth._extract_header_org_candidates(request, "  org-1  ", None, None)
    assert value == "org-1"
    assert source == auth.ORG_ID_HEADER_NAME


def test_coerce_org_id_from_record_and_settings():
    record = DummyRecord(org_id="org-record")
    assert auth._coerce_org_id_from_record(record) == "org-record"

    settings = types.SimpleNamespace(default_org_id="org-settings")
    request = make_request(settings=settings)
    assert auth._coerce_org_id_from_settings(request) == "org-settings"


def test_coerce_org_id_prefers_header_then_record_then_settings():
    record = DummyRecord(org_id="org-record")
    settings = types.SimpleNamespace(default_org_id="org-settings")
    request = make_request(settings=settings, headers={"X-Org-Id": "org-header"})

    assert auth._coerce_org_id(request, None, None, None, record) == ("org-header", auth.ORG_ID_HEADER_NAME)

    request_without_header = make_request(settings=settings)
    assert auth._coerce_org_id(request_without_header, None, None, None, record) == ("org-record", "api_key_record")
    assert auth._coerce_org_id(request_without_header, None, None, None, None) == ("org-settings", "settings")


def test_coerce_key_type_and_registry_principal_type():
    org_record = DummyRecord(key_type="organization", org_id="org-1")
    personal_record = DummyRecord(api_key="ic_user_123")

    assert auth._coerce_key_type(org_record) == "org"
    assert auth._coerce_key_type(personal_record) == "personal"
    assert auth._resolve_registry_principal_type(org_record) == "org_key"
    assert auth._resolve_registry_principal_type(DummyRecord(principal_type="platform")) == "platform"


def test_extract_bearer_token():
    assert auth._extract_bearer_token(None) is None
    assert auth._extract_bearer_token("Token abc") is None
    assert auth._extract_bearer_token("Bearer abc.def") == "abc.def"


def test_clean_claim_strings_and_extract_claim_values():
    claims = {"roles": ["admin", " admin ", "user"], "role": "user"}
    assert auth._clean_claim_strings(" admin ") == ("admin",)
    assert auth._clean_claim_strings(["a", " ", "b"]) == ("a", "b")
    assert auth._extract_claim_values(claims, "roles", "role") == ("admin", "user")


def test_resolve_bearer_org_id_prefers_claims_then_metadata_then_headers():
    request = make_request(headers={"X-Org-Id": "org-header"})
    claims = {"org_id": "org-claim"}
    assert auth._resolve_bearer_org_id(request, claims, None, None, None) == ("org-claim", "claim:org_id")

    claims = {"user_metadata": {"org_id": "org-user-meta"}}
    assert auth._resolve_bearer_org_id(request, claims, None, None, None) == ("org-user-meta", "user_metadata:org_id")

    claims = {"app_metadata": {"org_id": "org-app-meta"}}
    assert auth._resolve_bearer_org_id(request, claims, None, None, None) == ("org-app-meta", "app_metadata:org_id")

    claims = {}
    assert auth._resolve_bearer_org_id(request, claims, None, None, None) == ("org-header", auth.ORG_ID_HEADER_NAME)


def test_resolve_bearer_roles_permissions_and_principal_type():
    claims = {
        "roles": ["customer_admin"],
        "permissions": ["customer:write"],
        "principal_type": "customer",
    }
    assert auth._resolve_bearer_roles(claims) == ("customer_admin",)
    assert auth._resolve_bearer_permissions(claims) == ("customer:write",)
    assert auth._resolve_bearer_principal_type(claims) == "customer"

    fallback_claims = {}
    assert auth._resolve_bearer_roles(fallback_claims) == ("customer_user",)
    assert auth._resolve_bearer_permissions(fallback_claims) == ("customer:read",)
    assert auth._resolve_bearer_principal_type(fallback_claims) == "customer"


def test_get_bearer_context_returns_none_without_bearer_token():
    request = make_request()
    assert auth.get_bearer_context(request, None) is None


def test_get_bearer_context_raises_503_when_secret_missing_and_auth_required(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "get_supabase_jwt_secret", lambda req: None)

    with pytest.raises(HTTPException) as exc:
        auth.get_bearer_context(request, "Bearer token")

    assert exc.value.status_code == 503
    assert exc.value.detail == _MISSING_SUPABASE_JWT_SECRET_DETAIL


def test_get_bearer_context_ignores_missing_secret_when_auth_disabled(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: False)
    monkeypatch.setattr(auth, "get_supabase_jwt_secret", lambda req: None)

    assert auth.get_bearer_context(request, "Bearer token") is None


def test_get_bearer_context_raises_401_for_invalid_token_when_auth_required(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "get_supabase_jwt_secret", lambda req: "secret")
    monkeypatch.setattr(auth, "_get_jwt_algorithm", lambda req: "HS256")

    def fake_decode(*args, **kwargs):
        raise jwt.PyJWTError("bad token")

    monkeypatch.setattr(auth.jwt, "decode", fake_decode)

    with pytest.raises(HTTPException) as exc:
        auth.get_bearer_context(request, "Bearer token")

    assert exc.value.status_code == 401
    assert exc.value.detail == _INVALID_BEARER_DETAIL


def test_get_bearer_context_raises_401_when_sub_missing_and_auth_required(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "get_supabase_jwt_secret", lambda req: "secret")
    monkeypatch.setattr(auth, "_get_jwt_algorithm", lambda req: "HS256")
    monkeypatch.setattr(auth.jwt, "decode", lambda *args, **kwargs: {"email": "a@example.com"})

    with pytest.raises(HTTPException) as exc:
        auth.get_bearer_context(request, "Bearer token")

    assert exc.value.status_code == 401
    assert exc.value.detail == "Bearer token missing sub claim"


def test_get_bearer_context_returns_context_for_valid_token(monkeypatch):
    request = make_request()
    claims = {"sub": "user-123", "email": "user@example.com"}

    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "get_supabase_jwt_secret", lambda req: "secret")
    monkeypatch.setattr(auth, "_get_jwt_algorithm", lambda req: "HS256")
    monkeypatch.setattr(auth.jwt, "decode", lambda *args, **kwargs: claims)

    context = auth.get_bearer_context(request, "Bearer token-123")

    assert context is not None
    assert context.token == "token-123"
    assert context.principal_id == "user-123"
    assert context.claims == claims


def test_get_api_key_returns_none_when_bearer_context_present():
    request = make_request()
    bearer_context = auth.BearerAuthContext(token="t", principal_id="p", claims={})
    assert auth.get_api_key(request, None, bearer_context) is None


def test_get_api_key_raises_when_missing_and_auth_required(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)

    with pytest.raises(HTTPException) as exc:
        auth.get_api_key(request, None, None)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Missing API key — provide X-API-Key or Bearer token"


def test_get_api_key_accepts_configured_api_key(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "_extract_configured_api_key", lambda req: "key-123")

    assert auth.get_api_key(request, " key-123 ", None) == "key-123"


def test_get_api_key_accepts_registry_api_key(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "_extract_configured_api_key", lambda req: None)
    monkeypatch.setattr(auth, "_resolve_registry_api_key_for_request", lambda req, key: DummyRecord())

    assert auth.get_api_key(request, "registry-key", None) == "registry-key"


def test_get_api_key_passthrough_when_auth_disabled(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: False)
    monkeypatch.setattr(auth, "_extract_configured_api_key", lambda req: None)
    monkeypatch.setattr(auth, "_resolve_registry_api_key_for_request", lambda req, key: None)

    assert auth.get_api_key(request, "unknown-key", None) == "unknown-key"


def test_get_api_key_raises_auth_not_configured(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "_extract_configured_api_key", lambda req: None)
    monkeypatch.setattr(auth, "_resolve_registry_api_key_for_request", lambda req, key: None)
    monkeypatch.setattr(auth, "_has_registry_keys", lambda: False)

    with pytest.raises(AppError) as exc:
        auth.get_api_key(request, "bad-key", None)

    assert "Authentication is required but no API keys are configured" in str(exc.value)


def test_get_api_key_raises_invalid_api_key(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)
    monkeypatch.setattr(auth, "_extract_configured_api_key", lambda req: "configured-key")
    monkeypatch.setattr(auth, "_resolve_registry_api_key_for_request", lambda req, key: None)
    monkeypatch.setattr(auth, "_has_registry_keys", lambda: True)

    with pytest.raises(AppError) as exc:
        auth.get_api_key(request, "bad-key", None)

    assert "Invalid API key" in str(exc.value)


def test_get_auth_context_returns_preflight_context():
    request = make_request(
        method="OPTIONS",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    context = auth.get_auth_context(request, None, None, None, None, None, None)
    assert context.principal_type == "preflight"


def test_get_auth_context_from_api_key_registry_record(monkeypatch):
    request = make_request(headers={"X-Org-Id": "org-header"})
    record = DummyRecord(
        key_type="organization",
        org_id="org-record",
        permissions=["customer:read"],
        roles=["platform_admin"],
        key_id="key-123",
    )

    monkeypatch.setattr(auth, "_resolve_registry_api_key_for_request", lambda req, key: record)
    monkeypatch.setattr(auth, "_extract_configured_api_key", lambda req: None)

    context = auth.get_auth_context(
        request,
        "registry-key",
        None,
        "session-1",
        None,
        None,
        None,
    )

    assert context.api_key == "registry-key"
    assert context.principal_type == "org_key"
    assert context.principal_id == "key-123"
    assert context.session_id == "session-1"
    assert context.org_id == "org-header"
    assert context.permissions == ("customer:read",)
    assert context.roles == ("platform_admin",)
    assert context.authenticated is True
    assert context.auth_source == "registry"
    assert context.auth_method == "registry_api_key"
    assert context.key_type == "org"
    assert context.metadata["header"] == auth.API_KEY_HEADER_NAME
    assert context.metadata["org_source"] == auth.ORG_ID_HEADER_NAME


def test_get_auth_context_from_configured_api_key(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_resolve_registry_api_key_for_request", lambda req, key: None)
    monkeypatch.setattr(auth, "_extract_configured_api_key", lambda req: "configured-key")
    monkeypatch.setattr(auth, "_coerce_org_id", lambda *args, **kwargs: ("org-settings", "settings"))

    context = auth.get_auth_context(
        request,
        "configured-key",
        None,
        None,
        None,
        None,
        None,
    )

    assert context.principal_type == "platform"
    assert context.auth_source == "configured"
    assert context.auth_method == "api_key"
    assert context.org_id == "org-settings"


def test_get_auth_context_from_bearer_context(monkeypatch):
    request = make_request()
    bearer_context = auth.BearerAuthContext(
        token="token",
        principal_id="user-123",
        claims={
            "email": "user@example.com",
            "role": "customer_admin",
            "aal": "aal1",
            "iss": "issuer",
            "org_id": "org-123",
            "roles": ["customer_admin"],
            "permissions": ["customer:write"],
            "principal_type": "customer",
        },
    )

    context = auth.get_auth_context(
        request,
        None,
        bearer_context,
        "session-9",
        None,
        None,
        None,
    )

    assert context.api_key is None
    assert context.principal_type == "customer"
    assert context.principal_id == "user-123"
    assert context.session_id == "session-9"
    assert context.org_id == "org-123"
    assert context.permissions == ("customer:write",)
    assert context.roles == ("customer_admin",)
    assert context.authenticated is True
    assert context.auth_source == "supabase_jwt"
    assert context.auth_method == "bearer_jwt"
    assert context.metadata["header"] == auth.AUTHORIZATION_HEADER_NAME
    assert context.metadata["email"] == "user@example.com"
    assert context.metadata["role"] == "customer_admin"
    assert context.metadata["aal"] == "aal1"
    assert context.metadata["iss"] == "issuer"
    assert context.metadata["org_source"] == "claim:org_id"


def test_get_auth_context_raises_when_auth_required(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: True)

    with pytest.raises(HTTPException) as exc:
        auth.get_auth_context(request, None, None, None, None, None, None)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Missing API key — provide X-API-Key or Bearer token"


def test_get_auth_context_returns_anonymous_when_auth_disabled(monkeypatch):
    request = make_request()
    monkeypatch.setattr(auth, "_is_auth_required", lambda req: False)
    monkeypatch.setattr(auth, "_coerce_org_id", lambda *args, **kwargs: ("org-public", "settings"))

    context = auth.get_auth_context(request, None, None, None, None, None, None)

    assert context.principal_type == "anonymous"
    assert context.org_id == "org-public"
    assert context.authenticated is False
    assert context.auth_source == "disabled"
    assert context.metadata == {"org_source": "settings"}


def test_require_api_key_returns_api_key_for_normal_requests():
    request = make_request()
    assert auth.require_api_key(request, "key-123") == "key-123"


def test_require_api_key_returns_none_for_preflight():
    request = make_request(
        method="OPTIONS",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert auth.require_api_key(request, "key-123") is None


def test_require_auth_context_allows_preflight():
    context = auth.AuthContext(
        api_key=None,
        principal_type="preflight",
        principal_id=None,
        session_id=None,
        org_id=None,
        authenticated=False,
    )
    assert auth.require_auth_context(context) is context


def test_require_auth_context_raises_for_unauthenticated():
    context = auth.AuthContext(
        api_key=None,
        principal_type="anonymous",
        principal_id=None,
        session_id=None,
        org_id=None,
        authenticated=False,
    )

    with pytest.raises(HTTPException) as exc:
        auth.require_auth_context(context)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Authentication required"


def test_require_auth_context_returns_authenticated_context():
    context = auth.AuthContext(
        api_key="key",
        principal_type="platform",
        principal_id="p1",
        session_id=None,
        org_id="org-1",
        authenticated=True,
    )
    assert auth.require_auth_context(context) is context


def test_get_current_organization_id_prefers_context_org_id():
    context = auth.AuthContext(
        api_key=None,
        principal_type="platform",
        principal_id=None,
        session_id=None,
        org_id="org-123",
        authenticated=True,
    )
    assert auth.get_current_organization_id(context) == "org-123"


def test_get_current_organization_id_falls_back_to_default():
    context = auth.AuthContext(
        api_key=None,
        principal_type="platform",
        principal_id=None,
        session_id=None,
        org_id=None,
        authenticated=True,
    )
    assert auth.get_current_organization_id(context) == "default"
