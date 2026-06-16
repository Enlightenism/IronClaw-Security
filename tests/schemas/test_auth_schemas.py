from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pydantic import ValidationError
import pytest

from app.schemas.auth import (
    APIKey,
    APIKeyCreate,
    APIKeyIssuance,
    APIKeyResponse,
    AuthContext,
    Scope,
    TokenIntrospection,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REQUIRED_APIKEY_RESPONSE = dict(
    key_id="key_abc123",
    display_name="Test Key",
    key_prefix="ic_abc",
    created_at="2026-01-01T00:00:00+00:00",
)

_REQUIRED_APIKEY = dict(
    key_id="key_abc123",
    display_name="Test Key",
    masked_key="ic_abc...d3f4",
    fingerprint="aabbccdd" * 8,
    created_at="2026-01-01T00:00:00+00:00",
)


def _make_record(**overrides: Any) -> SimpleNamespace:
    """Build a minimal SimpleNamespace that mimics APIKeyRecord for from_record tests."""
    defaults = dict(
        key_id="key_001",
        display_name="Record Key",
        masked_key="ic_abc...ffff",
        fingerprint="deadbeef" * 8,
        scopes=[Scope.SCAN_READ, Scope.SCAN_WRITE],
        key_type="personal",
        org_id=None,
        owner_key="ironclaw-system",
        rate_plan="internal",
        active=True,
        created_at="2026-06-01T00:00:00+00:00",
        created_by="system",
        last_used_at=None,
        revoked_at=None,
        revoked_by=None,
        metadata={},
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Scope enum — fail-closed on unknown value
# ---------------------------------------------------------------------------


def test_scope_all_members_are_str_enum():
    for member in Scope:
        assert isinstance(member, str)
        assert isinstance(member, Scope)


def test_scope_missing_returns_none_not_raises():
    result = Scope._missing_("not:a:real:scope")
    assert result is None


def test_scope_unknown_value_raises_value_error_on_direct_call():
    with pytest.raises(ValueError):
        Scope("not:a:real:scope")


def test_scope_from_string_valid():
    assert Scope.from_string("scan:read") == Scope.SCAN_READ
    assert Scope.from_string("admin") == Scope.ADMIN
    assert Scope.from_string("system") == Scope.SYSTEM


def test_scope_from_string_invalid_raises():
    with pytest.raises(ValueError, match="Unknown scope"):
        Scope.from_string("nonexistent:scope")


def test_scope_validate_scope_list_valid():
    result = Scope.validate_scope_list(["scan:read", "scan:write", "policy:read"])
    assert result == [Scope.SCAN_READ, Scope.SCAN_WRITE, Scope.POLICY_READ]


def test_scope_validate_scope_list_invalid_raises():
    with pytest.raises(ValueError, match="Unknown scope"):
        Scope.validate_scope_list(["scan:read", "fake:scope"])


def test_scope_validate_scope_list_empty():
    assert Scope.validate_scope_list([]) == []


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("system", Scope.SYSTEM),
        ("admin", Scope.ADMIN),
        ("scan:read", Scope.SCAN_READ),
        ("scan:write", Scope.SCAN_WRITE),
        ("scan:execute", Scope.SCAN_EXECUTE),
        ("tool:read", Scope.TOOL_READ),
        ("tool:write", Scope.TOOL_WRITE),
        ("tool:execute", Scope.TOOL_EXECUTE),
        ("policy:read", Scope.POLICY_READ),
        ("policy:write", Scope.POLICY_WRITE),
        ("audit:read", Scope.AUDIT_READ),
        ("telemetry:read", Scope.TELEMETRY_READ),
        ("telemetry:write", Scope.TELEMETRY_WRITE),
        ("review:read", Scope.REVIEW_READ),
        ("review:write", Scope.REVIEW_WRITE),
        ("review:approve", Scope.REVIEW_APPROVE),
        ("trust:read", Scope.TRUST_READ),
        ("trust:write", Scope.TRUST_WRITE),
        ("threat:read", Scope.THREAT_READ),
        ("threat:write", Scope.THREAT_WRITE),
        ("webhook:read", Scope.WEBHOOK_READ),
        ("webhook:write", Scope.WEBHOOK_WRITE),
        ("ioc:read", Scope.IOC_READ),
        ("ioc:write", Scope.IOC_WRITE),
        ("keys:read", Scope.KEYS_READ),
        ("keys:write", Scope.KEYS_WRITE),
        ("keys:rotate", Scope.KEYS_ROTATE),
        ("org:read", Scope.ORG_READ),
        ("org:write", Scope.ORG_WRITE),
    ],
)
def test_scope_round_trip(raw: str, expected: Scope):
    assert Scope(raw) == expected
    assert expected.value == raw


# ---------------------------------------------------------------------------
# APIKeyCreate — validation contract
# ---------------------------------------------------------------------------


def test_apikeycreate_minimal_valid():
    obj = APIKeyCreate(display_name="My Key")
    assert obj.display_name == "My Key"
    assert obj.key_type == "personal"
    assert obj.org_id is None


def test_apikeycreate_default_scopes_is_system():
    obj = APIKeyCreate(display_name="Key")
    assert Scope.SYSTEM in obj.scopes


def test_apikeycreate_display_name_required():
    with pytest.raises(ValidationError):
        APIKeyCreate()


def test_apikeycreate_display_name_empty_rejected():
    with pytest.raises(ValidationError):
        APIKeyCreate(display_name="")


def test_apikeycreate_display_name_too_long_rejected():
    with pytest.raises(ValidationError):
        APIKeyCreate(display_name="x" * 129)


def test_apikeycreate_org_key_without_org_id_rejected():
    with pytest.raises(ValidationError, match="org_id is required"):
        APIKeyCreate(display_name="OrgKey", key_type="org", org_id=None)


def test_apikeycreate_org_key_with_org_id_accepted():
    obj = APIKeyCreate(display_name="OrgKey", key_type="org", org_id="org-001")
    assert obj.org_id == "org-001"


def test_apikeycreate_personal_key_without_org_id_accepted():
    obj = APIKeyCreate(display_name="PersonalKey", key_type="personal", org_id=None)
    assert obj.key_type == "personal"
    assert obj.org_id is None


def test_apikeycreate_invalid_key_type_rejected():
    with pytest.raises(ValidationError):
        APIKeyCreate(display_name="Bad Type", key_type="admin")


def test_apikeycreate_scopes_from_string_coerced():
    obj = APIKeyCreate(display_name="Key", scopes="scan:read")
    assert Scope.SCAN_READ in obj.scopes


def test_apikeycreate_scopes_from_list_of_strings():
    obj = APIKeyCreate(display_name="Key", scopes=["scan:read", "policy:write"])
    assert Scope.SCAN_READ in obj.scopes
    assert Scope.POLICY_WRITE in obj.scopes


def test_apikeycreate_scopes_none_defaults_to_system():
    obj = APIKeyCreate(display_name="Key", scopes=None)
    assert Scope.SYSTEM in obj.scopes


def test_apikeycreate_full_construction():
    obj = APIKeyCreate(
        display_name="Full Key",
        scopes=[Scope.SCAN_READ, Scope.AUDIT_READ],
        key_type="org",
        org_id="org-999",
        rate_plan="enterprise",
        owner_key="svc-agent",
        created_by="admin-user",
        metadata={"env": "prod"},
    )
    assert obj.rate_plan == "enterprise"
    assert obj.owner_key == "svc-agent"
    assert obj.created_by == "admin-user"
    assert obj.metadata["env"] == "prod"


def test_apikeycreate_whitespace_stripped_from_display_name():
    obj = APIKeyCreate(display_name="  Key  ")
    assert obj.display_name == "Key"


# ---------------------------------------------------------------------------
# APIKey (internal read model)
# ---------------------------------------------------------------------------


def test_apikey_minimal_valid():
    obj = APIKey(**_REQUIRED_APIKEY)
    assert obj.key_id == "key_abc123"
    assert obj.active is True


def test_apikey_scopes_coerced_from_strings():
    obj = APIKey(**{**_REQUIRED_APIKEY, "scopes": ["scan:read", "admin"]})
    assert Scope.SCAN_READ in obj.scopes
    assert Scope.ADMIN in obj.scopes


def test_apikey_scopes_invalid_values_not_raised_stored_as_is():
    # coercion logic appends the raw item on ValueError; schema layer tolerates it
    obj = APIKey(**{**_REQUIRED_APIKEY, "scopes": ["scan:read", "invalid:scope"]})
    # SCAN_READ should be coerced; invalid:scope should remain a raw string
    assert any(s == Scope.SCAN_READ for s in obj.scopes)


def test_apikey_scopes_none_or_empty_defaults_empty():
    obj = APIKey(**{**_REQUIRED_APIKEY, "scopes": None})
    assert obj.scopes == []


def test_apikey_optional_timestamps_default_none():
    obj = APIKey(**_REQUIRED_APIKEY)
    assert obj.last_used_at is None
    assert obj.revoked_at is None
    assert obj.revoked_by is None


def test_apikey_active_defaults_true():
    obj = APIKey(**_REQUIRED_APIKEY)
    assert obj.active is True


def test_apikey_metadata_defaults_empty():
    obj = APIKey(**_REQUIRED_APIKEY)
    assert obj.metadata == {}


# ---------------------------------------------------------------------------
# APIKeyResponse — from_record() never exposes raw key; key_prefix derivation
# ---------------------------------------------------------------------------


def test_apikeyresponse_from_record_basic():
    rec = _make_record()
    resp = APIKeyResponse.from_record(rec)
    assert resp.key_id == "key_001"
    assert resp.display_name == "Record Key"


def test_apikeyresponse_from_record_no_raw_key():
    rec = _make_record()
    resp = APIKeyResponse.from_record(rec)
    assert not hasattr(resp, "raw_key")
    # key_prefix must never be the full masked_key or full key
    assert "..." not in resp.key_prefix


def test_apikeyresponse_from_record_key_prefix_from_masked_key_with_ellipsis():
    rec = _make_record(masked_key="ic_xyz...a1b2")
    resp = APIKeyResponse.from_record(rec)
    assert resp.key_prefix == "ic_xyz"


def test_apikeyresponse_from_record_key_prefix_fallback_six_chars():
    rec = _make_record(masked_key="ic_noe")  # no "..." present
    resp = APIKeyResponse.from_record(rec)
    assert resp.key_prefix == "ic_noe"


def test_apikeyresponse_from_record_key_prefix_empty_masked_key():
    rec = _make_record(masked_key="")
    resp = APIKeyResponse.from_record(rec)
    assert resp.key_prefix == ""


def test_apikeyresponse_from_record_scopes_coerced():
    rec = _make_record(scopes=[Scope.SCAN_READ, "policy:write"])
    resp = APIKeyResponse.from_record(rec)
    assert Scope.SCAN_READ in resp.scopes
    assert Scope.POLICY_WRITE in resp.scopes


def test_apikeyresponse_from_record_unknown_scope_dropped():
    rec = _make_record(scopes=["scan:read", "garbage:scope"])
    resp = APIKeyResponse.from_record(rec)
    assert Scope.SCAN_READ in resp.scopes
    assert all(s != "garbage:scope" for s in resp.scopes)


def test_apikeyresponse_from_record_timestamps_preserved():
    rec = _make_record(
        created_at="2026-01-01T00:00:00+00:00",
        last_used_at="2026-06-01T12:00:00+00:00",
        revoked_at=None,
        revoked_by=None,
    )
    resp = APIKeyResponse.from_record(rec)
    assert resp.created_at == "2026-01-01T00:00:00+00:00"
    assert resp.last_used_at == "2026-06-01T12:00:00+00:00"
    assert resp.revoked_at is None


def test_apikeyresponse_from_record_revoked_fields_preserved():
    rec = _make_record(
        active=False,
        revoked_at="2026-06-10T08:00:00+00:00",
        revoked_by="admin-007",
    )
    resp = APIKeyResponse.from_record(rec)
    assert resp.revoked_at == "2026-06-10T08:00:00+00:00"
    assert resp.revoked_by == "admin-007"
    assert resp.active is False


def test_apikeyresponse_from_record_metadata_copied():
    rec = _make_record(metadata={"env": "staging", "team": "security"})
    resp = APIKeyResponse.from_record(rec)
    assert resp.metadata["env"] == "staging"
    assert resp.metadata["team"] == "security"


def test_apikeyresponse_from_record_org_fields_preserved():
    rec = _make_record(key_type="org", org_id="org-42")
    resp = APIKeyResponse.from_record(rec)
    assert resp.key_type == "org"
    assert resp.org_id == "org-42"


def test_apikeyresponse_direct_construction_valid():
    resp = APIKeyResponse(**_REQUIRED_APIKEY_RESPONSE)
    assert resp.key_id == "key_abc123"
    assert resp.key_prefix == "ic_abc"


def test_apikeyresponse_missing_key_prefix_rejected():
    data = {k: v for k, v in _REQUIRED_APIKEY_RESPONSE.items() if k != "key_prefix"}
    with pytest.raises(ValidationError):
        APIKeyResponse(**data)


def test_apikeyresponse_missing_created_at_rejected():
    data = {k: v for k, v in _REQUIRED_APIKEY_RESPONSE.items() if k != "created_at"}
    with pytest.raises(ValidationError):
        APIKeyResponse(**data)


# ---------------------------------------------------------------------------
# APIKeyIssuance — raw_key present; nested APIKeyResponse has no raw key
# ---------------------------------------------------------------------------


def test_apikeyissuance_carries_raw_key():
    resp = APIKeyResponse(**_REQUIRED_APIKEY_RESPONSE)
    issuance = APIKeyIssuance(raw_key="ic_supersecretvalue", key=resp)
    assert issuance.raw_key == "ic_supersecretvalue"


def test_apikeyissuance_nested_key_response_has_no_raw_key():
    resp = APIKeyResponse(**_REQUIRED_APIKEY_RESPONSE)
    issuance = APIKeyIssuance(raw_key="ic_supersecretvalue", key=resp)
    assert not hasattr(issuance.key, "raw_key")


def test_apikeyissuance_nested_response_shape_correct():
    resp = APIKeyResponse(**_REQUIRED_APIKEY_RESPONSE)
    issuance = APIKeyIssuance(raw_key="ic_supersecretvalue", key=resp)
    assert issuance.key.key_id == "key_abc123"
    assert issuance.key.key_prefix == "ic_abc"


def test_apikeyissuance_missing_raw_key_rejected():
    resp = APIKeyResponse(**_REQUIRED_APIKEY_RESPONSE)
    with pytest.raises(ValidationError):
        APIKeyIssuance(key=resp)


def test_apikeyissuance_missing_key_rejected():
    with pytest.raises(ValidationError):
        APIKeyIssuance(raw_key="ic_supersecretvalue")


# ---------------------------------------------------------------------------
# AuthContext.from_core() — round-trips all fields from a core dataclass mock
# ---------------------------------------------------------------------------

_CORE_CTX = SimpleNamespace(
    api_key="ic_abc...1234",
    principal_type="api_key",
    principal_id="principal-001",
    session_id="sess-xyz",
    org_id="org-001",
    permissions=[Scope.SCAN_READ.value, Scope.ADMIN.value],
    roles=["scanner", "admin"],
    authenticated=True,
    auth_source="registry",
    auth_method="header",
    key_type="personal",
    metadata={"env": "prod"},
)


def test_authcontext_from_core_api_key():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.api_key == "ic_abc...1234"


def test_authcontext_from_core_principal_type():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.principal_type == "api_key"


def test_authcontext_from_core_principal_id():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.principal_id == "principal-001"


def test_authcontext_from_core_session_id():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.session_id == "sess-xyz"


def test_authcontext_from_core_org_id():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.org_id == "org-001"


def test_authcontext_from_core_permissions_round_trip():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert Scope.SCAN_READ.value in ctx.permissions
    assert Scope.ADMIN.value in ctx.permissions


def test_authcontext_from_core_roles_round_trip():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert "scanner" in ctx.roles
    assert "admin" in ctx.roles


def test_authcontext_from_core_authenticated():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.authenticated is True


def test_authcontext_from_core_auth_source():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.auth_source == "registry"


def test_authcontext_from_core_auth_method():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.auth_method == "header"


def test_authcontext_from_core_key_type():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.key_type == "personal"


def test_authcontext_from_core_metadata():
    ctx = AuthContext.from_core(_CORE_CTX)
    assert ctx.metadata["env"] == "prod"


def test_authcontext_from_core_missing_attrs_default_gracefully():
    bare = SimpleNamespace()
    ctx = AuthContext.from_core(bare)
    assert ctx.api_key is None
    assert ctx.principal_type == "api_key"
    assert ctx.permissions == []
    assert ctx.roles == []
    assert ctx.authenticated is False
    assert ctx.auth_source == "none"


# ---------------------------------------------------------------------------
# AuthContext.has_scope / has_any_scope / has_all_scopes / is_admin
# ---------------------------------------------------------------------------

_SCOPE_CTX = AuthContext(
    authenticated=True,
    permissions=[Scope.SCAN_READ.value, Scope.POLICY_READ.value, Scope.AUDIT_READ.value],
)


def test_authcontext_has_scope_present():
    assert _SCOPE_CTX.has_scope(Scope.SCAN_READ) is True


def test_authcontext_has_scope_absent():
    assert _SCOPE_CTX.has_scope(Scope.SCAN_WRITE) is False


def test_authcontext_has_any_scope_one_match():
    assert _SCOPE_CTX.has_any_scope(Scope.SCAN_WRITE, Scope.SCAN_READ) is True


def test_authcontext_has_any_scope_no_match():
    assert _SCOPE_CTX.has_any_scope(Scope.SCAN_WRITE, Scope.TOOL_WRITE) is False


def test_authcontext_has_any_scope_all_absent():
    assert _SCOPE_CTX.has_any_scope(Scope.ADMIN, Scope.SYSTEM) is False


def test_authcontext_has_all_scopes_all_present():
    assert _SCOPE_CTX.has_all_scopes(Scope.SCAN_READ, Scope.POLICY_READ) is True


def test_authcontext_has_all_scopes_one_missing():
    assert _SCOPE_CTX.has_all_scopes(Scope.SCAN_READ, Scope.SCAN_WRITE) is False


def test_authcontext_has_all_scopes_none_present():
    assert _SCOPE_CTX.has_all_scopes(Scope.ADMIN, Scope.SYSTEM) is False


def test_authcontext_is_admin_via_admin_scope():
    ctx = AuthContext(authenticated=True, permissions=[Scope.ADMIN.value])
    assert ctx.is_admin() is True


def test_authcontext_is_admin_via_system_scope():
    ctx = AuthContext(authenticated=True, permissions=[Scope.SYSTEM.value])
    assert ctx.is_admin() is True


def test_authcontext_is_admin_false_without_admin_or_system():
    ctx = AuthContext(authenticated=True, permissions=[Scope.SCAN_READ.value])
    assert ctx.is_admin() is False


def test_authcontext_is_admin_false_empty_permissions():
    ctx = AuthContext(authenticated=True, permissions=[])
    assert ctx.is_admin() is False


def test_authcontext_defaults():
    ctx = AuthContext()
    assert ctx.authenticated is False
    assert ctx.api_key is None
    assert ctx.permissions == []
    assert ctx.roles == []
    assert ctx.auth_source == "none"
    assert ctx.principal_type == "api_key"
    assert ctx.key_type == "personal"
    assert ctx.metadata == {}


# ---------------------------------------------------------------------------
# TokenIntrospection.inactive() — active=False, no other fields populated
# ---------------------------------------------------------------------------


def test_token_introspection_inactive_active_false():
    ti = TokenIntrospection.inactive()
    assert ti.active is False


def test_token_introspection_inactive_key_id_none():
    ti = TokenIntrospection.inactive()
    assert ti.key_id is None


def test_token_introspection_inactive_key_prefix_none():
    ti = TokenIntrospection.inactive()
    assert ti.key_prefix is None


def test_token_introspection_inactive_scopes_empty():
    ti = TokenIntrospection.inactive()
    assert ti.scopes == []


def test_token_introspection_inactive_optional_fields_none():
    ti = TokenIntrospection.inactive()
    assert ti.key_type is None
    assert ti.principal_id is None
    assert ti.org_id is None
    assert ti.owner_key is None
    assert ti.rate_plan is None
    assert ti.issued_at is None
    assert ti.last_used_at is None
    assert ti.revoked_at is None


def test_token_introspection_inactive_metadata_empty():
    ti = TokenIntrospection.inactive()
    assert ti.metadata == {}


# ---------------------------------------------------------------------------
# TokenIntrospection.from_record() — revoked branch
# ---------------------------------------------------------------------------


def test_token_introspection_from_record_none_returns_inactive():
    ti = TokenIntrospection.from_record(None)
    assert ti.active is False
    assert ti.key_id is None


def test_token_introspection_from_record_revoked_returns_active_false():
    rec = _make_record(active=False, revoked_at="2026-06-10T08:00:00+00:00")
    ti = TokenIntrospection.from_record(rec)
    assert ti.active is False


def test_token_introspection_from_record_revoked_preserves_key_id():
    rec = _make_record(active=False, revoked_at="2026-06-10T08:00:00+00:00")
    ti = TokenIntrospection.from_record(rec)
    assert ti.key_id == "key_001"


def test_token_introspection_from_record_revoked_preserves_revoked_at():
    rec = _make_record(active=False, revoked_at="2026-06-10T08:00:00+00:00")
    ti = TokenIntrospection.from_record(rec)
    assert ti.revoked_at == "2026-06-10T08:00:00+00:00"


def test_token_introspection_from_record_revoked_has_no_scopes():
    rec = _make_record(active=False, revoked_at="2026-06-10T08:00:00+00:00")
    ti = TokenIntrospection.from_record(rec)
    assert ti.scopes == []


def test_token_introspection_from_record_revoked_has_no_prefix():
    rec = _make_record(active=False, revoked_at="2026-06-10T08:00:00+00:00")
    ti = TokenIntrospection.from_record(rec)
    assert ti.key_prefix is None


# ---------------------------------------------------------------------------
# TokenIntrospection.from_record() — active branch (fully populated)
# ---------------------------------------------------------------------------


def test_token_introspection_from_record_active_is_true():
    rec = _make_record()
    ti = TokenIntrospection.from_record(rec)
    assert ti.active is True


def test_token_introspection_from_record_active_key_id():
    rec = _make_record()
    ti = TokenIntrospection.from_record(rec)
    assert ti.key_id == "key_001"


def test_token_introspection_from_record_active_key_prefix_derived():
    rec = _make_record(masked_key="ic_abc...ffff")
    ti = TokenIntrospection.from_record(rec)
    assert ti.key_prefix == "ic_abc"


def test_token_introspection_from_record_active_key_prefix_no_ellipsis():
    rec = _make_record(masked_key="ic_xyz1")
    ti = TokenIntrospection.from_record(rec)
    assert "..." not in (ti.key_prefix or "")


def test_token_introspection_from_record_active_scopes_coerced():
    rec = _make_record(scopes=[Scope.SCAN_READ, Scope.POLICY_READ])
    ti = TokenIntrospection.from_record(rec)
    assert Scope.SCAN_READ in ti.scopes
    assert Scope.POLICY_READ in ti.scopes


def test_token_introspection_from_record_active_unknown_scope_dropped():
    rec = _make_record(scopes=["scan:read", "garbage:scope"])
    ti = TokenIntrospection.from_record(rec)
    assert Scope.SCAN_READ in ti.scopes
    assert all(s != "garbage:scope" for s in ti.scopes)


def test_token_introspection_from_record_active_key_type():
    rec = _make_record(key_type="org", org_id="org-777")
    ti = TokenIntrospection.from_record(rec)
    assert ti.key_type == "org"
    assert ti.org_id == "org-777"


def test_token_introspection_from_record_active_principal_id_matches_key_id():
    rec = _make_record(key_id="key_principal_001")
    ti = TokenIntrospection.from_record(rec)
    assert ti.principal_id == "key_principal_001"


def test_token_introspection_from_record_active_owner_key():
    rec = _make_record(owner_key="svc-ironclaw")
    ti = TokenIntrospection.from_record(rec)
    assert ti.owner_key == "svc-ironclaw"


def test_token_introspection_from_record_active_rate_plan():
    rec = _make_record(rate_plan="enterprise")
    ti = TokenIntrospection.from_record(rec)
    assert ti.rate_plan == "enterprise"


def test_token_introspection_from_record_active_issued_at():
    rec = _make_record(created_at="2026-01-15T00:00:00+00:00")
    ti = TokenIntrospection.from_record(rec)
    assert ti.issued_at == "2026-01-15T00:00:00+00:00"


def test_token_introspection_from_record_active_last_used_at():
    rec = _make_record(last_used_at="2026-06-15T10:00:00+00:00")
    ti = TokenIntrospection.from_record(rec)
    assert ti.last_used_at == "2026-06-15T10:00:00+00:00"


def test_token_introspection_from_record_active_revoked_at_none():
    rec = _make_record()
    ti = TokenIntrospection.from_record(rec)
    assert ti.revoked_at is None


def test_token_introspection_from_record_active_metadata_copied():
    rec = _make_record(metadata={"origin": "cli", "version": "2"})
    ti = TokenIntrospection.from_record(rec)
    assert ti.metadata["origin"] == "cli"
    assert ti.metadata["version"] == "2"


def test_token_introspection_from_record_active_empty_masked_key():
    rec = _make_record(masked_key="")
    ti = TokenIntrospection.from_record(rec)
    assert ti.key_prefix is None


def test_token_introspection_active_direct_construction():
    ti = TokenIntrospection(active=True, key_id="key_001")
    assert ti.active is True
    assert ti.key_id == "key_001"


def test_token_introspection_missing_active_rejected():
    with pytest.raises(ValidationError):
        TokenIntrospection()
