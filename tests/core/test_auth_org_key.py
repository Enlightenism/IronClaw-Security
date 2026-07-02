from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("AUTH_REQUIRED", "false")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from unittest.mock import MagicMock

import pytest

import app.core.apikeys as _apikeys_module
from app.core.apikeys import (
    APIKeyRecord,
    APIKeyRegistry,
    create_org_key,
    fingerprint_api_key,
)
from app.core.auth import (
    get_auth_context,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_registry():
    """Replace the module-level APIKeyRegistry singleton for each test."""
    fresh_registry = APIKeyRegistry()
    original = _apikeys_module._registry
    _apikeys_module._registry = fresh_registry
    yield fresh_registry
    _apikeys_module._registry = original


@pytest.fixture()
def org_id() -> str:
    return "acme-corp"


@pytest.fixture()
def org_key_record(org_id: str, _isolated_registry: APIKeyRegistry) -> APIKeyRecord:
    """Register a fresh org key in the isolated registry and return the record."""
    return _isolated_registry.create_key(
        "Acme Org Key",
        key_type="org",
        org_id=org_id,
        prefix="ic_org_",
        owner_key=f"ic_org_{org_id}",
        scopes=("system",),
    )


@pytest.fixture()
def personal_key_record(_isolated_registry: APIKeyRegistry) -> APIKeyRecord:
    """Register a personal (non-org) key in the isolated registry and return the record."""
    return _isolated_registry.create_key(
        "Personal Dev Key",
        key_type="personal",
        org_id=None,
        owner_key="user@ironclaw.test",
        scopes=("system",),
    )


def _make_request(api_key: str) -> MagicMock:
    """Build a minimal mock Request that auth.py can interrogate."""
    request = MagicMock()
    # settings: auth_required=False so missing keys don't 401 during resolution
    settings = MagicMock()
    settings.auth_required = False
    settings.ironclaw_api_key = None
    settings.internal_platform_api_key = None
    settings.platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None
    settings.secret_key = None
    settings.jwt_secret = None
    settings.org_id = None
    settings.organization_id = None
    settings.default_org_id = None
    request.app.state.settings = settings
    request.headers = {"X-API-Key": api_key}
    return request


# ---------------------------------------------------------------------------
# create_org_key — module-level factory
# ---------------------------------------------------------------------------


def test_create_org_key_returns_record_with_key_type_org(org_id: str) -> None:
    record = create_org_key(org_id, "Test Org Key")
    assert record.key_type == "org"


def test_create_org_key_sets_org_id_auth_org_key(org_id: str) -> None:
    record = create_org_key(org_id, "Test Org Key")
    assert record.org_id == org_id


def test_create_org_key_api_key_uses_ic_org_prefix(org_id: str) -> None:
    record = create_org_key(org_id, "Test Org Key")
    assert record.api_key.startswith("ic_org_")


def test_create_org_key_is_active_by_default(org_id: str) -> None:
    record = create_org_key(org_id, "Test Org Key")
    assert record.active is True


def test_create_org_key_fingerprint_is_deterministic(org_id: str) -> None:
    record = create_org_key(org_id, "Test Org Key")
    expected_fp = fingerprint_api_key(record.api_key)
    assert record.fingerprint == expected_fp


# ---------------------------------------------------------------------------
# get_auth_context — org key resolves to key_type="org"
# ---------------------------------------------------------------------------


def test_org_key_auth_context_key_type_is_org(
    org_key_record: APIKeyRecord,
    org_id: str,
) -> None:
    request = _make_request(org_key_record.api_key)
    ctx = get_auth_context(request, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.key_type == "org"


def test_org_key_auth_context_principal_type_is_org_key(
    org_key_record: APIKeyRecord,
    org_id: str,
) -> None:
    request = _make_request(org_key_record.api_key)
    ctx = get_auth_context(request, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.principal_type == "org_key"


def test_org_key_auth_context_org_id_matches_registered_org(
    org_key_record: APIKeyRecord,
    org_id: str,
) -> None:
    request = _make_request(org_key_record.api_key)
    ctx = get_auth_context(request, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.org_id == org_id


def test_org_key_auth_context_authenticated_is_true(
    org_key_record: APIKeyRecord,
) -> None:
    request = _make_request(org_key_record.api_key)
    ctx = get_auth_context(request, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.authenticated is True


def test_org_key_auth_context_auth_source_is_registry(
    org_key_record: APIKeyRecord,
) -> None:
    request = _make_request(org_key_record.api_key)
    ctx = get_auth_context(request, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.auth_source == "registry"


def test_org_key_auth_context_principal_id_equals_key_id(
    org_key_record: APIKeyRecord,
) -> None:
    request = _make_request(org_key_record.api_key)
    ctx = get_auth_context(request, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.principal_id == org_key_record.key_id


# ---------------------------------------------------------------------------
# Two different callers using the same org key resolve to the same org_id
# ---------------------------------------------------------------------------


def test_two_callers_same_org_key_resolve_same_org_id(
    org_key_record: APIKeyRecord,
    org_id: str,
) -> None:
    """Simulates two team members independently calling get_auth_context with the same org key."""
    request_member_a = _make_request(org_key_record.api_key)
    ctx_a = get_auth_context(
        request_member_a,
        api_key=org_key_record.api_key,
        session_id=None,
        provided_org_id=None,
    )

    request_member_b = _make_request(org_key_record.api_key)
    ctx_b = get_auth_context(
        request_member_b,
        api_key=org_key_record.api_key,
        session_id=None,
        provided_org_id=None,
    )

    assert ctx_a.org_id == ctx_b.org_id == org_id


def test_two_callers_same_org_key_resolve_same_key_type(
    org_key_record: APIKeyRecord,
) -> None:
    request_member_a = _make_request(org_key_record.api_key)
    ctx_a = get_auth_context(
        request_member_a,
        api_key=org_key_record.api_key,
        session_id=None,
        provided_org_id=None,
    )

    request_member_b = _make_request(org_key_record.api_key)
    ctx_b = get_auth_context(
        request_member_b,
        api_key=org_key_record.api_key,
        session_id=None,
        provided_org_id=None,
    )

    assert ctx_a.key_type == ctx_b.key_type == "org"
    assert ctx_a.principal_type == ctx_b.principal_type == "org_key"


def test_two_callers_same_org_key_resolve_same_principal_id(
    org_key_record: APIKeyRecord,
) -> None:
    request_member_a = _make_request(org_key_record.api_key)
    ctx_a = get_auth_context(
        request_member_a,
        api_key=org_key_record.api_key,
        session_id=None,
        provided_org_id=None,
    )

    request_member_b = _make_request(org_key_record.api_key)
    ctx_b = get_auth_context(
        request_member_b,
        api_key=org_key_record.api_key,
        session_id=None,
        provided_org_id=None,
    )

    assert ctx_a.principal_id == ctx_b.principal_id == org_key_record.key_id


# ---------------------------------------------------------------------------
# Personal key — get_auth_context resolves correctly
# ---------------------------------------------------------------------------


def test_personal_key_auth_context_key_type_is_personal(
    personal_key_record: APIKeyRecord,
) -> None:
    request = _make_request(personal_key_record.api_key)
    ctx = get_auth_context(request, api_key=personal_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.key_type == "personal"


def test_personal_key_auth_context_principal_type_is_api_key(
    personal_key_record: APIKeyRecord,
) -> None:
    request = _make_request(personal_key_record.api_key)
    ctx = get_auth_context(request, api_key=personal_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.principal_type == "api_key"


def test_personal_key_auth_context_org_id_is_none(
    personal_key_record: APIKeyRecord,
) -> None:
    request = _make_request(personal_key_record.api_key)
    ctx = get_auth_context(request, api_key=personal_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.org_id is None


def test_personal_key_auth_context_authenticated_is_true(
    personal_key_record: APIKeyRecord,
) -> None:
    request = _make_request(personal_key_record.api_key)
    ctx = get_auth_context(request, api_key=personal_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.authenticated is True


def test_personal_key_auth_context_principal_type_not_org_key(
    personal_key_record: APIKeyRecord,
) -> None:
    request = _make_request(personal_key_record.api_key)
    ctx = get_auth_context(request, api_key=personal_key_record.api_key, session_id=None, provided_org_id=None)
    assert ctx.principal_type != "org_key"


# ---------------------------------------------------------------------------
# Org key vs personal key — isolation across two concurrent registry entries
# ---------------------------------------------------------------------------


def test_org_and_personal_key_produce_different_principal_types(
    org_key_record: APIKeyRecord,
    personal_key_record: APIKeyRecord,
    org_id: str,
) -> None:
    req_org = _make_request(org_key_record.api_key)
    ctx_org = get_auth_context(req_org, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)

    req_personal = _make_request(personal_key_record.api_key)
    ctx_personal = get_auth_context(req_personal, api_key=personal_key_record.api_key, session_id=None, provided_org_id=None)

    assert ctx_org.principal_type == "org_key"
    assert ctx_personal.principal_type == "api_key"
    assert ctx_org.key_type == "org"
    assert ctx_personal.key_type == "personal"
    assert ctx_org.org_id == org_id
    assert ctx_personal.org_id is None


def test_org_and_personal_key_produce_different_key_types(
    org_key_record: APIKeyRecord,
    personal_key_record: APIKeyRecord,
) -> None:
    req_org = _make_request(org_key_record.api_key)
    ctx_org = get_auth_context(req_org, api_key=org_key_record.api_key, session_id=None, provided_org_id=None)

    req_personal = _make_request(personal_key_record.api_key)
    ctx_personal = get_auth_context(req_personal, api_key=personal_key_record.api_key, session_id=None, provided_org_id=None)

    assert ctx_org.key_type != ctx_personal.key_type


# ---------------------------------------------------------------------------
# Revoked org key — auth context authentication behavior
# ---------------------------------------------------------------------------


def test_revoked_org_key_is_not_resolved_by_registry(
    org_key_record: APIKeyRecord,
    _isolated_registry: APIKeyRegistry,
) -> None:
    _isolated_registry.revoke_key(org_key_record.key_id)
    resolved = _isolated_registry.get_by_fingerprint(fingerprint_api_key(org_key_record.api_key))
    assert resolved is not None
    assert resolved.active is False


def test_revoked_org_key_record_active_is_false(
    org_key_record: APIKeyRecord,
    _isolated_registry: APIKeyRegistry,
) -> None:
    revoked = _isolated_registry.revoke_key(org_key_record.key_id)
    assert revoked is not None
    assert revoked.active is False
    assert revoked.revoked_at is not None


# ---------------------------------------------------------------------------
# Multiple org keys for different orgs — complete isolation
# ---------------------------------------------------------------------------


def test_two_org_keys_for_different_orgs_produce_different_org_ids(
    _isolated_registry: APIKeyRegistry,
) -> None:
    record_alpha = _isolated_registry.create_key(
        "Alpha Org Key",
        key_type="org",
        org_id="alpha-corp",
        prefix="ic_org_",
        owner_key="ic_org_alpha-corp",
    )
    record_beta = _isolated_registry.create_key(
        "Beta Org Key",
        key_type="org",
        org_id="beta-corp",
        prefix="ic_org_",
        owner_key="ic_org_beta-corp",
    )

    req_alpha = _make_request(record_alpha.api_key)
    ctx_alpha = get_auth_context(req_alpha, api_key=record_alpha.api_key, session_id=None, provided_org_id=None)

    req_beta = _make_request(record_beta.api_key)
    ctx_beta = get_auth_context(req_beta, api_key=record_beta.api_key, session_id=None, provided_org_id=None)

    assert ctx_alpha.org_id == "alpha-corp"
    assert ctx_beta.org_id == "beta-corp"
    assert ctx_alpha.org_id != ctx_beta.org_id
    assert ctx_alpha.principal_type == "org_key"
    assert ctx_beta.principal_type == "org_key"


def test_two_org_keys_for_different_orgs_produce_different_principal_ids(
    _isolated_registry: APIKeyRegistry,
) -> None:
    record_alpha = _isolated_registry.create_key(
        "Alpha Org Key",
        key_type="org",
        org_id="alpha-corp",
        prefix="ic_org_",
        owner_key="ic_org_alpha-corp",
    )
    record_beta = _isolated_registry.create_key(
        "Beta Org Key",
        key_type="org",
        org_id="beta-corp",
        prefix="ic_org_",
        owner_key="ic_org_beta-corp",
    )

    req_alpha = _make_request(record_alpha.api_key)
    ctx_alpha = get_auth_context(req_alpha, api_key=record_alpha.api_key, session_id=None, provided_org_id=None)

    req_beta = _make_request(record_beta.api_key)
    ctx_beta = get_auth_context(req_beta, api_key=record_beta.api_key, session_id=None, provided_org_id=None)

    assert ctx_alpha.principal_id != ctx_beta.principal_id
