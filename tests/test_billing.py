from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from contextlib import contextmanager

from fastapi.testclient import TestClient
import pytest

from app.api.routes.billing import PACKAGE_CATALOG
from app.core.auth import (
    AuthContext,
    get_api_key,
    get_auth_context,
    require_api_key,
    require_auth_context,
)
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import TOKEN_CHUNK_SIZE, UnitWalletRegistry
from app.main import app as _app

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}


# ---------------------------------------------------------------------------
# Auth context factories
# ---------------------------------------------------------------------------


def _make_personal_ctx(email: str = "test@ironclaw.test") -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="api_key",
        principal_id=None,
        session_id=None,
        org_id=None,
        authenticated=True,
        auth_source="registry",
        auth_method="api_key",
        key_type="personal",
    )


def _make_personal_ctx_with_id(email: str) -> AuthContext:
    """Personal ctx with a set principal_id — used only for cross-wallet 403 tests."""
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="api_key",
        principal_id=email,
        session_id=None,
        org_id=None,
        authenticated=True,
        auth_source="registry",
        auth_method="api_key",
        key_type="personal",
    )


def _make_org_ctx(org_id: str) -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="org_key",
        principal_id=f"ic_org_{org_id}",
        session_id=None,
        org_id=org_id,
        authenticated=True,
        auth_source="registry",
        auth_method="api_key",
        key_type="org",
    )


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


def _fresh_registry() -> UnitWalletRegistry:
    """Install and return a fresh registry on the module global."""
    fresh = UnitWalletRegistry()
    _unit_wallet_module._unit_wallet_registry = fresh
    return fresh


def _seed_wallet(registry: UnitWalletRegistry, owner_key: str, units: int = 500) -> None:
    registry.credit_units(owner_key=owner_key, units=units)


# ---------------------------------------------------------------------------
# Auth override context manager
# ---------------------------------------------------------------------------


@contextmanager
def _override_auth(ctx: AuthContext):
    """
    Override auth dependencies on the shared _app and install a fresh
    wallet registry so isolation tests never share state.
    """
    registry = _fresh_registry()

    def _stub_api_key() -> str:
        return ctx.api_key or _MOCK_API_KEY

    def _stub_auth_ctx() -> AuthContext:
        return ctx

    _app.dependency_overrides[get_api_key] = _stub_api_key
    _app.dependency_overrides[get_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_api_key] = _stub_api_key
    try:
        yield TestClient(_app, raise_server_exceptions=False), registry
    finally:
        _app.dependency_overrides.pop(get_api_key, None)
        _app.dependency_overrides.pop(get_auth_context, None)
        _app.dependency_overrides.pop(require_auth_context, None)
        _app.dependency_overrides.pop(require_api_key, None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_wallet_registry():
    """Guarantee a clean registry before AND after every test."""
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()
    yield
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()


@pytest.fixture()
def client(_reset_wallet_registry):
    ctx = _make_personal_ctx()

    def _stub_api_key() -> str:
        return _MOCK_API_KEY

    def _stub_auth_ctx() -> AuthContext:
        return ctx

    _app.dependency_overrides[require_api_key] = _stub_api_key
    _app.dependency_overrides[get_api_key] = _stub_api_key
    _app.dependency_overrides[get_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_auth_context] = _stub_auth_ctx
    with TestClient(_app, raise_server_exceptions=False) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c
    _app.dependency_overrides.pop(require_api_key, None)
    _app.dependency_overrides.pop(get_api_key, None)
    _app.dependency_overrides.pop(get_auth_context, None)
    _app.dependency_overrides.pop(require_auth_context, None)


# ---------------------------------------------------------------------------
# GET /billing/packages
# ---------------------------------------------------------------------------


def test_packages_returns_exactly_three_packages(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert len(body["packages"]) == 3


def test_packages_catalog_ids_match_package_catalog(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    returned_ids = {p["package_id"] for p in resp.json()["packages"]}
    assert returned_ids == set(PACKAGE_CATALOG.keys())


def test_packages_unit_policy_present(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    body = resp.json()
    assert "unit_policy" in body
    assert body["unit_policy"]["token_chunk_size"] == TOKEN_CHUNK_SIZE


def test_packages_token_coverage_computed_correctly(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    for pkg in resp.json()["packages"]:
        assert pkg["token_coverage"] == pkg["included_units"] * TOKEN_CHUNK_SIZE
        assert pkg["tokens_per_unit"] == TOKEN_CHUNK_SIZE


def test_packages_no_auth_header_returns_401() -> None:
    _app.dependency_overrides.clear()
    with TestClient(_app, raise_server_exceptions=False) as c:
        resp = c.get("/billing/packages")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/purchase  (canonical route)
# ---------------------------------------------------------------------------
# NOTE: /billing/packages/purchase is NOT a valid route.
# The router registers POST /billing/purchase — never /billing/packages/purchase.
# Any test that hits /billing/packages/purchase correctly expects 404/405.
# ---------------------------------------------------------------------------


def test_purchase_old_path_returns_404_or_405(client: TestClient) -> None:
    """Guard: the stale /billing/packages/purchase path must never resolve."""
    payload = {
        "package_id": "pkg_5000",
        "buyer_name": "Ghost",
        "buyer_email": "ghost@ironclaw.test",
    }
    resp = client.post("/billing/packages/purchase", json=payload)
    assert resp.status_code in (404, 405)


def test_purchase_starter_package_credits_wallet(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_5000",
        "buyer_name": "Test User",
        "buyer_email": "test@ironclaw.test",
    }
    resp = client.post("/billing/purchase", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "ok"
    assert body["purchase"]["granted_units"] == 5_000
    assert body["wallet"]["balance_units"] == 5_000


def test_purchase_team_package_credits_wallet(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_25000",
        "buyer_name": "Team User",
        "buyer_email": "team@ironclaw.test",
    }
    resp = client.post("/billing/purchase", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["granted_units"] == 25_000
    assert body["wallet"]["balance_units"] == 25_000


def test_purchase_enterprise_package_credits_wallet(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_60000",
        "buyer_name": "Ent User",
        "buyer_email": "ent@ironclaw.test",
    }
    resp = client.post("/billing/purchase", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["granted_units"] == 60_000
    assert body["wallet"]["balance_units"] == 60_000


def test_purchase_unknown_package_returns_404(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_invalid",
        "buyer_name": "X",
        "buyer_email": "x@x.test",
    }
    resp = client.post("/billing/purchase", json=payload)
    assert resp.status_code == 404


def test_purchase_missing_required_fields_returns_422(client: TestClient) -> None:
    resp = client.post("/billing/purchase", json={"package_id": "pkg_5000"})
    assert resp.status_code == 422


def test_purchase_no_auth_returns_401() -> None:
    _app.dependency_overrides.clear()
    with TestClient(_app, raise_server_exceptions=False) as c:
        resp = c.post(
            "/billing/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "No Auth",
                "buyer_email": "noauth@ironclaw.test",
            },
        )
    assert resp.status_code == 401


def test_purchase_org_key_pools_to_org_wallet() -> None:
    ctx = _make_org_ctx("org-abc")
    with _override_auth(ctx) as (c, _registry):
        payload = {
            "package_id": "pkg_5000",
            "buyer_name": "Org User",
            "buyer_email": "orguser@ironclaw.test",
        }
        resp = c.post("/billing/purchase", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["owner_key"] == "ic_org_org-abc"
    assert body["wallet"]["owner_key"] == "ic_org_org-abc"


def test_purchase_response_token_coverage_correct(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_5000",
        "buyer_name": "TC User",
        "buyer_email": "tc@ironclaw.test",
    }
    resp = client.post("/billing/purchase", json=payload)
    assert resp.status_code == 201
    purchase = resp.json()["purchase"]
    assert purchase["token_coverage"] == 5_000 * TOKEN_CHUNK_SIZE
    assert purchase["tokens_per_unit"] == TOKEN_CHUNK_SIZE


def test_purchase_idempotent_double_purchase_accumulates(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_5000",
        "buyer_name": "Double User",
        "buyer_email": "double@ironclaw.test",
    }
    client.post("/billing/purchase", json=payload)
    resp = client.post("/billing/purchase", json=payload)
    assert resp.status_code == 201
    assert resp.json()["wallet"]["balance_units"] == 10_000


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}
# ---------------------------------------------------------------------------


def test_get_wallet_balance_returns_200(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "test@ironclaw.test", 100)
    resp = client.get("/billing/wallet/test@ironclaw.test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["wallet"]["owner_key"] == "test@ironclaw.test"
    assert body["wallet"]["balance_units"] == 100


def test_get_wallet_returns_404_for_unknown_owner(client: TestClient) -> None:
    resp = client.get("/billing/wallet/nobody@ironclaw.test")
    assert resp.status_code == 404


def test_get_wallet_requires_auth_context() -> None:
    _app.dependency_overrides.clear()
    with TestClient(_app, raise_server_exceptions=False) as c:
        resp = c.get("/billing/wallet/test@ironclaw.test")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit
# ---------------------------------------------------------------------------


def test_debit_by_units_reduces_balance(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "debit@ironclaw.test", 200)
    resp = client.post(
        "/billing/wallet/debit@ironclaw.test/debit",
        json={"units": 50},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["units_debited"] == 50
    assert body["wallet"]["balance_units"] == 150


def test_debit_by_token_count_uses_ceiling_division(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "tokens@ironclaw.test", 200)
    resp = client.post(
        "/billing/wallet/tokens@ironclaw.test/debit",
        json={"token_count": 25_001},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["units_debited"] == 2
    assert body["wallet"]["balance_units"] == 198


def test_debit_exact_chunk_boundary_uses_one_unit(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "boundary@ironclaw.test", 10)
    resp = client.post(
        "/billing/wallet/boundary@ironclaw.test/debit",
        json={"token_count": TOKEN_CHUNK_SIZE},
    )
    assert resp.status_code == 200
    assert resp.json()["units_debited"] == 1


def test_debit_insufficient_units_returns_402(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "broke@ironclaw.test", 1)
    resp = client.post(
        "/billing/wallet/broke@ironclaw.test/debit",
        json={"units": 100},
    )
    assert resp.status_code == 402
    detail = resp.json()["detail"]
    assert detail["status"] == "insufficient_units"
    assert detail["have"] == 1
    assert detail["need"] == 100


def test_debit_missing_units_and_token_count_returns_422(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "miss@ironclaw.test", 10)
    resp = client.post(
        "/billing/wallet/miss@ironclaw.test/debit",
        json={"reason": "test"},
    )
    assert resp.status_code == 422


def test_debit_requires_auth_context() -> None:
    _app.dependency_overrides.clear()
    with TestClient(_app, raise_server_exceptions=False) as c:
        resp = c.post(
            "/billing/wallet/test@ironclaw.test/debit",
            json={"units": 1},
        )
    assert resp.status_code == 401


def test_debit_zero_units_rejected(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "zero@ironclaw.test", 50)
    resp = client.post(
        "/billing/wallet/zero@ironclaw.test/debit",
        json={"units": 0},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund
# ---------------------------------------------------------------------------


def test_refund_increases_balance(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "refund@ironclaw.test", 100)
    resp = client.post(
        "/billing/wallet/refund@ironclaw.test/refund",
        json={"units": 25},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["units_refunded"] == 25
    assert body["wallet"]["balance_units"] == 125
    assert body["wallet"]["total_refunded_units"] == 25


def test_refund_zero_units_rejected_by_schema(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "rzero@ironclaw.test", 50)
    resp = client.post(
        "/billing/wallet/rzero@ironclaw.test/refund",
        json={"units": 0},
    )
    assert resp.status_code == 422


def test_refund_requires_auth_context() -> None:
    _app.dependency_overrides.clear()
    with TestClient(_app, raise_server_exceptions=False) as c:
        resp = c.post(
            "/billing/wallet/test@ironclaw.test/refund",
            json={"units": 10},
        )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}/ledger
# ---------------------------------------------------------------------------


def test_ledger_returns_entries_after_credit(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    _seed_wallet(registry, "ledger@ironclaw.test", 50)
    resp = client.get("/billing/wallet/ledger@ironclaw.test/ledger")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert len(body["entries"]) >= 1


def test_ledger_limit_param_respected(client: TestClient) -> None:
    registry = _unit_wallet_module._unit_wallet_registry
    for _ in range(5):
        _seed_wallet(registry, "lim@ironclaw.test", 10)
    resp = client.get("/billing/wallet/lim@ironclaw.test/ledger?limit=2")
    assert resp.status_code == 200
    assert len(resp.json()["entries"]) <= 2


def test_ledger_requires_auth_context() -> None:
    _app.dependency_overrides.clear()
    with TestClient(_app, raise_server_exceptions=False) as c:
        resp = c.get("/billing/wallet/test@ironclaw.test/ledger")
    assert resp.status_code == 401


def test_ledger_empty_for_new_wallet_after_purchase(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_5000",
        "buyer_name": "Ledger User",
        "buyer_email": "ledgeruser@ironclaw.test",
    }
    client.post("/billing/purchase", json=payload)
    resp = client.get("/billing/wallet/ledgeruser@ironclaw.test/ledger")
    assert resp.status_code == 200
    assert len(resp.json()["entries"]) >= 1


# ---------------------------------------------------------------------------
# Org isolation — _assert_owner_access 403 paths
# ---------------------------------------------------------------------------


def test_org_debit_wrong_org_key_returns_403() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="ic_org_org-beta", units=500)
        resp = c.post(
            "/billing/wallet/ic_org_org-beta/debit",
            json={"units": 10},
        )
    assert resp.status_code == 403


def test_org_refund_wrong_org_key_returns_403() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="ic_org_org-beta", units=500)
        resp = c.post(
            "/billing/wallet/ic_org_org-beta/refund",
            json={"units": 10},
        )
    assert resp.status_code == 403


def test_org_wallet_read_wrong_org_key_returns_403() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, _registry):
        resp = c.get("/billing/wallet/ic_org_org-beta")
    assert resp.status_code == 403


def test_org_ledger_wrong_org_key_returns_403() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="ic_org_org-beta", units=100)
        resp = c.get("/billing/wallet/ic_org_org-beta/ledger")
    assert resp.status_code == 403


def test_org_debit_correct_org_key_succeeds() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="ic_org_org-alpha", units=500)
        resp = c.post(
            "/billing/wallet/ic_org_org-alpha/debit",
            json={"units": 10},
        )
    assert resp.status_code == 200
    assert resp.json()["wallet"]["balance_units"] == 490


def test_org_refund_correct_org_key_succeeds() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="ic_org_org-alpha", units=100)
        resp = c.post(
            "/billing/wallet/ic_org_org-alpha/refund",
            json={"units": 5},
        )
    assert resp.status_code == 200
    assert resp.json()["wallet"]["total_refunded_units"] == 5


def test_org_wallet_read_correct_org_key_succeeds() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="ic_org_org-alpha", units=50)
        resp = c.get("/billing/wallet/ic_org_org-alpha")
    assert resp.status_code == 200
    assert resp.json()["wallet"]["owner_key"] == "ic_org_org-alpha"


def test_org_ledger_correct_org_key_succeeds() -> None:
    ctx = _make_org_ctx("org-alpha")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="ic_org_org-alpha", units=100)
        resp = c.get("/billing/wallet/ic_org_org-alpha/ledger")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_personal_key_debit_own_wallet_succeeds() -> None:
    ctx = _make_personal_ctx_with_id("test@ironclaw.test")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="test@ironclaw.test", units=200)
        resp = c.post(
            "/billing/wallet/test@ironclaw.test/debit",
            json={"units": 50},
        )
    assert resp.status_code == 200


def test_personal_key_blocked_from_other_personal_wallet() -> None:
    ctx = _make_personal_ctx_with_id("owner-a@ironclaw.test")
    with _override_auth(ctx) as (c, registry):
        registry.credit_units(owner_key="owner-b@ironclaw.test", units=100)
        resp = c.post(
            "/billing/wallet/owner-b@ironclaw.test/debit",
            json={"units": 10},
        )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# units_required_for_tokens — boundary coverage
# ---------------------------------------------------------------------------


def test_units_required_for_tokens_exact_boundary() -> None:
    from app.core.unit_wallet import units_required_for_tokens

    assert units_required_for_tokens(TOKEN_CHUNK_SIZE) == 1
    assert units_required_for_tokens(TOKEN_CHUNK_SIZE + 1) == 2
    assert units_required_for_tokens(TOKEN_CHUNK_SIZE * 2) == 2
    assert units_required_for_tokens(TOKEN_CHUNK_SIZE * 2 + 1) == 3
    assert units_required_for_tokens(0) == 0
    assert units_required_for_tokens(-1) == 0
