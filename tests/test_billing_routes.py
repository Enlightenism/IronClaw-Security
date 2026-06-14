from __future__ import annotations

import concurrent.futures
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.billing import router as billing_router
from app.core.auth import (
    AuthContext,
    require_auth_context,
)
from app.core.unit_wallet import (
    UNIT_PACKAGE_CATALOG,
    get_unit_wallet_registry,
)

# ---------------------------------------------------------------------------
# Expected package IDs (sourced from UNIT_PACKAGE_CATALOG — no hardcoding)
# ---------------------------------------------------------------------------

_PKG_5K = "pkg_5000"
_PKG_25K = "pkg_25000"
_PKG_60K = "pkg_60000"
_ALL_PKG_IDS = {_PKG_5K, _PKG_25K, _PKG_60K}

assert _ALL_PKG_IDS <= set(UNIT_PACKAGE_CATALOG.keys()), f"UNIT_PACKAGE_CATALOG is missing expected packages: " f"{_ALL_PKG_IDS - set(UNIT_PACKAGE_CATALOG.keys())}"

# ---------------------------------------------------------------------------
# App factory helpers
# ---------------------------------------------------------------------------

_PERSONAL_API_KEY = "test-personal-key"
_ORG_API_KEY = "test-org-key"
_ORG_ID = "testorg001"
_ORG_OWNER_KEY = f"ic_org_{_ORG_ID}"

_PERSONAL_AUTH_CTX = AuthContext(
    api_key=_PERSONAL_API_KEY,
    principal_type="api_key",
    principal_id="personal-principal",
    session_id=None,
    org_id=None,
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="personal",
)

_ORG_AUTH_CTX = AuthContext(
    api_key=_ORG_API_KEY,
    principal_type="org_key",
    principal_id="org-principal",
    session_id=None,
    org_id=_ORG_ID,
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="org",
)


def _build_app(*, auth_ctx: AuthContext | None = None) -> FastAPI:
    """
    Build a minimal FastAPI app with the billing router.

    When auth_ctx is provided, override require_auth_context so the router
    receives a fully-resolved AuthContext without touching real key validation.
    When auth_ctx is None, no override is set — the real auth dependency runs
    and will reject missing keys with 401 (auth_required=True on settings).
    """
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key=_PERSONAL_API_KEY,
        admin_api_key=None,
    )
    app.include_router(billing_router)
    if auth_ctx is not None:
        app.dependency_overrides[require_auth_context] = lambda: auth_ctx
    return app


def _personal_client() -> TestClient:
    return TestClient(_build_app(auth_ctx=_PERSONAL_AUTH_CTX))


def _org_client() -> TestClient:
    return TestClient(_build_app(auth_ctx=_ORG_AUTH_CTX))


def _unauthed_client() -> TestClient:
    # No override — real auth runs and must reject with 401.
    return TestClient(_build_app(), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# GET /billing/packages
# ---------------------------------------------------------------------------


def test_list_packages_returns_200_with_all_three_packages() -> None:
    response = _personal_client().get("/billing/packages")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data

    returned_ids = {p["package_id"] for p in data["packages"]}
    assert returned_ids == _ALL_PKG_IDS, f"Expected packages {_ALL_PKG_IDS}, got {returned_ids}"

    for pkg in data["packages"]:
        assert pkg["included_units"] > 0
        assert pkg["price_usd"] > 0
        assert pkg["tokens_per_unit"] > 0
        assert pkg["token_coverage"] > 0
        assert isinstance(pkg["description"], str)

    # unit_policy required fields
    policy = data["unit_policy"]
    assert isinstance(policy["unit_definition"], str)
    assert isinstance(policy["delivery_model"], str)
    assert isinstance(policy["buyer_positioning"], str)
    assert policy["token_chunk_size"] > 0
    assert isinstance(policy["protection_layers"], list)
    assert len(policy["protection_layers"]) > 0
    assert isinstance(policy["market_context"], list)
    assert len(policy["market_context"]) > 0


def test_list_packages_returns_401_unauthenticated() -> None:
    response = _unauthed_client().get("/billing/packages")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — personal key
# ---------------------------------------------------------------------------


def test_purchase_personal_key_returns_201_and_owner_key_is_buyer_email() -> None:
    buyer_email = "buyer@ironclaw.test"
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_5K,
            "buyer_name": "Test Buyer",
            "buyer_email": buyer_email,
            "metadata": {},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"

    purchase = data["purchase"]
    assert purchase["package_id"] == _PKG_5K
    assert purchase["buyer_email"] == buyer_email.lower()
    # Personal key → owner_key must equal normalized buyer_email
    assert purchase["owner_key"] == buyer_email.lower()
    assert purchase["granted_units"] > 0
    assert purchase["token_coverage"] > 0
    assert "purchase_id" in purchase
    assert "created_at" in purchase

    wallet = data["wallet"]
    assert wallet["owner_key"] == buyer_email.lower()
    assert wallet["balance_units"] >= purchase["granted_units"]


def test_purchase_personal_key_pkg_25k_returns_201() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_25K,
            "buyer_name": "Team Buyer",
            "buyer_email": "team@ironclaw.test",
            "metadata": {"team": "engineering"},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["purchase"]["package_id"] == _PKG_25K
    assert data["purchase"]["granted_units"] == UNIT_PACKAGE_CATALOG[_PKG_25K]["unit_amount"]


def test_purchase_personal_key_pkg_60k_returns_201() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_60K,
            "buyer_name": "Enterprise Buyer",
            "buyer_email": "enterprise@ironclaw.test",
            "metadata": {},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["purchase"]["package_id"] == _PKG_60K
    assert data["purchase"]["granted_units"] == UNIT_PACKAGE_CATALOG[_PKG_60K]["unit_amount"]


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — purchase_id uniqueness (uuid-based)
# ---------------------------------------------------------------------------


def test_purchase_id_uniqueness_across_concurrent_purchases() -> None:
    """
    purchase_id must be uuid-based and collision-free under concurrent load.
    Sequential ID generation (len + 1) would produce duplicates; uuid4 must not.
    """
    client = _personal_client()

    def _do_purchase(i: int) -> str:
        resp = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": f"Concurrent Buyer {i}",
                "buyer_email": f"concurrent{i}@ironclaw.test",
                "metadata": {},
            },
        )
        assert resp.status_code == 201, f"Purchase {i} failed: {resp.text}"
        return resp.json()["purchase"]["purchase_id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_do_purchase, i) for i in range(20)]
        purchase_ids = [f.result() for f in concurrent.futures.as_completed(futures)]

    # All purchase_ids must be unique
    assert len(purchase_ids) == len(set(purchase_ids)), f"Duplicate purchase_ids detected: {purchase_ids}"
    # All must be uuid-based (purch_ prefix + 32 hex chars)
    for pid in purchase_ids:
        assert pid.startswith("purch_"), f"purchase_id missing purch_ prefix: {pid!r}"
        hex_part = pid[len("purch_") :]
        assert len(hex_part) == 32, f"purchase_id hex part wrong length: {pid!r}"
        assert all(c in "0123456789abcdef" for c in hex_part), f"purchase_id contains non-hex characters: {pid!r}"


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — org key
# ---------------------------------------------------------------------------


def test_purchase_org_key_returns_201_and_owner_key_is_ic_org() -> None:
    """
    Org API key → owner_key must be ic_org_{org_id}, not buyer_email.
    This verifies resolve_billing_owner routes org purchases to the shared
    org wallet, keeping all team consumption pooled under one wallet.
    """
    response = _org_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_5K,
            "buyer_name": "Org Admin",
            "buyer_email": "admin@ironclaw-org.test",
            "metadata": {"org": _ORG_ID},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"

    purchase = data["purchase"]
    assert purchase["package_id"] == _PKG_5K
    # Org key → owner_key must be ic_org_{org_id}, NOT buyer_email
    assert purchase["owner_key"] == _ORG_OWNER_KEY, f"Expected org wallet key {_ORG_OWNER_KEY!r}, got {purchase['owner_key']!r}"
    assert purchase["granted_units"] > 0

    wallet = data["wallet"]
    assert wallet["owner_key"] == _ORG_OWNER_KEY


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — auth enforcement
# ---------------------------------------------------------------------------


def test_purchase_no_api_key_returns_401() -> None:
    """
    Core require_auth_context enforcement gate: unauthenticated purchase
    attempt must be rejected with 401 before any purchase logic executes.
    No wallet state must change as a result of this call.
    """
    response = _unauthed_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_5K,
            "buyer_name": "Attacker",
            "buyer_email": "attacker@evil.test",
            "metadata": {},
        },
    )
    assert response.status_code == 401


def test_purchase_unknown_package_id_returns_404() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_does_not_exist",
            "buyer_name": "Test Buyer",
            "buyer_email": "buyer@ironclaw.test",
            "metadata": {},
        },
    )
    assert response.status_code == 404


def test_purchase_empty_package_id_returns_422() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": "",
            "buyer_name": "Test Buyer",
            "buyer_email": "buyer@ironclaw.test",
            "metadata": {},
        },
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key} — personal key
# ---------------------------------------------------------------------------


def test_get_wallet_personal_key_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="wallet-read-personal@ironclaw.test",
        units=100,
        metadata={"package_id": _PKG_5K},
    )
    response = _personal_client().get("/billing/wallet/wallet-read-personal@ironclaw.test")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    wallet = data["wallet"]
    assert wallet["owner_key"] == "wallet-read-personal@ironclaw.test"
    assert wallet["balance_units"] >= 100
    assert "wallet_id" in wallet
    assert "updated_at" in wallet


def test_get_wallet_personal_key_cannot_access_org_wallet_returns_403() -> None:
    """Personal key must not be allowed to read an org wallet."""
    response = _personal_client().get(f"/billing/wallet/{_ORG_OWNER_KEY}")
    assert response.status_code == 403


def test_get_wallet_unauthenticated_returns_401() -> None:
    response = _unauthed_client().get("/billing/wallet/some-owner@test.com")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key} — org key isolation
# ---------------------------------------------------------------------------


def test_get_wallet_org_key_reads_own_org_wallet_returns_200() -> None:
    """Org key can read its own ic_org_* wallet."""
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=500,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().get(f"/billing/wallet/{_ORG_OWNER_KEY}")
    assert response.status_code == 200
    data = response.json()
    assert data["wallet"]["owner_key"] == _ORG_OWNER_KEY
    assert data["wallet"]["balance_units"] >= 500


def test_get_wallet_org_key_cannot_access_personal_wallet_returns_403() -> None:
    """Org key must not be allowed to read a personal wallet."""
    response = _org_client().get("/billing/wallet/personal@ironclaw.test")
    assert response.status_code == 403


def test_get_wallet_org_key_cannot_access_different_org_wallet_returns_403() -> None:
    """Org key for org A must not read org B's wallet."""
    other_org_wallet = "ic_org_differentorg999"
    response = _org_client().get(f"/billing/wallet/{other_org_wallet}")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit — personal key
# ---------------------------------------------------------------------------


def test_debit_personal_wallet_by_units_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="debit-personal@ironclaw.test",
        units=500,
        metadata={"package_id": _PKG_5K},
    )
    response = _personal_client().post(
        "/billing/wallet/debit-personal@ironclaw.test/debit",
        json={"units": 10, "reason": "test debit"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_debited"] == 10
    assert data["owner_key"] == "debit-personal@ironclaw.test"
    assert data["wallet"]["balance_units"] == 490


def test_debit_personal_wallet_by_token_count_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="debit-tokens@ironclaw.test",
        units=500,
        metadata={"package_id": _PKG_5K},
    )
    # 50_000 tokens = 2 units at TOKEN_CHUNK_SIZE=25_000
    response = _personal_client().post(
        "/billing/wallet/debit-tokens@ironclaw.test/debit",
        json={"token_count": 50_000},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["units_debited"] == 2
    assert data["token_count"] == 50_000


def test_debit_wallet_returns_402_on_insufficient_units() -> None:
    response = _personal_client().post(
        "/billing/wallet/empty-wallet-noexist@ironclaw.test/debit",
        json={"units": 999_999_999},
    )
    assert response.status_code == 402
    data = response.json()
    assert data["status"] == "insufficient_units"
    assert "have" in data
    assert "need" in data


def test_debit_wallet_returns_422_when_no_units_or_token_count() -> None:
    response = _personal_client().post(
        "/billing/wallet/debit-personal@ironclaw.test/debit",
        json={"reason": "missing amount"},
    )
    assert response.status_code == 422


def test_debit_wallet_returns_401_unauthenticated() -> None:
    response = _unauthed_client().post(
        "/billing/wallet/debit-personal@ironclaw.test/debit",
        json={"units": 1},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit — org key isolation
# ---------------------------------------------------------------------------


def test_debit_org_wallet_via_org_key_returns_200_and_routes_to_org_wallet() -> None:
    """
    Org key debit must always route to ic_org_{org_id} regardless of URL
    owner_key. Verify resolved_owner in response is the org wallet.
    """
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=1000,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 5, "reason": "org debit test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert data["units_debited"] == 5
    assert data["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_debit_org_key_personal_url_redirects_to_org_wallet() -> None:
    """
    Org key calling debit with a personal email in the URL path must be
    silently redirected to the caller's own org wallet, not rejected.
    The response owner_key must be the org wallet, not the URL personal key.
    """
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=200,
        metadata={"package_id": _PKG_5K},
    )
    response = _org_client().post(
        "/billing/wallet/some-personal@ironclaw.test/debit",
        json={"units": 1, "reason": "redirect test"},
    )
    assert response.status_code == 200
    data = response.json()
    # Must resolve to the org wallet, not the personal URL path key
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert data["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_debit_org_key_cannot_target_different_org_wallet_returns_403() -> None:
    """Org key for org A must not debit org B's wallet."""
    other_org = "ic_org_attackerorg"
    response = _org_client().post(
        f"/billing/wallet/{other_org}/debit",
        json={"units": 1},
    )
    assert response.status_code == 403


def test_debit_personal_key_cannot_target_org_wallet_returns_403() -> None:
    """Personal key must not be allowed to debit an org wallet."""
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 1},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund — personal key
# ---------------------------------------------------------------------------


def test_refund_personal_wallet_path_key_used_directly_as_owner_key() -> None:
    """
    Regression: refund_wallet must pass the URL path owner_key directly to
    _assert_owner_access, NOT through resolve_billing_owner (which expects a
    buyer_email and would incorrectly re-derive the wallet key).
    The response owner_key must equal the URL path exactly.
    """
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="refund-pathkey@ironclaw.test",
        units=100,
        metadata={"package_id": _PKG_5K},
    )
    registry.debit_units(
        owner_key="refund-pathkey@ironclaw.test",
        units=30,
        metadata={"reason": "setup"},
    )
    response = _personal_client().post(
        "/billing/wallet/refund-pathkey@ironclaw.test/refund",
        json={"units": 10, "reason": "path key regression test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_refunded"] == 10
    # owner_key in response must be the path parameter exactly
    assert data["owner_key"] == "refund-pathkey@ironclaw.test"
    assert data["wallet"]["balance_units"] == 80  # 100 - 30 + 10


def test_refund_personal_wallet_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="refund-personal@ironclaw.test",
        units=200,
        metadata={"package_id": _PKG_5K},
    )
    registry.debit_units(
        owner_key="refund-personal@ironclaw.test",
        units=50,
        metadata={"reason": "setup"},
    )
    response = _personal_client().post(
        "/billing/wallet/refund-personal@ironclaw.test/refund",
        json={"units": 20, "reason": "test refund"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_refunded"] == 20
    assert data["owner_key"] == "refund-personal@ironclaw.test"
    wallet = data["wallet"]
    assert wallet["balance_units"] == 170  # 200 - 50 + 20


def test_refund_zero_units_returns_422() -> None:
    """Refund schema enforces ge=1 — zero units must be rejected at validation."""
    response = _personal_client().post(
        "/billing/wallet/refund-personal@ironclaw.test/refund",
        json={"units": 0},
    )
    assert response.status_code == 422


def test_refund_wallet_returns_401_unauthenticated() -> None:
    response = _unauthed_client().post(
        "/billing/wallet/refund-personal@ironclaw.test/refund",
        json={"units": 5},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund — org key isolation
# ---------------------------------------------------------------------------


def test_refund_org_wallet_via_org_key_returns_200() -> None:
    """Org key refund must route to ic_org_{org_id}."""
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=300,
        metadata={"package_id": _PKG_25K},
    )
    registry.debit_units(
        owner_key=_ORG_OWNER_KEY,
        units=100,
        metadata={"reason": "setup"},
    )
    response = _org_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/refund",
        json={"units": 30, "reason": "org refund test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_refunded"] == 30
    assert data["owner_key"] == _ORG_OWNER_KEY


def test_refund_org_key_different_org_wallet_returns_403() -> None:
    """
    Org key for org A calling refund on ic_org_other (a different org's wallet)
    must be rejected with 403. _assert_owner_access enforces this boundary.
    """
    other_org_wallet = "ic_org_completelyotherorg"
    response = _org_client().post(
        f"/billing/wallet/{other_org_wallet}/refund",
        json={"units": 1, "reason": "cross-org refund attempt"},
    )
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["reason"] in {"org_id_mismatch", "org_wallet_requires_org_key"}


def test_refund_personal_key_cannot_refund_org_wallet_returns_403() -> None:
    """Personal key must not be allowed to refund an org wallet."""
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/refund",
        json={"units": 1},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# GET /billing/ledger — personal key
# ---------------------------------------------------------------------------


def test_get_ledger_personal_key_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="ledger-personal@ironclaw.test",
        units=1000,
        metadata={"package_id": _PKG_5K},
    )
    registry.debit_units(
        owner_key="ledger-personal@ironclaw.test",
        units=25,
        metadata={"route": "/guard/execute"},
    )
    response = _personal_client().get(
        "/billing/ledger",
        params={"owner_key": "ledger-personal@ironclaw.test", "limit": 10},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == "ledger-personal@ironclaw.test"
    assert data["limit"] == 10
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) >= 2

    entry = data["entries"][-1]
    assert entry["owner_key"] == "ledger-personal@ironclaw.test"
    assert entry["entry_type"] in {"credit", "debit"}
    assert "units" in entry
    assert "balance_after" in entry
    assert "created_at" in entry


def test_get_ledger_returns_401_unauthenticated() -> None:
    response = _unauthed_client().get("/billing/ledger")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/ledger — org key isolation
# ---------------------------------------------------------------------------


def test_get_ledger_org_key_can_read_own_org_wallet_entries() -> None:
    """Org key ledger query for its own ic_org_ wallet must succeed."""
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=200,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().get(
        "/billing/ledger",
        params={"owner_key": _ORG_OWNER_KEY, "limit": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert isinstance(data["entries"], list)


def test_get_ledger_org_key_cannot_query_personal_wallet_entries_returns_403() -> None:
    """Org key must not be able to read a personal owner's ledger entries."""
    response = _org_client().get(
        "/billing/ledger",
        params={"owner_key": "personal@ironclaw.test"},
    )
    assert response.status_code == 403


def test_get_ledger_personal_key_cannot_query_org_wallet_entries_returns_403() -> None:
    """Personal key must not be able to read an org wallet's ledger entries."""
    response = _personal_client().get(
        "/billing/ledger",
        params={"owner_key": _ORG_OWNER_KEY},
    )
    assert response.status_code == 403


def test_get_ledger_org_key_cannot_query_different_org_wallet_returns_403() -> None:
    """Org key for org A must not read org B's ledger entries."""
    response = _org_client().get(
        "/billing/ledger",
        params={"owner_key": "ic_org_otherorg999"},
    )
    assert response.status_code == 403
