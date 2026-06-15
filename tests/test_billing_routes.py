from __future__ import annotations

import concurrent.futures
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.billing import (
    _PURCHASES_MAX_SIZE,
    _append_purchase,
)
from app.api.routes.billing import router as billing_router
from app.core.auth import (
    AuthContext,
    get_auth_context,
    require_api_key,
    require_auth_context,
)
from app.core.unit_wallet import (
    UNIT_PACKAGE_CATALOG,
    get_unit_wallet_registry,
)

# ---------------------------------------------------------------------------
# Expected package IDs
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
    principal_id=None,
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
    principal_id=None,
    session_id=None,
    org_id=_ORG_ID,
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="org",
)


def _build_app(*, auth_ctx: AuthContext | None = None) -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key=_PERSONAL_API_KEY,
        admin_api_key=None,
    )
    app.include_router(billing_router)
    if auth_ctx is not None:
        app.dependency_overrides[require_api_key] = lambda: auth_ctx.api_key
        app.dependency_overrides[get_auth_context] = lambda: auth_ctx
        app.dependency_overrides[require_auth_context] = lambda: auth_ctx
    return app


def _personal_client() -> TestClient:
    return TestClient(_build_app(auth_ctx=_PERSONAL_AUTH_CTX))


def _org_client() -> TestClient:
    return TestClient(_build_app(auth_ctx=_ORG_AUTH_CTX))


def _unauthed_client() -> TestClient:
    return TestClient(_build_app(), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# GET /billing/packages
# ---------------------------------------------------------------------------


def test_list_packages_returns_200_with_all_three_packages() -> None:
    response = _personal_client().get("/billing/packages")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "ok"
    assert data["service"] in {"ironclaw-billing", "IronClaw-Security"}
    assert "timestamp" in data

    returned_ids = {p["package_id"] for p in data["packages"]}
    assert returned_ids == _ALL_PKG_IDS, f"Expected packages {_ALL_PKG_IDS}, got {returned_ids}"

    for pkg in data["packages"]:
        assert pkg["included_units"] > 0
        assert pkg["price_usd"] > 0
        assert pkg["tokens_per_unit"] > 0
        assert pkg["token_coverage"] > 0
        assert isinstance(pkg["description"], str)

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
# POST /billing/purchase — personal key
# ---------------------------------------------------------------------------


def test_purchase_personal_key_returns_201_and_owner_key_is_buyer_email() -> None:
    buyer_email = "buyer@ironclaw.test"
    response = _personal_client().post(
        "/billing/purchase",
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
        "/billing/purchase",
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
        "/billing/purchase",
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
# POST /billing/purchase — purchase_id uniqueness
# ---------------------------------------------------------------------------


def test_purchase_id_uniqueness_across_concurrent_purchases() -> None:
    client = _personal_client()

    def _do_purchase(i: int) -> str:
        resp = client.post(
            "/billing/purchase",
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

    assert len(purchase_ids) == len(set(purchase_ids)), f"Duplicate purchase_ids detected: {purchase_ids}"
    for pid in purchase_ids:
        assert pid.startswith("purch_"), f"purchase_id missing purch_ prefix: {pid!r}"
        hex_part = pid[len("purch_") :]
        assert len(hex_part) == 16, f"purchase_id hex part wrong length: {pid!r}"
        assert all(c in "0123456789abcdef" for c in hex_part), f"purchase_id contains non-hex characters: {pid!r}"


# ---------------------------------------------------------------------------
# _append_purchase cap enforcement
# ---------------------------------------------------------------------------


def test_append_purchase_enforces_max_size_cap() -> None:
    import app.api.routes.billing as billing_mod
    from app.api.routes.billing import BillingPackagePurchaseView

    original = list(billing_mod._PURCHASES)
    billing_mod._PURCHASES.clear()

    try:
        cap = _PURCHASES_MAX_SIZE
        for i in range(cap):
            _append_purchase(
                BillingPackagePurchaseView(
                    purchase_id=f"purch_{i:016x}",
                    package_id=_PKG_5K,
                    package_name="Starter",
                    buyer_name="Cap Test",
                    buyer_email=f"captest{i}@ironclaw.test",
                    owner_key=f"captest{i}@ironclaw.test",
                    price_usd=20.0,
                    granted_units=5000,
                    token_coverage=125_000_000,
                    tokens_per_unit=25_000,
                    created_at="2026-06-14T00:00:00Z",
                    metadata={},
                )
            )
        assert len(billing_mod._PURCHASES) == cap

        _append_purchase(
            BillingPackagePurchaseView(
                purchase_id="purch_overflow_0000000",
                package_id=_PKG_5K,
                package_name="Starter",
                buyer_name="Overflow",
                buyer_email="overflow@ironclaw.test",
                owner_key="overflow@ironclaw.test",
                price_usd=20.0,
                granted_units=5000,
                token_coverage=125_000_000,
                tokens_per_unit=25_000,
                created_at="2026-06-14T00:00:01Z",
                metadata={},
            )
        )
        assert len(billing_mod._PURCHASES) == cap
        assert billing_mod._PURCHASES[-1].purchase_id == "purch_overflow_0000000"
        assert billing_mod._PURCHASES[0].purchase_id != "purch_0000000000000000"
    finally:
        billing_mod._PURCHASES.clear()
        billing_mod._PURCHASES.extend(original)


# ---------------------------------------------------------------------------
# POST /billing/purchase — org key
# ---------------------------------------------------------------------------


def test_purchase_org_key_returns_201_and_owner_key_is_ic_org() -> None:
    response = _org_client().post(
        "/billing/purchase",
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
    assert purchase["owner_key"] == _ORG_OWNER_KEY, f"Expected org wallet key {_ORG_OWNER_KEY!r}, got {purchase['owner_key']!r}"
    assert purchase["granted_units"] > 0

    wallet = data["wallet"]
    assert wallet["owner_key"] == _ORG_OWNER_KEY


# ---------------------------------------------------------------------------
# POST /billing/purchase — auth enforcement
# ---------------------------------------------------------------------------


def test_purchase_no_api_key_returns_401() -> None:
    response = _unauthed_client().post(
        "/billing/purchase",
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
        "/billing/purchase",
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
        "/billing/purchase",
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
    response = _personal_client().get(f"/billing/wallet/{_ORG_OWNER_KEY}")
    assert response.status_code == 403


def test_get_wallet_unauthenticated_returns_401() -> None:
    response = _unauthed_client().get("/billing/wallet/some-owner@test.com")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key} — org key isolation
# ---------------------------------------------------------------------------


def test_get_wallet_org_key_reads_own_org_wallet_returns_200() -> None:
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
    response = _org_client().get("/billing/wallet/personal@ironclaw.test")
    assert response.status_code == 403


def test_get_wallet_org_key_cannot_access_different_org_wallet_returns_403() -> None:
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
    detail = response.json()["detail"]
    assert detail["status"] == "insufficient_units"
    assert "have" in detail
    assert "need" in detail


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
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=200,
        metadata={"package_id": _PKG_5K},
    )
    response = _org_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 1, "reason": "redirect test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert data["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_debit_org_key_cannot_target_different_org_wallet_returns_403() -> None:
    other_org = "ic_org_attackerorg"
    response = _org_client().post(
        f"/billing/wallet/{other_org}/debit",
        json={"units": 1},
    )
    assert response.status_code == 403


def test_debit_personal_key_cannot_target_org_wallet_returns_403() -> None:
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 1},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund — personal key
# ---------------------------------------------------------------------------


def test_refund_personal_wallet_path_key_used_directly_as_owner_key() -> None:
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
    assert data["owner_key"] == "refund-pathkey@ironclaw.test"
    assert data["wallet"]["balance_units"] == 80


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
    assert data["wallet"]["balance_units"] == 170


def test_refund_zero_units_returns_422() -> None:
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
    other_org_wallet = "ic_org_completelyotherorg"
    response = _org_client().post(
        f"/billing/wallet/{other_org_wallet}/refund",
        json={"units": 1, "reason": "cross-org refund attempt"},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, str)
    assert len(detail) > 0


def test_refund_personal_key_cannot_refund_org_wallet_returns_403() -> None:
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/refund",
        json={"units": 1},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}/ledger — personal key
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
        metadata={"reason": "test_debit", "route": "/guard/execute"},
    )
    response = _personal_client().get(
        "/billing/wallet/ledger-personal@ironclaw.test/ledger",
        params={"limit": 10},
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
    response = _unauthed_client().get("/billing/wallet/ledger-personal@ironclaw.test/ledger")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}/ledger — org key isolation
# ---------------------------------------------------------------------------


def test_get_ledger_org_key_can_read_own_org_wallet_entries() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=200,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().get(
        f"/billing/wallet/{_ORG_OWNER_KEY}/ledger",
        params={"limit": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert isinstance(data["entries"], list)


def test_get_ledger_org_key_cannot_query_personal_wallet_entries_returns_403() -> None:
    response = _org_client().get("/billing/wallet/personal@ironclaw.test/ledger")
    assert response.status_code == 403


def test_get_ledger_personal_key_cannot_query_org_wallet_entries_returns_403() -> None:
    response = _personal_client().get(f"/billing/wallet/{_ORG_OWNER_KEY}/ledger")
    assert response.status_code == 403


def test_get_ledger_org_key_cannot_query_different_org_wallet_returns_403() -> None:
    response = _org_client().get("/billing/wallet/ic_org_otherorg999/ledger")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# GET /billing/purchases
# ---------------------------------------------------------------------------


def test_list_purchases_returns_200_with_count_and_list() -> None:
    response = _personal_client().get("/billing/purchases")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] in {"ironclaw-billing", "IronClaw-Security"}
    assert "timestamp" in data
    assert "count" in data
    assert isinstance(data["purchases"], list)


def test_list_purchases_limit_query_param_respected() -> None:
    response = _personal_client().get("/billing/purchases", params={"limit": 1})
    assert response.status_code == 200
    data = response.json()
    assert len(data["purchases"]) <= 1


def test_list_purchases_returns_401_unauthenticated() -> None:
    response = _unauthed_client().get("/billing/purchases")
    assert response.status_code == 401
