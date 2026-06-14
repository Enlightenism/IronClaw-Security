from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.billing import router as billing_router
from app.core.auth import API_KEY_HEADER_NAME
from app.core.unit_wallet import UNIT_PACKAGE_CATALOG, get_unit_wallet_registry


def _build_app() -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key="test-secret-key",
        admin_api_key=None,
    )
    app.include_router(billing_router)
    return app


_APP = _build_app()
_AUTHED = {API_KEY_HEADER_NAME: "test-secret-key"}
_VALID_PACKAGE_ID = next(iter(UNIT_PACKAGE_CATALOG))


# ---------------------------------------------------------------------------
# GET /billing/packages
# ---------------------------------------------------------------------------


def test_list_billing_packages_returns_200_with_auth() -> None:
    client = TestClient(_APP)
    response = client.get("/billing/packages", headers=_AUTHED)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert isinstance(data["packages"], list)
    assert len(data["packages"]) > 0
    assert "unit_policy" in data


def test_list_billing_packages_returns_401_without_auth() -> None:
    client = TestClient(_APP, raise_server_exceptions=False)
    response = client.get("/billing/packages")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase
# ---------------------------------------------------------------------------


def test_purchase_billing_package_returns_201_with_auth() -> None:
    client = TestClient(_APP)
    response = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": _VALID_PACKAGE_ID,
            "buyer_name": "Test Buyer",
            "buyer_email": "buyer@ironclaw.test",
            "metadata": {},
        },
        headers=_AUTHED,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"
    assert "purchase" in data
    assert "wallet" in data
    purchase = data["purchase"]
    assert purchase["package_id"] == _VALID_PACKAGE_ID
    assert purchase["buyer_email"] == "buyer@ironclaw.test"
    assert purchase["granted_units"] > 0


def test_purchase_billing_package_returns_401_unauthenticated() -> None:
    """
    Core auth-enforcement gate: unauthenticated POST to /billing/packages/purchase
    must be rejected with HTTP 401 before any purchase logic executes.
    """
    client = TestClient(_APP, raise_server_exceptions=False)
    response = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": _VALID_PACKAGE_ID,
            "buyer_name": "Attacker",
            "buyer_email": "attacker@evil.test",
            "metadata": {},
        },
    )
    assert response.status_code == 401


def test_purchase_billing_package_returns_404_for_unknown_package() -> None:
    client = TestClient(_APP)
    response = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_does_not_exist",
            "buyer_name": "Test Buyer",
            "buyer_email": "buyer@ironclaw.test",
            "metadata": {},
        },
        headers=_AUTHED,
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}
# ---------------------------------------------------------------------------


def test_get_wallet_returns_200_with_auth() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="wallet-test-owner",
        units=100,
        metadata={"package_id": _VALID_PACKAGE_ID},
    )
    client = TestClient(_APP)
    response = client.get(
        "/billing/wallet/wallet-test-owner",
        headers=_AUTHED,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    wallet = data["wallet"]
    assert wallet["owner_key"] == "wallet-test-owner"
    assert wallet["balance_units"] >= 100


def test_get_wallet_returns_401_unauthenticated() -> None:
    client = TestClient(_APP, raise_server_exceptions=False)
    response = client.get("/billing/wallet/wallet-test-owner")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit
# ---------------------------------------------------------------------------


def test_debit_wallet_by_units_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="debit-test-owner",
        units=500,
        metadata={"package_id": _VALID_PACKAGE_ID},
    )
    client = TestClient(_APP)
    response = client.post(
        "/billing/wallet/debit-test-owner/debit",
        json={"units": 10, "reason": "test debit"},
        headers=_AUTHED,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_debited"] == 10
    assert data["wallet"]["balance_units"] == 490


def test_debit_wallet_returns_401_unauthenticated() -> None:
    client = TestClient(_APP, raise_server_exceptions=False)
    response = client.post(
        "/billing/wallet/debit-test-owner/debit",
        json={"units": 1},
    )
    assert response.status_code == 401


def test_debit_wallet_returns_402_on_insufficient_units() -> None:
    client = TestClient(_APP)
    response = client.post(
        "/billing/wallet/empty-wallet-owner/debit",
        json={"units": 99999999},
        headers=_AUTHED,
    )
    assert response.status_code == 402
    data = response.json()
    assert data["status"] == "insufficient_units"


def test_debit_wallet_returns_400_when_no_units_or_token_count() -> None:
    client = TestClient(_APP)
    response = client.post(
        "/billing/wallet/debit-test-owner/debit",
        json={"reason": "missing amount"},
        headers=_AUTHED,
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund
# ---------------------------------------------------------------------------


def test_refund_wallet_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="refund-test-owner",
        units=200,
        metadata={"package_id": _VALID_PACKAGE_ID},
    )
    registry.debit_units(
        owner_key="refund-test-owner",
        units=50,
        metadata={"reason": "setup"},
    )
    client = TestClient(_APP)
    response = client.post(
        "/billing/wallet/refund-test-owner/refund",
        json={"units": 20, "reason": "test refund"},
        headers=_AUTHED,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_refunded"] == 20


def test_refund_wallet_returns_401_unauthenticated() -> None:
    client = TestClient(_APP, raise_server_exceptions=False)
    response = client.post(
        "/billing/wallet/refund-test-owner/refund",
        json={"units": 5},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/ledger
# ---------------------------------------------------------------------------


def test_get_ledger_returns_200_with_auth() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="ledger-test-owner",
        units=25_000,
        metadata={"package_id": _VALID_PACKAGE_ID},
    )
    registry.debit_units(
        owner_key="ledger-test-owner",
        units=125,
        metadata={"route": "/guard/execute"},
    )
    client = TestClient(_APP)
    response = client.get(
        "/billing/ledger",
        params={"owner_key": "ledger-test-owner", "limit": 10},
        headers=_AUTHED,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == "ledger-test-owner"
    assert data["limit"] == 10
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) >= 2
    entry = data["entries"][-1]
    assert entry["owner_key"] == "ledger-test-owner"
    assert entry["entry_type"] in {"credit", "debit"}


def test_get_ledger_returns_401_unauthenticated() -> None:
    client = TestClient(_APP, raise_server_exceptions=False)
    response = client.get("/billing/ledger")
    assert response.status_code == 401
