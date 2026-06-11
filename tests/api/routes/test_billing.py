from __future__ import annotations

import math
import os

from fastapi.testclient import TestClient
import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from app.core.auth import AuthContext, require_auth_context
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import TOKEN_CHUNK_SIZE, UNIT_PACKAGE_CATALOG, UnitWalletRegistry
from app.main import app as _app

_TEST_AUTH_CONTEXT = AuthContext(
    api_key="test-api-key",
    principal_type="api_key",
    principal_id="test-principal",
    session_id=None,
    org_id="test-org",
    permissions=(),
    roles=(),
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
)

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}


def _override_require_auth_context() -> AuthContext:
    return _TEST_AUTH_CONTEXT


@pytest.fixture(autouse=True)
def _reset_wallet_registry():
    fresh = UnitWalletRegistry()
    _unit_wallet_module._unit_wallet_registry = fresh
    yield
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()


@pytest.fixture()
def client(_reset_wallet_registry):
    _app.dependency_overrides[require_auth_context] = _override_require_auth_context
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c
    _app.dependency_overrides.pop(require_auth_context, None)


# ---------------------------------------------------------------------------
# GET /billing/packages
# ---------------------------------------------------------------------------


def test_list_billing_packages_returns_correct_token_coverage(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    packages = {p["package_id"]: p for p in body["packages"]}
    assert len(packages) >= 3

    for pkg_id, pkg in packages.items():
        source = UNIT_PACKAGE_CATALOG.get(pkg_id)
        assert source is not None, f"package {pkg_id!r} not found in UNIT_PACKAGE_CATALOG"
        expected_coverage = int(source["unit_amount"]) * TOKEN_CHUNK_SIZE
        assert pkg["token_coverage"] == expected_coverage, f"{pkg_id}: token_coverage {pkg['token_coverage']} != {expected_coverage}"
        assert pkg["tokens_per_unit"] == TOKEN_CHUNK_SIZE, f"{pkg_id}: tokens_per_unit {pkg['tokens_per_unit']} != {TOKEN_CHUNK_SIZE}"


def test_list_billing_packages_token_coverage_matches_token_chunk_size(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    policy = resp.json()["unit_policy"]
    assert policy["token_chunk_size"] == TOKEN_CHUNK_SIZE

    for pkg in resp.json()["packages"]:
        assert pkg["tokens_per_unit"] == TOKEN_CHUNK_SIZE
        assert pkg["token_coverage"] == pkg["included_units"] * TOKEN_CHUNK_SIZE


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase
# ---------------------------------------------------------------------------


def test_purchase_valid_package_creates_purchase_credits_wallet_returns_201(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_5000",
        "buyer_name": "Test Buyer",
        "buyer_email": "buyer@ironclaw.test",
        "metadata": {},
    }
    resp = client.post("/billing/packages/purchase", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "ok"

    purchase = body["purchase"]
    assert purchase["package_id"] == "pkg_5000"
    assert purchase["granted_units"] == 5_000
    assert purchase["token_coverage"] == 5_000 * TOKEN_CHUNK_SIZE
    assert purchase["tokens_per_unit"] == TOKEN_CHUNK_SIZE
    assert purchase["buyer_email"] == "buyer@ironclaw.test"
    assert purchase["purchase_id"].startswith("purch_")

    wallet = body["wallet"]
    assert wallet["balance_units"] == 5_000
    assert wallet["total_purchased_units"] == 5_000
    assert wallet["owner_key"] == "buyer@ironclaw.test"


def test_purchase_team_package_credits_correct_units(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_25000",
        "buyer_name": "Team Buyer",
        "buyer_email": "team@ironclaw.test",
        "metadata": {"org": "ironclaw"},
    }
    resp = client.post("/billing/packages/purchase", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["granted_units"] == 25_000
    assert body["wallet"]["balance_units"] == 25_000


def test_purchase_enterprise_package_credits_correct_units(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_60000",
        "buyer_name": "Enterprise Buyer",
        "buyer_email": "enterprise@ironclaw.test",
        "metadata": {},
    }
    resp = client.post("/billing/packages/purchase", json=payload)
    assert resp.status_code == 201
    assert resp.json()["purchase"]["granted_units"] == 60_000


def test_purchase_unknown_package_returns_404(client: TestClient) -> None:
    payload = {
        "package_id": "pkg_unknown_xyz",
        "buyer_name": "Ghost Buyer",
        "buyer_email": "ghost@ironclaw.test",
        "metadata": {},
    }
    resp = client.post("/billing/packages/purchase", json=payload)
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "pkg_unknown_xyz" in detail


def test_purchase_empty_package_id_returns_422(client: TestClient) -> None:
    payload = {
        "package_id": "",
        "buyer_name": "Bad Buyer",
        "buyer_email": "bad@ironclaw.test",
        "metadata": {},
    }
    resp = client.post("/billing/packages/purchase", json=payload)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit — units param
# ---------------------------------------------------------------------------


def _fund_wallet(client: TestClient, email: str, package_id: str = "pkg_5000") -> None:
    client.post(
        "/billing/packages/purchase",
        json={
            "package_id": package_id,
            "buyer_name": "Fixture Buyer",
            "buyer_email": email,
            "metadata": {},
        },
    )


def test_debit_with_units_param_debits_correctly_returns_200(client: TestClient) -> None:
    owner = "debit-units@ironclaw.test"
    _fund_wallet(client, owner)

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 10, "reason": "test_debit"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["owner_key"] == owner
    assert body["units_debited"] == 10
    assert body["wallet"]["balance_units"] == 5_000 - 10
    assert body["wallet"]["total_consumed_units"] == 10


def test_debit_with_token_count_computes_ceiling_units_returns_200(client: TestClient) -> None:
    owner = "debit-tokens@ironclaw.test"
    _fund_wallet(client, owner)

    token_count = TOKEN_CHUNK_SIZE + 1
    expected_units = math.ceil(token_count / TOKEN_CHUNK_SIZE)
    assert expected_units == 2

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"token_count": token_count, "reason": "test_token_debit"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["units_debited"] == expected_units
    assert body["token_count"] == token_count
    assert body["wallet"]["balance_units"] == 5_000 - expected_units


def test_debit_exact_chunk_boundary_costs_one_unit(client: TestClient) -> None:
    owner = "boundary@ironclaw.test"
    _fund_wallet(client, owner)

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"token_count": TOKEN_CHUNK_SIZE},
    )
    assert resp.status_code == 200
    assert resp.json()["units_debited"] == 1


def test_debit_one_token_costs_one_unit(client: TestClient) -> None:
    owner = "onetoken@ironclaw.test"
    _fund_wallet(client, owner)

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"token_count": 1},
    )
    assert resp.status_code == 200
    assert resp.json()["units_debited"] == 1


def test_debit_insufficient_balance_returns_402_structured_body(client: TestClient) -> None:
    owner = "broke@ironclaw.test"
    _fund_wallet(client, owner)

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 9_999_999, "reason": "overdraft_test"},
    )
    assert resp.status_code == 402
    detail = resp.json()["detail"]
    assert detail["status"] == "insufficient_units"
    assert detail["owner_key"] == owner
    assert "have" in detail
    assert "need" in detail
    assert "tokens_per_unit" in detail
    assert detail["have"] == 5_000
    assert detail["need"] == 9_999_999
    assert detail["tokens_per_unit"] == TOKEN_CHUNK_SIZE


def test_debit_insufficient_balance_zero_wallet_returns_402(client: TestClient) -> None:
    owner = "empty-wallet@ironclaw.test"

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 1},
    )
    assert resp.status_code == 402
    detail = resp.json()["detail"]
    assert detail["have"] == 0
    assert detail["need"] == 1
    assert detail["owner_key"] == owner


def test_debit_neither_units_nor_token_count_returns_422(client: TestClient) -> None:
    owner = "noparam@ironclaw.test"
    _fund_wallet(client, owner)

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"reason": "missing_both"},
    )
    assert resp.status_code == 422


def test_debit_units_zero_rejected_by_schema(client: TestClient) -> None:
    owner = "zeroparam@ironclaw.test"
    _fund_wallet(client, owner)

    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 0},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund
# ---------------------------------------------------------------------------


def test_refund_credits_back_correctly_with_entry_type_refund(client: TestClient) -> None:
    owner = "refund-user@ironclaw.test"
    _fund_wallet(client, owner)

    client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 100, "reason": "consumed"},
    )

    resp = client.post(
        f"/billing/wallet/{owner}/refund",
        json={"units": 50, "reason": "test_refund"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["owner_key"] == owner
    assert body["units_refunded"] == 50
    assert body["wallet"]["balance_units"] == 5_000 - 100 + 50
    assert body["wallet"]["total_refunded_units"] == 50

    ledger_resp = client.get(f"/billing/ledger?owner_key={owner}")
    assert ledger_resp.status_code == 200
    entries = ledger_resp.json()["entries"]
    entry_types = [e["entry_type"] for e in entries]
    assert "refund" in entry_types


def test_refund_units_zero_rejected_by_schema(client: TestClient) -> None:
    owner = "refund-zero@ironclaw.test"
    resp = client.post(
        f"/billing/wallet/{owner}/refund",
        json={"units": 0},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}
# ---------------------------------------------------------------------------


def test_get_wallet_creates_wallet_on_first_access(client: TestClient) -> None:
    owner = "new-wallet@ironclaw.test"
    resp = client.get(f"/billing/wallet/{owner}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    wallet = body["wallet"]
    assert wallet["owner_key"] == owner
    assert wallet["balance_units"] == 0
    assert wallet["total_purchased_units"] == 0
    assert wallet["total_consumed_units"] == 0
    assert "wallet_id" in wallet
    assert "updated_at" in wallet


def test_get_wallet_returns_funded_balance(client: TestClient) -> None:
    owner = "funded-wallet@ironclaw.test"
    _fund_wallet(client, owner, package_id="pkg_25000")

    resp = client.get(f"/billing/wallet/{owner}")
    assert resp.status_code == 200
    assert resp.json()["wallet"]["balance_units"] == 25_000


def test_get_wallet_is_idempotent_on_repeated_access(client: TestClient) -> None:
    owner = "idempotent-wallet@ironclaw.test"
    r1 = client.get(f"/billing/wallet/{owner}")
    r2 = client.get(f"/billing/wallet/{owner}")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["wallet"]["wallet_id"] == r2.json()["wallet"]["wallet_id"]


# ---------------------------------------------------------------------------
# GET /billing/ledger
# ---------------------------------------------------------------------------


def test_ledger_without_owner_key_returns_all_entries(client: TestClient) -> None:
    owner_a = "ledger-a@ironclaw.test"
    owner_b = "ledger-b@ironclaw.test"
    _fund_wallet(client, owner_a)
    _fund_wallet(client, owner_b)

    resp = client.get("/billing/ledger")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["owner_key"] is None
    owner_keys = {e["owner_key"] for e in body["entries"]}
    assert owner_a in owner_keys
    assert owner_b in owner_keys


def test_ledger_with_owner_key_filter_returns_only_that_owner(client: TestClient) -> None:
    owner_a = "filter-a@ironclaw.test"
    owner_b = "filter-b@ironclaw.test"
    _fund_wallet(client, owner_a)
    _fund_wallet(client, owner_b)

    resp = client.get(f"/billing/ledger?owner_key={owner_a}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["owner_key"] == owner_a
    for entry in body["entries"]:
        assert entry["owner_key"] == owner_a


def test_ledger_entry_shape_is_complete(client: TestClient) -> None:
    owner = "shape-check@ironclaw.test"
    _fund_wallet(client, owner)

    resp = client.get(f"/billing/ledger?owner_key={owner}")
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert len(entries) >= 1

    entry = entries[0]
    for field in ("entry_id", "wallet_id", "owner_key", "entry_type", "units", "balance_after", "created_at"):
        assert field in entry, f"ledger entry missing field: {field!r}"


def test_ledger_debit_and_credit_entries_appear(client: TestClient) -> None:
    owner = "full-ledger@ironclaw.test"
    _fund_wallet(client, owner)

    client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 5, "reason": "ledger_verify"},
    )

    resp = client.get(f"/billing/ledger?owner_key={owner}")
    assert resp.status_code == 200
    entry_types = {e["entry_type"] for e in resp.json()["entries"]}
    assert "debit" in entry_types


def test_ledger_limit_param_respected(client: TestClient) -> None:
    owner = "limit-test@ironclaw.test"
    _fund_wallet(client, owner, package_id="pkg_5000")
    for _ in range(5):
        client.post(
            f"/billing/wallet/{owner}/debit",
            json={"units": 1},
        )

    resp = client.get(f"/billing/ledger?owner_key={owner}&limit=3")
    assert resp.status_code == 200
    body = resp.json()
    assert body["limit"] == 3
    assert len(body["entries"]) <= 3


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


def test_billing_routes_reject_missing_api_key() -> None:
    with TestClient(_app, raise_server_exceptions=True) as c:
        resp = c.get("/billing/packages")
    assert resp.status_code in (401, 403)


def test_billing_routes_reject_wrong_api_key() -> None:
    with TestClient(_app, raise_server_exceptions=True) as c:
        resp = c.get("/billing/packages", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code in (401, 403)
