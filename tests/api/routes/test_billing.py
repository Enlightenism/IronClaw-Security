from __future__ import annotations

import math
import os
from unittest.mock import MagicMock

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

from app.core.auth import AuthContext, require_api_key
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import (
    ORG_KEY_PREFIX,
    TOKEN_CHUNK_SIZE,
    UNIT_PACKAGE_CATALOG,
    UnitWalletRegistry,
)
from app.main import app as _app

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}


def _override_require_api_key() -> str:
    return _MOCK_API_KEY


def _make_auth_ctx(
    *,
    principal_id: str | None = None,
    org_id: str | None = None,
    key_type: str | None = None,
) -> AuthContext:
    ctx = MagicMock(spec=AuthContext)
    ctx.principal_id = principal_id
    ctx.org_id = org_id
    ctx.key_type = key_type
    return ctx


@pytest.fixture(autouse=True)
def _reset_wallet_registry():
    fresh = UnitWalletRegistry()
    _unit_wallet_module._unit_wallet_registry = fresh
    yield
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()


@pytest.fixture()
def client(_reset_wallet_registry):
    _app.dependency_overrides[require_api_key] = _override_require_api_key
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c
    _app.dependency_overrides.pop(require_api_key, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fund_wallet(client: TestClient, email: str, package_id: str = "pkg_5000") -> None:
    resp = client.post(
        "/billing/purchase",
        json={
            "package_id": package_id,
            "buyer_name": "Fixture Buyer",
            "buyer_email": email,
            "metadata": {},
        },
    )
    assert resp.status_code == 201, f"_fund_wallet failed: {resp.status_code} {resp.text}"


# ---------------------------------------------------------------------------
# GET /billing/packages — schema correctness
# ---------------------------------------------------------------------------


def test_list_packages_returns_200_with_correct_schema(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "packages" in body
    assert "unit_policy" in body
    assert isinstance(body["packages"], list)
    assert len(body["packages"]) >= 3

    for pkg in body["packages"]:
        for field in ("package_id", "name", "price_usd", "included_units", "display_label", "description", "token_coverage", "tokens_per_unit"):
            assert field in pkg, f"packages entry missing field: {field!r}"
        assert pkg["tokens_per_unit"] == TOKEN_CHUNK_SIZE
        assert pkg["token_coverage"] == pkg["included_units"] * TOKEN_CHUNK_SIZE

    policy = body["unit_policy"]
    assert policy["token_chunk_size"] == TOKEN_CHUNK_SIZE
    assert "unit_definition" in policy
    assert "delivery_model" in policy


def test_list_packages_token_coverage_matches_catalog(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    packages = {p["package_id"]: p for p in resp.json()["packages"]}
    assert len(packages) >= 3
    for pkg_id, pkg in packages.items():
        source = UNIT_PACKAGE_CATALOG.get(pkg_id)
        assert source is not None, f"{pkg_id!r} not in UNIT_PACKAGE_CATALOG"
        expected_coverage = int(source["unit_amount"]) * TOKEN_CHUNK_SIZE
        assert pkg["token_coverage"] == expected_coverage


# ---------------------------------------------------------------------------
# POST /billing/purchase
# ---------------------------------------------------------------------------


def test_purchase_valid_package_returns_201_with_correct_shape(client: TestClient) -> None:
    resp = client.post(
        "/billing/purchase",
        json={
            "package_id": "pkg_5000",
            "buyer_name": "Test Buyer",
            "buyer_email": "buyer@ironclaw.test",
            "metadata": {},
        },
    )
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
    resp = client.post(
        "/billing/purchase",
        json={
            "package_id": "pkg_25000",
            "buyer_name": "Team Buyer",
            "buyer_email": "team@ironclaw.test",
            "metadata": {"org": "ironclaw"},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["granted_units"] == 25_000
    assert body["wallet"]["balance_units"] == 25_000


def test_purchase_enterprise_package_credits_correct_units(client: TestClient) -> None:
    resp = client.post(
        "/billing/purchase",
        json={
            "package_id": "pkg_60000",
            "buyer_name": "Enterprise Buyer",
            "buyer_email": "enterprise@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 201
    assert resp.json()["purchase"]["granted_units"] == 60_000


def test_purchase_unknown_package_returns_404(client: TestClient) -> None:
    resp = client.post(
        "/billing/purchase",
        json={
            "package_id": "pkg_unknown_xyz",
            "buyer_name": "Ghost Buyer",
            "buyer_email": "ghost@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 404
    assert "pkg_unknown_xyz" in resp.json()["detail"]


def test_purchase_empty_package_id_returns_422(client: TestClient) -> None:
    resp = client.post(
        "/billing/purchase",
        json={
            "package_id": "",
            "buyer_name": "Bad Buyer",
            "buyer_email": "bad@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit
# ---------------------------------------------------------------------------


def test_debit_with_units_param_returns_200(client: TestClient) -> None:
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


def test_debit_with_token_count_computes_ceiling_units(client: TestClient) -> None:
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


def test_debit_insufficient_balance_returns_402_with_structured_detail(client: TestClient) -> None:
    """Primary regression: removed catch block must propagate 402 with dict detail."""
    owner = "broke@ironclaw.test"
    _fund_wallet(client, owner)
    resp = client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 9_999_999, "reason": "overdraft_test"},
    )
    assert resp.status_code == 402
    detail = resp.json()["detail"]
    assert isinstance(detail, dict), "detail must be a dict, not a string"
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
    assert isinstance(detail, dict)
    assert detail["have"] == 0
    assert detail["need"] == 1
    assert detail["owner_key"] == owner


def test_debit_missing_both_units_and_token_count_returns_422(client: TestClient) -> None:
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


def test_refund_returns_200_on_valid_refund_after_credit(client: TestClient) -> None:
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


def test_refund_entry_appears_in_ledger(client: TestClient) -> None:
    owner = "refund-ledger@ironclaw.test"
    _fund_wallet(client, owner)
    client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 10, "reason": "pre_refund_debit"},
    )
    client.post(
        f"/billing/wallet/{owner}/refund",
        json={"units": 5, "reason": "test_refund_entry"},
    )
    resp = client.get(f"/billing/wallet/{owner}/ledger")
    assert resp.status_code == 200
    entry_types = {e["entry_type"] for e in resp.json()["entries"]}
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


def test_get_wallet_returns_200_and_creates_wallet_if_absent(client: TestClient) -> None:
    """
    The route returns 404 when no wallet exists; fund first to ensure
    the wallet is created, then assert 200 with correct shape.
    """
    owner = "new-wallet@ironclaw.test"
    _fund_wallet(client, owner)
    resp = client.get(f"/billing/wallet/{owner}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    wallet = body["wallet"]
    assert wallet["owner_key"] == owner
    assert wallet["balance_units"] == 5_000
    assert "wallet_id" in wallet
    assert "updated_at" in wallet


def test_get_wallet_absent_returns_404(client: TestClient) -> None:
    owner = "ghost-wallet@ironclaw.test"
    resp = client.get(f"/billing/wallet/{owner}")
    assert resp.status_code == 404


def test_get_wallet_returns_funded_balance(client: TestClient) -> None:
    owner = "funded-wallet@ironclaw.test"
    _fund_wallet(client, owner, package_id="pkg_25000")
    resp = client.get(f"/billing/wallet/{owner}")
    assert resp.status_code == 200
    assert resp.json()["wallet"]["balance_units"] == 25_000


def test_get_wallet_is_idempotent_on_repeated_access(client: TestClient) -> None:
    owner = "idempotent-wallet@ironclaw.test"
    _fund_wallet(client, owner)
    r1 = client.get(f"/billing/wallet/{owner}")
    r2 = client.get(f"/billing/wallet/{owner}")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["wallet"]["wallet_id"] == r2.json()["wallet"]["wallet_id"]


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}/ledger
# ---------------------------------------------------------------------------


def test_ledger_returns_200_with_correct_schema(client: TestClient) -> None:
    owner = "ledger-schema@ironclaw.test"
    _fund_wallet(client, owner)
    resp = client.get(f"/billing/wallet/{owner}/ledger")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["owner_key"] == owner
    assert "entries" in body
    assert "limit" in body
    assert isinstance(body["entries"], list)
    assert len(body["entries"]) >= 1
    entry = body["entries"][0]
    for field in ("entry_id", "wallet_id", "owner_key", "entry_type", "units", "balance_after", "created_at"):
        assert field in entry, f"ledger entry missing field: {field!r}"


def test_ledger_debit_and_credit_entries_appear(client: TestClient) -> None:
    owner = "full-ledger@ironclaw.test"
    _fund_wallet(client, owner)
    client.post(
        f"/billing/wallet/{owner}/debit",
        json={"units": 5, "reason": "ledger_verify"},
    )
    resp = client.get(f"/billing/wallet/{owner}/ledger")
    assert resp.status_code == 200
    entry_types = {e["entry_type"] for e in resp.json()["entries"]}
    assert "debit" in entry_types


def test_ledger_limit_param_respected(client: TestClient) -> None:
    owner = "limit-test@ironclaw.test"
    _fund_wallet(client, owner)
    for _ in range(5):
        client.post(f"/billing/wallet/{owner}/debit", json={"units": 1})
    resp = client.get(f"/billing/wallet/{owner}/ledger?limit=3")
    assert resp.status_code == 200
    body = resp.json()
    assert body["limit"] == 3
    assert len(body["entries"]) <= 3


# ---------------------------------------------------------------------------
# _assert_owner_access — direct unit tests via route module
# ---------------------------------------------------------------------------


def test_assert_owner_access_key_type_none_does_not_raise() -> None:
    """key_type=None (personal) with no principal_id set — must not raise."""
    from fastapi import HTTPException

    from app.api.routes.billing import _assert_owner_access

    ctx = _make_auth_ctx(principal_id=None, org_id=None, key_type=None)
    # Should not raise — no principal_id means no ownership check is enforced
    try:
        _assert_owner_access("anyone@ironclaw.test", ctx)
    except HTTPException:
        pytest.fail("_assert_owner_access raised HTTPException for key_type=None with no principal_id")


def test_assert_owner_access_org_mismatched_wallet_returns_403() -> None:
    """key_type='org' with mismatched org_id must raise 403."""
    from fastapi import HTTPException

    from app.api.routes.billing import _assert_owner_access

    org_owner_key = f"{ORG_KEY_PREFIX}acme"
    ctx = _make_auth_ctx(principal_id=None, org_id="different-org", key_type="org")
    with pytest.raises(HTTPException) as exc_info:
        _assert_owner_access(org_owner_key, ctx)
    assert exc_info.value.status_code == 403


def test_assert_owner_access_org_correct_wallet_passes() -> None:
    """key_type='org' with matching org_id must not raise."""
    from fastapi import HTTPException

    from app.api.routes.billing import _assert_owner_access

    org_id = "acme"
    org_owner_key = f"{ORG_KEY_PREFIX}{org_id}"
    ctx = _make_auth_ctx(principal_id=None, org_id=org_id, key_type="org")
    try:
        _assert_owner_access(org_owner_key, ctx)
    except HTTPException:
        pytest.fail("_assert_owner_access raised HTTPException for correct org wallet")


def test_assert_owner_access_personal_matching_principal_passes() -> None:
    from fastapi import HTTPException

    from app.api.routes.billing import _assert_owner_access

    principal = "user@ironclaw.test"
    ctx = _make_auth_ctx(principal_id=principal, org_id=None, key_type=None)
    try:
        _assert_owner_access(principal, ctx)
    except HTTPException:
        pytest.fail("_assert_owner_access raised for matching personal principal")


def test_assert_owner_access_personal_mismatched_principal_returns_403() -> None:
    from fastapi import HTTPException

    from app.api.routes.billing import _assert_owner_access

    ctx = _make_auth_ctx(principal_id="owner@ironclaw.test", org_id=None, key_type=None)
    with pytest.raises(HTTPException) as exc_info:
        _assert_owner_access("other@ironclaw.test", ctx)
    assert exc_info.value.status_code == 403


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
