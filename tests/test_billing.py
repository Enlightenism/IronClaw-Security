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


def _override_require_api_key() -> str:
    return _MOCK_API_KEY


def _make_personal_ctx(email: str = "test@ironclaw.test") -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="api_key",
        principal_id="test-principal",
        session_id=None,
        org_id=None,
        authenticated=True,
        auth_source="registry",
        key_type="personal",
    )


def _make_org_ctx(org_id: str) -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="org_key",
        principal_id="test-principal",
        session_id=None,
        org_id=org_id,
        authenticated=True,
        auth_source="registry",
        key_type="org",
    )


@contextmanager
def _override_auth(ctx: AuthContext):
    def _stub_api_key() -> str:
        return ctx.api_key or _MOCK_API_KEY

    def _stub_auth_ctx() -> AuthContext:
        return ctx

    _app.dependency_overrides[get_api_key] = _stub_api_key
    _app.dependency_overrides[get_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_api_key] = _stub_api_key
    try:
        yield TestClient(_app, raise_server_exceptions=True)
    finally:
        _app.dependency_overrides.pop(get_api_key, None)
        _app.dependency_overrides.pop(get_auth_context, None)
        _app.dependency_overrides.pop(require_auth_context, None)
        _app.dependency_overrides.pop(require_api_key, None)


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
# GET /billing/packages
# ---------------------------------------------------------------------------


def test_packages_returns_exactly_three_packages(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert len(body["packages"]) == 3


def test_packages_returns_correct_included_units_and_price_usd(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    packages = {p["package_id"]: p for p in resp.json()["packages"]}

    assert packages["pkg_5000"]["included_units"] == 5_000
    assert packages["pkg_5000"]["price_usd"] == 20.0

    assert packages["pkg_25000"]["included_units"] == 25_000
    assert packages["pkg_25000"]["price_usd"] == 90.0

    assert packages["pkg_60000"]["included_units"] == 60_000
    assert packages["pkg_60000"]["price_usd"] == 180.0


def test_packages_token_coverage_matches_chunk_size(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    for pkg in resp.json()["packages"]:
        assert pkg["tokens_per_unit"] == TOKEN_CHUNK_SIZE
        assert pkg["token_coverage"] == pkg["included_units"] * TOKEN_CHUNK_SIZE


def test_packages_unit_policy_present_with_non_empty_protection_layers_and_market_context(
    client: TestClient,
) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    policy = resp.json()["unit_policy"]
    assert "token_chunk_size" in policy
    assert policy["token_chunk_size"] == TOKEN_CHUNK_SIZE
    assert isinstance(policy["protection_layers"], list)
    assert len(policy["protection_layers"]) > 0
    assert isinstance(policy["market_context"], list)
    assert len(policy["market_context"]) > 0
    for layer in policy["protection_layers"]:
        assert "title" in layer
        assert "detail" in layer


def test_packages_catalog_integrity_matches_source(client: TestClient) -> None:
    resp = client.get("/billing/packages")
    assert resp.status_code == 200
    packages = {p["package_id"]: p for p in resp.json()["packages"]}
    for pkg_id, pkg in packages.items():
        source = PACKAGE_CATALOG.get(pkg_id)
        assert source is not None, f"{pkg_id!r} missing from PACKAGE_CATALOG"
        assert pkg["included_units"] == int(source["included_units"])
        assert pkg["price_usd"] == float(source["price_usd"])


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — personal key (existing)
# ---------------------------------------------------------------------------


def test_purchase_starter_returns_201_with_correct_granted_units_and_price_usd(
    client: TestClient,
) -> None:
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_5000",
            "buyer_name": "Test Buyer",
            "buyer_email": "starter@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "ok"
    purchase = body["purchase"]
    assert purchase["package_id"] == "pkg_5000"
    assert purchase["granted_units"] == 5_000
    assert purchase["price_usd"] == 20.0
    assert purchase["token_coverage"] == 5_000 * TOKEN_CHUNK_SIZE
    assert purchase["tokens_per_unit"] == TOKEN_CHUNK_SIZE
    assert purchase["purchase_id"].startswith("purch_")
    assert body["wallet"]["balance_units"] == 5_000
    assert body["wallet"]["owner_key"] == "starter@ironclaw.test"


def test_purchase_team_returns_201_with_correct_granted_units_and_price_usd(
    client: TestClient,
) -> None:
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_25000",
            "buyer_name": "Team Buyer",
            "buyer_email": "team@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["granted_units"] == 25_000
    assert body["purchase"]["price_usd"] == 90.0
    assert body["wallet"]["balance_units"] == 25_000


def test_purchase_enterprise_returns_201_with_granted_units_60000_and_price_usd_180(
    client: TestClient,
) -> None:
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_60000",
            "buyer_name": "Enterprise Buyer",
            "buyer_email": "enterprise@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["granted_units"] == 60_000
    assert body["purchase"]["price_usd"] == 180.0
    assert body["wallet"]["balance_units"] == 60_000


def test_purchase_unknown_package_returns_404_not_500(client: TestClient) -> None:
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "enterprise-security",
            "buyer_name": "Ghost Buyer",
            "buyer_email": "ghost@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "enterprise-security" in detail


def test_purchase_completely_unknown_package_id_returns_404(client: TestClient) -> None:
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_does_not_exist",
            "buyer_name": "Nobody",
            "buyer_email": "nobody@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 404


def test_purchase_empty_package_id_returns_422(client: TestClient) -> None:
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "",
            "buyer_name": "Bad Buyer",
            "buyer_email": "bad@ironclaw.test",
            "metadata": {},
        },
    )
    assert resp.status_code == 422


def test_purchase_credits_wallet_correctly_after_purchase(client: TestClient) -> None:
    email = "credit-verify@ironclaw.test"
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_5000",
            "buyer_name": "Credit Verify",
            "buyer_email": email,
            "metadata": {},
        },
    )
    assert resp.status_code == 201
    wallet = resp.json()["wallet"]
    assert wallet["total_purchased_units"] == 5_000
    assert wallet["balance_units"] == 5_000
    assert wallet["total_consumed_units"] == 0


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — org key routing
# ---------------------------------------------------------------------------


def test_org_purchase_owner_key_is_ic_org_prefixed() -> None:
    org_id = "acme-corp"
    ctx = _make_org_ctx(org_id)
    with _override_auth(ctx) as client:
        resp = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Org Buyer",
                "buyer_email": "member@acme.com",
                "metadata": {},
            },
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["purchase"]["owner_key"] == f"ic_org_{org_id}"
    assert body["wallet"]["owner_key"] == f"ic_org_{org_id}"


def test_org_two_members_share_same_wallet_balance() -> None:
    org_id = "shared-org"
    ctx = _make_org_ctx(org_id)
    pkg_id = "pkg_5000"
    with _override_auth(ctx) as client:
        resp_a = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": pkg_id,
                "buyer_name": "Alice",
                "buyer_email": "alice@shared-org.com",
                "metadata": {},
            },
        )
        resp_b = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": pkg_id,
                "buyer_name": "Bob",
                "buyer_email": "bob@shared-org.com",
                "metadata": {},
            },
        )
    assert resp_a.status_code == 201
    assert resp_b.status_code == 201
    assert resp_a.json()["wallet"]["wallet_id"] == resp_b.json()["wallet"]["wallet_id"]
    assert resp_b.json()["wallet"]["balance_units"] == 10_000
    assert resp_b.json()["wallet"]["total_purchased_units"] == 10_000


def test_org_purchase_does_not_credit_buyer_email_wallet(
    _reset_wallet_registry,
) -> None:
    org_id = "isolated-org"
    buyer_email = "member@isolated-org.com"
    ctx = _make_org_ctx(org_id)
    with _override_auth(ctx) as client:
        client.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Member",
                "buyer_email": buyer_email,
                "metadata": {},
            },
        )
    registry = _unit_wallet_module._unit_wallet_registry
    email_wallet = registry.get_wallet(buyer_email)
    assert email_wallet is None or email_wallet.balance_units == 0


def test_org_and_personal_purchases_with_same_email_never_share_wallet() -> None:
    org_id = "split-org"
    shared_email = "shared@example.com"
    org_ctx = _make_org_ctx(org_id)
    personal_ctx = _make_personal_ctx()
    with _override_auth(org_ctx) as client:
        resp_org = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "OrgMember",
                "buyer_email": shared_email,
                "metadata": {},
            },
        )
    with _override_auth(personal_ctx) as client:
        resp_personal = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "PersonalUser",
                "buyer_email": shared_email,
                "metadata": {},
            },
        )
    assert resp_org.status_code == 201
    assert resp_personal.status_code == 201
    assert resp_org.json()["wallet"]["wallet_id"] != resp_personal.json()["wallet"]["wallet_id"]
    assert resp_org.json()["purchase"]["owner_key"] == f"ic_org_{org_id}"
    assert resp_personal.json()["purchase"]["owner_key"] == shared_email


def test_personal_purchase_owner_key_is_normalized_email() -> None:
    ctx = _make_personal_ctx()
    with _override_auth(ctx) as client:
        resp = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Dev",
                "buyer_email": "Dev@IronClaw.IO",
                "metadata": {},
            },
        )
    assert resp.status_code == 201
    assert resp.json()["purchase"]["owner_key"] == "dev@ironclaw.io"
    assert resp.json()["wallet"]["owner_key"] == "dev@ironclaw.io"
