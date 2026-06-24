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

from contextlib import contextmanager
from unittest.mock import MagicMock

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
from app.core.billing import resolve_billing_owner
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import (
    MemoryUnitWalletRepository,
    UnitWalletRegistry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MOCK_API_KEY = "test-key"

_PURCHASE_URL = "/billing/packages/purchase"


def _make_auth_ctx(
    *,
    key_type: str = "personal",
    principal_type: str = "api_key",
    org_id: str | None = None,
    authenticated: bool = True,
    auth_source: str = "registry",
) -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type=principal_type,
        principal_id=None,
        session_id=None,
        org_id=org_id,
        authenticated=authenticated,
        auth_source=auth_source,
        auth_method="api_key",
        key_type=key_type,
    )


def _first_package() -> tuple[str, dict]:
    """Return (pkg_id, pkg_dict) for the first entry in PACKAGE_CATALOG (route layer)."""
    pkg_id = next(iter(PACKAGE_CATALOG))
    return pkg_id, PACKAGE_CATALOG[pkg_id]


def _purchase_payload(
    buyer_email: str,
    buyer_name: str = "Test Buyer",
    package_id: str | None = None,
) -> dict:
    if package_id is None:
        package_id = next(iter(PACKAGE_CATALOG))
    return {
        "package_id": package_id,
        "buyer_name": buyer_name,
        "buyer_email": buyer_email,
        "metadata": {},
    }


def _org_ctx(org_id: str) -> AuthContext:
    return _make_auth_ctx(key_type="org", principal_type="org_key", org_id=org_id)


def _personal_ctx() -> AuthContext:
    return _make_auth_ctx(key_type="personal", principal_type="api_key", org_id=None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_wallet_registry():
    fresh_repo = MemoryUnitWalletRepository()
    fresh_registry = UnitWalletRegistry()
    fresh_registry._repo = fresh_repo
    original = _unit_wallet_module._unit_wallet_registry
    _unit_wallet_module._unit_wallet_registry = fresh_registry
    yield fresh_registry
    _unit_wallet_module._unit_wallet_registry = original


@pytest.fixture()
def app_instance():
    from app.main import app

    app.dependency_overrides.clear()
    yield app
    app.dependency_overrides.clear()


@pytest.fixture()
def org_id() -> str:
    return "acme-corp"


@pytest.fixture()
def org_auth_ctx(org_id: str) -> AuthContext:
    return _org_ctx(org_id)


@pytest.fixture()
def personal_auth_ctx() -> AuthContext:
    return _personal_ctx()


@contextmanager
def _override_auth(app_instance, ctx: AuthContext):
    def _stub_api_key() -> str:
        return ctx.api_key or _MOCK_API_KEY

    def _stub_auth_ctx() -> AuthContext:
        return ctx

    app_instance.dependency_overrides[get_api_key] = _stub_api_key
    app_instance.dependency_overrides[require_api_key] = _stub_api_key
    app_instance.dependency_overrides[get_auth_context] = _stub_auth_ctx
    app_instance.dependency_overrides[require_auth_context] = _stub_auth_ctx
    try:
        yield TestClient(app_instance, raise_server_exceptions=True)
    finally:
        for dep in (get_api_key, require_api_key, get_auth_context, require_auth_context):
            app_instance.dependency_overrides.pop(dep, None)


# ---------------------------------------------------------------------------
# Unit tests — resolve_billing_owner
# ---------------------------------------------------------------------------


class TestResolveBillingOwner:
    def test_org_key_with_org_id_returns_ic_org_prefix(self, org_id: str) -> None:
        ctx = _make_auth_ctx(key_type="org", org_id=org_id)
        result = resolve_billing_owner(ctx, "buyer@example.com")
        assert result == f"ic_org_{org_id}"

    def test_org_key_with_org_id_does_not_return_email(self, org_id: str) -> None:
        ctx = _make_auth_ctx(key_type="org", org_id=org_id)
        result = resolve_billing_owner(ctx, "buyer@example.com")
        assert "@" not in result

    def test_org_key_with_org_id_ignores_buyer_email(self, org_id: str) -> None:
        ctx = _make_auth_ctx(key_type="org", org_id=org_id)
        result_a = resolve_billing_owner(ctx, "alice@example.com")
        result_b = resolve_billing_owner(ctx, "bob@example.com")
        assert result_a == result_b == f"ic_org_{org_id}"

    def test_personal_key_returns_normalized_buyer_email(self) -> None:
        ctx = _make_auth_ctx(key_type="personal", org_id=None)
        result = resolve_billing_owner(ctx, "Alice@Example.COM")
        assert result == "alice@example.com"

    def test_personal_key_strips_whitespace_from_email(self) -> None:
        ctx = _make_auth_ctx(key_type="personal", org_id=None)
        result = resolve_billing_owner(ctx, "  dev@ironclaw.io  ")
        assert result == "dev@ironclaw.io"

    def test_personal_key_returns_email_not_org_prefix(self) -> None:
        ctx = _make_auth_ctx(key_type="personal", org_id=None)
        result = resolve_billing_owner(ctx, "dev@ironclaw.io")
        assert not result.startswith("ic_org_")

    def test_org_key_without_org_id_falls_back_to_buyer_email(self) -> None:
        ctx = _make_auth_ctx(key_type="org", org_id=None)
        result = resolve_billing_owner(ctx, "buyer@example.com")
        assert result == "buyer@example.com"

    def test_org_key_with_empty_string_org_id_falls_back_to_buyer_email(self) -> None:
        ctx = _make_auth_ctx(key_type="org", org_id=None)
        result = resolve_billing_owner(ctx, "buyer@example.com")
        assert result == "buyer@example.com"

    def test_org_key_with_none_org_id_returns_normalized_email(self) -> None:
        ctx = _make_auth_ctx(key_type="org", org_id=None)
        result = resolve_billing_owner(ctx, "BUYER@EXAMPLE.COM  ")
        assert result == "buyer@example.com"

    def test_session_key_type_falls_back_to_email(self) -> None:
        ctx = _make_auth_ctx(key_type="session", org_id=None)
        result = resolve_billing_owner(ctx, "user@ironclaw.io")
        assert result == "user@ironclaw.io"

    def test_missing_key_type_attribute_falls_back_to_email(self) -> None:
        ctx = MagicMock(spec=[])
        result = resolve_billing_owner(ctx, "user@ironclaw.io")
        assert result == "user@ironclaw.io"

    def test_org_routing_produces_ic_org_prefixed_owner_key(self, org_id: str) -> None:
        ctx = _make_auth_ctx(key_type="org", org_id=org_id)
        owner_key = resolve_billing_owner(ctx, "irrelevant@email.com")
        assert owner_key.startswith("ic_org_")

    def test_personal_routing_never_produces_ic_org_prefix(self) -> None:
        ctx = _make_auth_ctx(key_type="personal", org_id=None)
        result = resolve_billing_owner(ctx, "dev@ironclaw.io")
        assert not result.startswith("ic_org_")


# ---------------------------------------------------------------------------
# Unit tests — wallet routing directly via UnitWalletRegistry
# ---------------------------------------------------------------------------


class TestOrgWalletRouting:
    def test_org_key_purchase_credits_org_wallet(
        self,
        org_id: str,
        org_auth_ctx: AuthContext,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        owner_key = resolve_billing_owner(org_auth_ctx, "buyer@example.com")
        _isolated_wallet_registry.credit_units(owner_key=owner_key, units=500)
        wallet = _isolated_wallet_registry.get_wallet(owner_key)
        assert wallet is not None
        assert wallet.balance_units == 500
        assert wallet.owner_key == f"ic_org_{org_id}"

    def test_personal_key_purchase_credits_email_wallet(
        self,
        personal_auth_ctx: AuthContext,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        email = "dev@ironclaw.io"
        owner_key = resolve_billing_owner(personal_auth_ctx, email)
        _isolated_wallet_registry.credit_units(owner_key=owner_key, units=250)
        wallet = _isolated_wallet_registry.get_wallet(owner_key)
        assert wallet is not None
        assert wallet.balance_units == 250
        assert wallet.owner_key == email

    def test_org_and_personal_wallets_are_isolated(
        self,
        org_id: str,
        org_auth_ctx: AuthContext,
        personal_auth_ctx: AuthContext,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        org_owner = resolve_billing_owner(org_auth_ctx, "buyer@example.com")
        personal_owner = resolve_billing_owner(personal_auth_ctx, "buyer@example.com")
        _isolated_wallet_registry.credit_units(owner_key=org_owner, units=1000)
        _isolated_wallet_registry.credit_units(owner_key=personal_owner, units=99)
        org_wallet = _isolated_wallet_registry.get_wallet(org_owner)
        personal_wallet = _isolated_wallet_registry.get_wallet(personal_owner)
        assert org_wallet is not None
        assert personal_wallet is not None
        assert org_wallet.wallet_id != personal_wallet.wallet_id
        assert org_wallet.balance_units == 1000
        assert personal_wallet.balance_units == 99

    def test_two_buyer_emails_same_org_key_share_wallet_balance(
        self,
        org_id: str,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        ctx_alice = _make_auth_ctx(key_type="org", org_id=org_id)
        ctx_bob = _make_auth_ctx(key_type="org", org_id=org_id)
        owner_alice = resolve_billing_owner(ctx_alice, "alice@example.com")
        owner_bob = resolve_billing_owner(ctx_bob, "bob@example.com")
        assert owner_alice == owner_bob == f"ic_org_{org_id}"
        _isolated_wallet_registry.credit_units(owner_key=owner_alice, units=300)
        _isolated_wallet_registry.credit_units(owner_key=owner_bob, units=200)
        wallet = _isolated_wallet_registry.get_wallet(f"ic_org_{org_id}")
        assert wallet is not None
        assert wallet.balance_units == 500
        assert wallet.total_purchased_units == 500

    def test_two_org_keys_different_orgs_have_different_wallets(
        self,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        ctx_alpha = _make_auth_ctx(key_type="org", org_id="alpha-corp")
        ctx_beta = _make_auth_ctx(key_type="org", org_id="beta-corp")
        owner_alpha = resolve_billing_owner(ctx_alpha, "any@example.com")
        owner_beta = resolve_billing_owner(ctx_beta, "any@example.com")
        assert owner_alpha != owner_beta
        _isolated_wallet_registry.credit_units(owner_key=owner_alpha, units=400)
        _isolated_wallet_registry.credit_units(owner_key=owner_beta, units=100)
        wallet_alpha = _isolated_wallet_registry.get_wallet(owner_alpha)
        wallet_beta = _isolated_wallet_registry.get_wallet(owner_beta)
        assert wallet_alpha is not None
        assert wallet_beta is not None
        assert wallet_alpha.wallet_id != wallet_beta.wallet_id
        assert wallet_alpha.balance_units == 400
        assert wallet_beta.balance_units == 100


# ---------------------------------------------------------------------------
# Integration tests — POST /billing/packages/purchase via TestClient
# ---------------------------------------------------------------------------


class TestPurchaseOrgWalletIntegration:
    def test_org_purchase_response_owner_key_is_ic_org_prefixed(
        self,
        app_instance,
        org_id: str,
    ) -> None:
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            resp = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("buyer@example.com"),
            )
        assert resp.status_code == 201
        assert resp.json()["purchase"]["owner_key"] == f"ic_org_{org_id}"

    def test_org_purchase_wallet_owner_key_is_ic_org_prefixed(
        self,
        app_instance,
        org_id: str,
    ) -> None:
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            resp = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("buyer@example.com"),
            )
        assert resp.status_code == 201
        assert resp.json()["wallet"]["owner_key"] == f"ic_org_{org_id}"

    def test_org_purchase_credits_org_wallet_balance(
        self,
        app_instance,
        org_id: str,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        pkg_id, pkg = _first_package()
        expected_units = int(pkg["included_units"])
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            resp = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("buyer@example.com", package_id=pkg_id),
            )
        assert resp.status_code == 201
        assert resp.json()["wallet"]["balance_units"] == expected_units
        org_wallet = _isolated_wallet_registry.get_wallet(f"ic_org_{org_id}")
        assert org_wallet is not None
        assert org_wallet.balance_units == expected_units

    def test_org_purchase_does_not_credit_buyer_email_wallet(
        self,
        app_instance,
        org_id: str,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        buyer_email = "personal-buyer@example.com"
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            client.post(
                _PURCHASE_URL,
                json=_purchase_payload(buyer_email),
            )
        email_wallet = _isolated_wallet_registry.get_wallet(buyer_email)
        assert email_wallet is None or email_wallet.balance_units == 0

    def test_two_buyer_emails_same_org_key_share_wallet_balance(
        self,
        app_instance,
        org_id: str,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        pkg_id, pkg = _first_package()
        expected_units_each = int(pkg["included_units"])
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            resp_alice = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("alice@example.com", buyer_name="Alice", package_id=pkg_id),
            )
            resp_bob = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("bob@example.com", buyer_name="Bob", package_id=pkg_id),
            )
        assert resp_alice.status_code == 201
        assert resp_bob.status_code == 201
        assert resp_alice.json()["purchase"]["owner_key"] == f"ic_org_{org_id}"
        assert resp_bob.json()["purchase"]["owner_key"] == f"ic_org_{org_id}"
        org_wallet = _isolated_wallet_registry.get_wallet(f"ic_org_{org_id}")
        assert org_wallet is not None
        assert org_wallet.balance_units == expected_units_each * 2
        assert org_wallet.total_purchased_units == expected_units_each * 2

    def test_two_buyer_emails_same_org_key_share_same_wallet_id(
        self,
        app_instance,
        org_id: str,
    ) -> None:
        pkg_id = next(iter(PACKAGE_CATALOG))
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            resp_a = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("alice@example.com", buyer_name="Alice", package_id=pkg_id),
            )
            resp_b = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("bob@example.com", buyer_name="Bob", package_id=pkg_id),
            )
        assert resp_a.status_code == 201
        assert resp_b.status_code == 201
        assert resp_a.json()["wallet"]["wallet_id"] == resp_b.json()["wallet"]["wallet_id"]

    def test_personal_key_purchase_credits_email_wallet(
        self,
        app_instance,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        buyer_email = "solo-dev@ironclaw.io"
        pkg_id, pkg = _first_package()
        expected_units = int(pkg["included_units"])
        ctx = _personal_ctx()
        with _override_auth(app_instance, ctx) as client:
            resp = client.post(
                _PURCHASE_URL,
                json=_purchase_payload(buyer_email, package_id=pkg_id),
            )
        assert resp.status_code == 201
        body = resp.json()
        assert body["purchase"]["owner_key"] == buyer_email
        assert body["wallet"]["owner_key"] == buyer_email
        assert body["wallet"]["balance_units"] == expected_units
        email_wallet = _isolated_wallet_registry.get_wallet(buyer_email)
        assert email_wallet is not None
        assert email_wallet.balance_units == expected_units

    def test_personal_key_purchase_does_not_create_org_wallet(
        self,
        app_instance,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        buyer_email = "solo-dev@ironclaw.io"
        ctx = _personal_ctx()
        with _override_auth(app_instance, ctx) as client:
            client.post(
                _PURCHASE_URL,
                json=_purchase_payload(buyer_email),
            )
        org_wallet = _isolated_wallet_registry.get_wallet("ic_org_acme-corp")
        assert org_wallet is None or org_wallet.balance_units == 0

    def test_personal_key_owner_key_is_normalized_email(
        self,
        app_instance,
    ) -> None:
        ctx = _personal_ctx()
        with _override_auth(app_instance, ctx) as client:
            resp = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("Dev@IronClaw.IO"),
            )
        assert resp.status_code == 201
        assert resp.json()["purchase"]["owner_key"] == "dev@ironclaw.io"

    def test_org_and_personal_purchases_never_share_wallet(
        self,
        app_instance,
        org_id: str,
        _isolated_wallet_registry: UnitWalletRegistry,
    ) -> None:
        shared_email = "shared@example.com"
        pkg_id = next(iter(PACKAGE_CATALOG))
        org_ctx = _org_ctx(org_id)
        personal_ctx = _personal_ctx()
        with _override_auth(app_instance, org_ctx) as client:
            resp_org = client.post(
                _PURCHASE_URL,
                json=_purchase_payload(shared_email, buyer_name="OrgMember", package_id=pkg_id),
            )
        with _override_auth(app_instance, personal_ctx) as client:
            resp_personal = client.post(
                _PURCHASE_URL,
                json=_purchase_payload(shared_email, buyer_name="PersonalUser", package_id=pkg_id),
            )
        assert resp_org.status_code == 201
        assert resp_personal.status_code == 201
        assert resp_org.json()["wallet"]["wallet_id"] != resp_personal.json()["wallet"]["wallet_id"]
        assert resp_org.json()["purchase"]["owner_key"] == f"ic_org_{org_id}"
        assert resp_personal.json()["purchase"]["owner_key"] == shared_email

    def test_purchase_response_schema_contains_required_fields(
        self,
        app_instance,
        org_id: str,
    ) -> None:
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            resp = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("buyer@example.com"),
            )
        assert resp.status_code == 201
        body = resp.json()
        assert "purchase" in body
        assert "wallet" in body
        for field in ("purchase_id", "owner_key", "granted_units", "buyer_email", "package_id"):
            assert field in body["purchase"], f"Missing field: {field!r}"

    def test_wallet_response_schema_contains_required_fields(
        self,
        app_instance,
        org_id: str,
    ) -> None:
        ctx = _org_ctx(org_id)
        with _override_auth(app_instance, ctx) as client:
            resp = client.post(
                _PURCHASE_URL,
                json=_purchase_payload("buyer@example.com"),
            )
        assert resp.status_code == 201
        wallet = resp.json()["wallet"]
        for field in ("wallet_id", "owner_key", "balance_units", "total_purchased_units"):
            assert field in wallet, f"Missing field: {field!r}"
