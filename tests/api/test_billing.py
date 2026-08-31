from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.billing import (
    router,
)
from app.core.auth import AuthContext, require_auth_context
from app.core.install_keys import InstallKeyRecord
from app.core.unit_wallet import TOKEN_CHUNK_SIZE, UNIT_PACKAGE_CATALOG, get_unit_wallet_registry

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

_APP = FastAPI()
_APP.include_router(router)


def _client_for(auth_ctx: AuthContext) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_auth_context] = lambda: auth_ctx
    return TestClient(app, raise_server_exceptions=False)


_PERSONAL_AUTH = AuthContext(
    api_key="test-api-key",
    principal_type="api_key",
    principal_id="user-123",
    session_id=None,
    org_id=None,
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="personal",
)

_ORG_AUTH = AuthContext(
    api_key="test-org-key",
    principal_type="org_key",
    principal_id="org-123",
    session_id=None,
    org_id="org-123",
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="org",
)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(_APP, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _reset_wallet_state() -> None:
    registry = get_unit_wallet_registry()
    registry._wallets.clear()
    registry._wallets_by_owner.clear()
    registry._repo._wallets.clear()
    registry._repo._ledger.clear()


def _body(payload: dict[str, object]) -> dict[str, object]:
    return payload


def test_list_billing_packages() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        response = c.get("/billing/packages")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "IronClaw-Security"
    assert len(body["packages"]) >= 3
    assert body["unit_policy"]["token_chunk_size"] == TOKEN_CHUNK_SIZE
    assert {pkg["package_id"] for pkg in body["packages"]} == set(UNIT_PACKAGE_CATALOG)


def test_purchase_billing_package_creates_pending_purchase_without_crediting_wallet() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        response = c.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Alice Buyer",
                "buyer_email": "alice@example.com",
                "metadata": {"source": "test"},
            },
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "ok"
    purchase = payload["purchase"]
    assert purchase["package_id"] == "pkg_5000"
    assert purchase["buyer_email"] == "alice@example.com"
    assert purchase["granted_units"] == 0
    assert purchase["payment_status"] == "pending"
    assert purchase["entitlement_status"] == "not_active"
    assert purchase["install_key_id"] is None
    assert purchase["masked_key"] is None
    assert purchase["program"] is None
    wallet = payload["wallet"]
    assert wallet["owner_key"] == "alice@example.com"
    assert wallet["balance_units"] == 0


def test_purchase_rejects_visible_system_owner_key() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        with patch("app.api.billing.resolve_billing_owner", return_value="ironclaw-system"):
            response = c.post(
                "/billing/packages/purchase",
                json={
                    "package_id": "pkg_5000",
                    "buyer_name": "System Buyer",
                    "buyer_email": "system@example.com",
                    "metadata": {},
                },
            )

    assert response.status_code == 400
    body = response.json()
    assert body["detail"]["reason"] == "purchase_checkout_must_not_resolve_to_visible_system_key"


def test_fulfill_purchase_can_issue_install_key_after_successful_payment() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        create = c.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Paid Buyer",
                "buyer_email": "paid@example.com",
                "metadata": {},
            },
        )
        purchase_id = create.json()["purchase"]["purchase_id"]

        mock_registry = MagicMock()
        mock_registry.get_keys_for_owner.return_value = []
        openclaw_record = InstallKeyRecord(
            key_id="ik_test_123",
            owner_key="paid@example.com",
            subscription_id=purchase_id,
            program="openclaw",
            raw_key="ic_install_openclaw_1A2B3C4D5E6F7G8H9J",
            raw_key_hash="abc123",
            masked_key="ic_install_openclaw_...9J",
            label="paid-provisioned",
            active=True,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            metadata={"purchase_id": purchase_id, "auto_provisioned": True},
        )
        hermes_record = InstallKeyRecord(
            key_id="ik_hermes_456",
            owner_key="paid@example.com",
            subscription_id=purchase_id,
            program="hermes",
            raw_key="ic_install_hermes_1A2B3C4D5E6F7G8H9J",
            raw_key_hash="def456",
            masked_key="ic_install_hermes_...9J",
            label="hermes-provisioned",
            active=True,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            metadata={"purchase_id": purchase_id, "auto_provisioned": True},
        )
        mock_registry.generate_install_key.side_effect = [openclaw_record, hermes_record]

        with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
            fulfill = c.post(
                f"/billing/packages/{purchase_id}/fulfill",
                params={"payment_id": "pay_123", "payment_status": "paid", "entitlement_status": "active"},
            )

    assert fulfill.status_code == 200
    body = fulfill.json()
    payment = body["purchase"]
    assert payment["payment_id"] == "pay_123"
    assert payment["entitlement_status"] == "active"
    assert payment["install_key_id"] == "ik_hermes_456"
    assert payment["masked_key"] == "ic_install_hermes_...9J"
    assert payment["program"] == "hermes"
    assert payment["openclaw_install_key"] == "ic_install_openclaw_...9J"
    assert payment["hermes_install_key"] == "ic_install_hermes_...9J"
    assert payment["usage_summary"]["program"] == "hermes"
    assert payment["usage_summary"]["entitlement_status"] == "active"
    assert payment["metadata"]["install_keys_provisioned"] is True
    assert body["wallet"]["owner_key"] == "paid@example.com"
    assert body["wallet"]["balance_units"] == 5000


def test_fulfill_purchase_skips_install_key_before_payment_confirmation() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        create = c.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Unpaid Buyer",
                "buyer_email": "unpaid@example.com",
                "metadata": {},
            },
        )
        purchase_id = create.json()["purchase"]["purchase_id"]

        mock_registry = MagicMock()
        mock_registry.get_keys_for_owner.return_value = []

        with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
            fulfill = c.post(
                f"/billing/packages/{purchase_id}/fulfill",
                params={"payment_id": "pay_456", "payment_status": "pending", "entitlement_status": "not_active"},
            )

    assert fulfill.status_code == 200
    body = fulfill.json()
    purchase = body["purchase"]
    assert purchase["payment_status"] == "pending"
    assert purchase["entitlement_status"] == "not_active"
    assert purchase["install_key_id"] is None
    assert purchase["masked_key"] is None
    assert purchase["metadata"]["install_keys_provisioned"] is False
    assert body["wallet"]["owner_key"] == "unpaid@example.com"
    assert body["wallet"]["balance_units"] == 0
    mock_registry.generate_install_key.assert_not_called()


def test_fulfill_purchase_requires_confirmed_payment_and_active_entitlement() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        create = c.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Fulfillment Buyer",
                "buyer_email": "fulfillment@example.com",
                "metadata": {},
            },
        )
        purchase_id = create.json()["purchase"]["purchase_id"]

        mock_registry = MagicMock()
        mock_registry.get_keys_for_owner.return_value = []

        with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
            fulfill = c.post(
                f"/billing/packages/{purchase_id}/fulfill",
            )

    assert fulfill.status_code == 200
    body = fulfill.json()
    purchase = body["purchase"]
    assert purchase["payment_status"] == "pending"
    assert purchase["entitlement_status"] == "not_active"
    assert purchase["install_key_id"] is None
    assert purchase["masked_key"] is None
    assert purchase["usage_summary"] == {}
    assert body["wallet"]["owner_key"] == "fulfillment@example.com"
    assert body["wallet"]["balance_units"] == 0
    mock_registry.generate_install_key.assert_not_called()


def test_fulfill_purchase_rejects_generic_platform_api_key_context() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        create = c.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Platform Buyer",
                "buyer_email": "customer@example.com",
                "metadata": {},
            },
        )
        purchase_id = create.json()["purchase"]["purchase_id"]

    platform_auth = AuthContext(
        api_key="platform-api-key",
        principal_type="platform",
        principal_id="platform-123",
        session_id=None,
        org_id=None,
        authenticated=True,
        auth_source="configured",
        auth_method="api_key",
        key_type="platform",
    )

    with _client_for(platform_auth) as c:
        mock_registry = MagicMock()
        mock_registry.get_keys_for_owner.return_value = []

        with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
            fulfill = c.post(
                f"/billing/packages/{purchase_id}/fulfill",
                params={"payment_id": "pay_platform_123", "payment_status": "paid", "entitlement_status": "active"},
            )

    assert fulfill.status_code == 403
    body = fulfill.json()
    assert body["detail"]["reason"] == "install_key_requires_customer_owner_context"
    assert body["detail"]["owner_key"] == "customer@example.com"
    mock_registry.generate_install_key.assert_not_called()


def test_wallet_debit_requires_units_or_tokens() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        response = c.post(
            "/billing/wallet/alice@example.com/debit",
            json={"reason": "test"},
        )

    assert response.status_code == 422


def test_wallet_debit_for_units_reduces_balance_and_returns_wallet() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(owner_key="alice@example.com", units=1000)

    with _client_for(_PERSONAL_AUTH) as c:
        response = c.post(
            "/billing/wallet/alice@example.com/debit",
            json={"units": 300, "reason": "usage"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["owner_key"] == "alice@example.com"
    assert payload["units_debited"] == 300
    assert payload["wallet"]["balance_units"] == 700


def test_wallet_debit_for_tokens_converts_to_units() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(owner_key="alice@example.com", units=100000)

    with _client_for(_PERSONAL_AUTH) as c:
        response = c.post(
            "/billing/wallet/alice@example.com/debit",
            json={"token_count": 125000, "reason": "token-usage"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["token_count"] == 125000
    assert payload["units_debited"] == 5
    assert payload["wallet"]["balance_units"] == 99995


def test_wallet_refund_recredits_units() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(owner_key="alice@example.com", units=100)

    with _client_for(_PERSONAL_AUTH) as c:
        response = c.post(
            "/billing/wallet/alice@example.com/refund",
            json={"units": 25, "reason": "adjustment"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["units_refunded"] == 25
    assert payload["wallet"]["balance_units"] == 125


def test_get_wallet_and_ledger_work_for_personal_owner() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(owner_key="alice@example.com", units=250)

    with _client_for(_PERSONAL_AUTH) as c:
        wallet = c.get("/billing/wallet/alice@example.com")
        ledger = c.get("/billing/ledger", params={"owner_key": "alice@example.com", "limit": 10})

    assert wallet.status_code == 200
    assert wallet.json()["wallet"]["balance_units"] == 250
    assert ledger.status_code == 200
    assert ledger.json()["owner_key"] == "alice@example.com"
    assert len(ledger.json()["entries"]) >= 1


def test_org_wallet_access_requires_org_key_and_matches_org_owner() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(owner_key="ic_org_org-123", units=500)

    with _client_for(_ORG_AUTH) as c:
        wallet = c.get("/billing/wallet/ic_org_org-123")
        deny = c.get("/billing/wallet/ic_org_other-org")

    assert wallet.status_code == 200
    assert wallet.json()["wallet"]["owner_key"] == "ic_org_org-123"
    assert deny.status_code == 403


def test_org_key_cannot_access_personal_wallet() -> None:
    with _client_for(_ORG_AUTH) as c:
        response = c.get("/billing/wallet/alice@example.com")

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "org_key_cannot_access_personal_wallet"


def test_ledger_requires_org_key_for_org_wallet() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        response = c.get("/billing/ledger", params={"owner_key": "ic_org_org-123", "limit": 10})

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "org_wallet_requires_org_key"


def test_invalid_buyer_email_is_rejected() -> None:
    with _client_for(_PERSONAL_AUTH) as c:
        response = c.post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "Bad Email",
                "buyer_email": "not_an_email",
                "metadata": {},
            },
        )

    assert response.status_code == 422


def test_package_catalog_is_known_for_all_supported_packages() -> None:
    assert "pkg_5000" in UNIT_PACKAGE_CATALOG
    assert "pkg_25000" in UNIT_PACKAGE_CATALOG
    assert "pkg_60000" in UNIT_PACKAGE_CATALOG
    for pkg_id, pkg in UNIT_PACKAGE_CATALOG.items():
        assert pkg["package_id"] == pkg_id
        assert int(pkg["unit_amount"]) > 0
        assert float(pkg["price_usd"]) > 0
        assert pkg["tokens_per_unit"] == TOKEN_CHUNK_SIZE
