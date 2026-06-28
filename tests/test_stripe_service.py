from __future__ import annotations

from collections.abc import Generator
import hashlib
import hmac as _hmac
import json
import math
import os
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from app.services.stripe_service import (
    PACKAGE_CATALOGUE,
    CheckoutSessionResponse,
    InvoiceResponse,
    PaymentMethodResponse,
    StripeAPIError,
    StripeBillingInterval,
    StripeCheckoutMode,
    StripeConfigError,
    StripeIdempotencyError,
    StripeInsufficientUnitsError,
    StripePaymentMethodNotFoundError,
    StripeService,
    StripeServiceError,
    StripeSessionNotFoundError,
    StripeSubscriptionNotFoundError,
    StripeSubscriptionStatus,
    StripeUnitEventReason,
    StripeWebhookEventType,
    StripeWebhookSignatureError,
    SubscriptionResponse,
    UnitBalanceResponse,
    WebhookVerifyResult,
    _new_id,
    _StripeHTTPClient,
    _utcnow_iso,
    get_stripe_service,
    reset_stripe_service,
    units_for_tokens,
)
from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
    TOKENS_PER_UNIT,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_ORG = "org-test-stripe-001"
_TEST_ORG_2 = "org-test-stripe-002"
_TEST_PRICE_ID = "price_test_abc123"
_TEST_SUCCESS_URL = "https://example.com/success"
_TEST_CANCEL_URL = "https://example.com/cancel"
_TEST_CUSTOMER_ID = "cus_test_abc123"
_TEST_CUSTOMER_ID_2 = "cus_test_def456"
_TEST_SUB_ID = "sub_test_abc123"
_TEST_SESSION_ID = "cs_test_abc123"
_TEST_WEBHOOK_SECRET = "whsec_testsecret1234567890abcdefghij"
_TEST_API_KEY = "sk_test_ironclaw_key_abc123456789"
_TEST_PM_ID = "pm_test_abc123"
_TEST_PM_ID_2 = "pm_test_def456"

# ---------------------------------------------------------------------------
# Package catalogue test constants — derived from supabaseclient single source
# of truth so test assertions never drift from production values.
# starter    :  5,000 units → $20 USD
# team       : 25,000 units → $90 USD
# enterprise : 60,000 units → $180 USD
# Each unit covers up to TOKENS_PER_UNIT (25,000) tokens.
# ---------------------------------------------------------------------------

_PKG_STARTER_UNITS: int = BILLING_TIER_5K_UNITS  # 5_000
_PKG_STARTER_PRICE_USD: int = BILLING_TIER_5K_PRICE_USD  # 20
_PKG_STARTER_PRICE_CENTS: int = BILLING_TIER_5K_PRICE_USD * 100  # 2_000

_PKG_TEAM_UNITS: int = BILLING_TIER_25K_UNITS  # 25_000
_PKG_TEAM_PRICE_USD: int = BILLING_TIER_25K_PRICE_USD  # 90
_PKG_TEAM_PRICE_CENTS: int = BILLING_TIER_25K_PRICE_USD * 100  # 9_000

_PKG_ENTERPRISE_UNITS: int = BILLING_TIER_60K_UNITS  # 60_000
_PKG_ENTERPRISE_PRICE_USD: int = BILLING_TIER_60K_PRICE_USD  # 180
_PKG_ENTERPRISE_PRICE_CENTS: int = BILLING_TIER_60K_PRICE_USD * 100  # 18_000

_TOKENS_PER_UNIT: int = TOKENS_PER_UNIT  # 25_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_stripe_sig(secret: str, payload: bytes, timestamp: int | None = None) -> str:
    ts = timestamp if timestamp is not None else int(time.time())
    signed = f"{ts}.".encode() + payload
    sig = _hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _mock_session_resp(
    session_id: str = _TEST_SESSION_ID,
    url: str = "https://checkout.stripe.com/pay/test",
    customer_id: str = _TEST_CUSTOMER_ID,
    expires_at: int | None = None,
) -> dict[str, Any]:
    return {
        "id": session_id,
        "url": url,
        "customer": customer_id,
        "expires_at": expires_at or int(time.time()) + 1800,
    }


def _mock_subscription_obj(
    sub_id: str = _TEST_SUB_ID,
    customer_id: str = _TEST_CUSTOMER_ID,
    status: str = "active",
    price_id: str = _TEST_PRICE_ID,
    interval: str = "month",
    cancel_at_period_end: bool = False,
    org_id: str = _TEST_ORG,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "id": sub_id,
        "customer": customer_id,
        "status": status,
        "cancel_at_period_end": cancel_at_period_end,
        "current_period_start": now,
        "current_period_end": now + 2592000,
        "metadata": {"org_id": org_id},
        "items": {
            "data": [
                {
                    "price": {"id": price_id, "recurring": {"usage_type": "licensed"}},
                    "plan": {"interval": interval, "id": price_id},
                }
            ]
        },
    }


def _mock_pm_resp(
    pm_id: str = _TEST_PM_ID,
    customer_id: str = _TEST_CUSTOMER_ID,
    brand: str = "visa",
    last4: str = "4242",
    exp_month: int = 12,
    exp_year: int = 2030,
) -> dict[str, Any]:
    return {
        "id": pm_id,
        "type": "card",
        "customer": customer_id,
        "card": {
            "brand": brand,
            "last4": last4,
            "exp_month": exp_month,
            "exp_year": exp_year,
        },
    }


def _mock_invoice_list(
    customer_id: str = _TEST_CUSTOMER_ID,
    count: int = 2,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "data": [
            {
                "id": f"in_test_{i}",
                "customer": customer_id,
                "subscription": _TEST_SUB_ID,
                "amount_paid": 2000,
                "currency": "usd",
                "status": "paid",
                "invoice_pdf": f"https://stripe.com/invoice_{i}.pdf",
                "hosted_invoice_url": f"https://invoice.stripe.com/{i}",
                "created": now - (i * 86400),
            }
            for i in range(count)
        ]
    }


def _make_payment_intent_obj(
    pi_id: str = "pi_test_001",
    customer_id: str = _TEST_CUSTOMER_ID,
    amount: int = 2000,
    currency: str = "usd",
    status: str = "succeeded",
    org_id: str = _TEST_ORG,
) -> dict[str, Any]:
    return {
        "id": pi_id,
        "customer": customer_id,
        "amount": amount,
        "currency": currency,
        "status": status,
        "metadata": {"org_id": org_id},
    }


def _make_charge_refunded_obj(
    charge_id: str = "ch_refund_1",
    customer_id: str = _TEST_CUSTOMER_ID,
    org_id: str = _TEST_ORG,
    unit_credits: int = _PKG_STARTER_UNITS,  # type: ignore[assignment]
) -> dict[str, Any]:
    return {
        "id": charge_id,
        "customer": customer_id,
        "metadata": {"unit_credits": str(unit_credits), "org_id": org_id},
    }


def _make_invoice_upcoming_obj(
    invoice_id: str = "in_upcoming_1",
    customer_id: str = _TEST_CUSTOMER_ID,
    subscription_id: str = _TEST_SUB_ID,
    amount_due: int = 9000,
) -> dict[str, Any]:
    return {
        "id": invoice_id,
        "customer": customer_id,
        "subscription": subscription_id,
        "amount_due": amount_due,
        "currency": "usd",
    }


def _make_customer_updated_obj(
    customer_id: str = _TEST_CUSTOMER_ID,
    org_id: str = _TEST_ORG,
    email: str = "updated@example.com",
) -> dict[str, Any]:
    return {
        "id": customer_id,
        "email": email,
        "metadata": {"org_id": org_id},
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_service() -> Generator[None, None, None]:
    reset_stripe_service()
    yield
    reset_stripe_service()


@pytest.fixture()
def svc() -> StripeService:
    return StripeService()


@pytest.fixture()
def mock_client() -> MagicMock:
    return MagicMock(spec=_StripeHTTPClient)


@pytest.fixture()
def svc_with_client(svc: StripeService, mock_client: MagicMock) -> StripeService:
    svc._override_client(mock_client)
    return svc


# ===========================================================================
# Section 1 — Utility helpers
# ===========================================================================


class TestUtilityHelpers:
    def test_utcnow_iso_format(self) -> None:
        ts = _utcnow_iso()
        assert ts.endswith("Z")
        assert "T" in ts

    def test_utcnow_iso_monotonic(self) -> None:
        t1 = _utcnow_iso()
        time.sleep(0.01)
        t2 = _utcnow_iso()
        assert t2 >= t1

    def test_new_id_prefix(self) -> None:
        i = _new_id("pfx")
        assert i.startswith("pfx-")

    def test_new_id_unique(self) -> None:
        ids = {_new_id("x") for _ in range(20)}
        assert len(ids) == 20

    def test_new_id_length(self) -> None:
        i = _new_id("ab")
        assert len(i) == 19


# ===========================================================================
# Section 2 — Singleton behaviour
# ===========================================================================


class TestStripeServiceSingleton:
    def test_get_stripe_service_returns_same_instance(self) -> None:
        a = get_stripe_service()
        b = get_stripe_service()
        assert a is b

    def test_reset_clears_state_not_replaces_instance(self) -> None:
        svc = get_stripe_service()
        svc._unit_balances["org-sentinel"] = 999
        assert svc._unit_balances.get("org-sentinel") == 999
        reset_stripe_service()
        assert svc._unit_balances.get("org-sentinel") is None
        assert get_stripe_service() is svc

    def test_reset_creates_new_instance(self) -> None:
        svc = get_stripe_service()
        svc._unit_balances["probe-org"] = 42
        reset_stripe_service()
        assert get_stripe_service()._unit_balances.get("probe-org") is None

    def test_service_instance_is_stripe_service(self) -> None:
        assert isinstance(get_stripe_service(), StripeService)


# ===========================================================================
# Section 3 — Configuration / client
# ===========================================================================


class TestStripeServiceConfig:
    def test_get_api_key_raises_config_error_when_missing(self, svc: StripeService) -> None:
        with patch("app.services.stripe_service.vault") as mock_vault:
            mock_vault.get.return_value = ""
            with pytest.raises(StripeConfigError):
                svc._get_api_key()

    def test_get_webhook_secret_raises_config_error_when_missing(self, svc: StripeService) -> None:
        with patch("app.services.stripe_service.vault") as mock_vault:
            mock_vault.get.return_value = ""
            with pytest.raises(StripeConfigError):
                svc._get_webhook_secret()

    def test_override_client_replaces_client(self, svc: StripeService, mock_client: MagicMock) -> None:
        svc._override_client(mock_client)
        assert svc._client is mock_client

    def test_get_client_creates_http_client(self, svc: StripeService) -> None:
        with patch("app.services.stripe_service.vault") as mock_vault:
            mock_vault.get.return_value = _TEST_API_KEY
            client = svc._get_client()
        assert isinstance(client, _StripeHTTPClient)

    def test_get_client_cached_after_first_call(self, svc: StripeService) -> None:
        with patch("app.services.stripe_service.vault") as mock_vault:
            mock_vault.get.return_value = _TEST_API_KEY
            c1 = svc._get_client()
            c2 = svc._get_client()
        assert c1 is c2


# ===========================================================================
# Section 4 — Customer management
# ===========================================================================


class TestCustomerManagement:
    def test_register_customer_mapping(self, svc: StripeService) -> None:
        svc.register_customer_mapping("org-a", "cus_aaa")
        assert svc.resolve_org_from_customer("cus_aaa") == "org-a"

    def test_resolve_org_unknown_customer_returns_none(self, svc: StripeService) -> None:
        assert svc.resolve_org_from_customer("cus_ghost") is None

    def test_register_mapping_bidirectional(self, svc: StripeService) -> None:
        svc.register_customer_mapping("org-b", "cus_bbb")
        assert svc._org_customer_map["org-b"] == "cus_bbb"
        assert svc._customer_org_map["cus_bbb"] == "org-b"

    def test_get_or_create_customer_calls_stripe(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "cus_new123"}
        cid = svc_with_client.get_or_create_stripe_customer("org-new", email="test@example.com", name="Test Org")
        assert cid == "cus_new123"
        mock_client.post.assert_called_once()
        call_path = mock_client.post.call_args[0][0]
        assert call_path == "/customers"

    def test_get_or_create_customer_cached_after_first_call(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "cus_cached"}
        svc_with_client.get_or_create_stripe_customer("org-cached")
        svc_with_client.get_or_create_stripe_customer("org-cached")
        assert mock_client.post.call_count == 1

    def test_get_or_create_customer_different_orgs_separate_calls(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.side_effect = [{"id": "cus_x"}, {"id": "cus_y"}]
        svc_with_client.get_or_create_stripe_customer("org-x")
        svc_with_client.get_or_create_stripe_customer("org-y")
        assert mock_client.post.call_count == 2

    def test_get_or_create_customer_stores_mapping(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "cus_mapped"}
        svc_with_client.get_or_create_stripe_customer("org-mapped")
        assert svc_with_client.resolve_org_from_customer("cus_mapped") == "org-mapped"

    # --- resolve_customer_id ---

    def test_resolve_customer_id_happy_path(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        result = svc.resolve_customer_id(_TEST_ORG)
        assert result == _TEST_CUSTOMER_ID

    def test_resolve_customer_id_missing_returns_none(self, svc: StripeService) -> None:
        result = svc.resolve_customer_id("org-never-registered")
        assert result is None

    def test_resolve_customer_id_after_stripe_create(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "cus_stripe_id_lookup"}
        svc_with_client.get_or_create_stripe_customer("org-lookup")
        result = svc_with_client.resolve_customer_id("org-lookup")
        assert result == "cus_stripe_id_lookup"

    def test_resolve_customer_id_multiple_orgs_isolated(self, svc: StripeService) -> None:
        svc.register_customer_mapping("org-aa", "cus_aa")
        svc.register_customer_mapping("org-bb", "cus_bb")
        assert svc.resolve_customer_id("org-aa") == "cus_aa"
        assert svc.resolve_customer_id("org-bb") == "cus_bb"


# ===========================================================================
# Section 5 — Checkout session creation
# ===========================================================================


class TestCheckoutSessionCreation:
    def test_create_checkout_session_returns_response(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        resp = svc_with_client.create_checkout_session(
            org_id=_TEST_ORG,
            price_id=_TEST_PRICE_ID,
            mode=StripeCheckoutMode.PAYMENT,
            quantity=1,
            unit_credits=_PKG_STARTER_UNITS,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        assert isinstance(resp, CheckoutSessionResponse)
        assert resp.session_id == _TEST_SESSION_ID
        assert resp.unit_credits == _PKG_STARTER_UNITS
        assert resp.org_id == _TEST_ORG

    def test_create_checkout_session_stores_record(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        svc_with_client.create_checkout_session(
            org_id=_TEST_ORG,
            price_id=_TEST_PRICE_ID,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        record = svc_with_client.get_checkout_session(_TEST_SESSION_ID)
        assert record is not None
        assert record["session_id"] == _TEST_SESSION_ID

    def test_create_checkout_session_quantity_zero_raises(self, svc_with_client: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc_with_client.create_checkout_session(
                org_id=_TEST_ORG,
                price_id=_TEST_PRICE_ID,
                quantity=0,
                success_url=_TEST_SUCCESS_URL,
                cancel_url=_TEST_CANCEL_URL,
            )

    def test_create_checkout_session_negative_credits_raises(self, svc_with_client: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc_with_client.create_checkout_session(
                org_id=_TEST_ORG,
                price_id=_TEST_PRICE_ID,
                unit_credits=-1,
                success_url=_TEST_SUCCESS_URL,
                cancel_url=_TEST_CANCEL_URL,
            )

    def test_create_checkout_session_posts_to_correct_path(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        svc_with_client.create_checkout_session(
            org_id=_TEST_ORG,
            price_id=_TEST_PRICE_ID,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        call_path = mock_client.post.call_args[0][0]
        assert call_path == "/checkout/sessions"

    def test_get_checkout_session_missing_returns_none(self, svc: StripeService) -> None:
        assert svc.get_checkout_session("cs_nonexistent") is None

    def test_expire_checkout_session(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        svc_with_client.create_checkout_session(
            org_id=_TEST_ORG,
            price_id=_TEST_PRICE_ID,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        result = svc_with_client.expire_checkout_session(_TEST_SESSION_ID)
        assert result is True
        record = svc_with_client.get_checkout_session(_TEST_SESSION_ID)
        assert record is not None
        assert record["status"] == "expired"

    def test_expire_nonexistent_session_returns_false(self, svc: StripeService) -> None:
        assert svc.expire_checkout_session("cs_ghost") is False

    def test_list_checkout_sessions_all(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        svc_with_client.create_checkout_session(
            org_id=_TEST_ORG,
            price_id=_TEST_PRICE_ID,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        sessions = svc_with_client.list_checkout_sessions()
        assert len(sessions) >= 1

    def test_list_checkout_sessions_filter_org(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        svc_with_client.create_checkout_session(
            org_id="org-alpha",
            price_id=_TEST_PRICE_ID,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        results = svc_with_client.list_checkout_sessions(org_id="org-alpha")
        assert all(s["org_id"] == "org-alpha" for s in results)

    def test_create_checkout_session_response_has_schema_version(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        resp = svc_with_client.create_checkout_session(
            org_id=_TEST_ORG,
            price_id=_TEST_PRICE_ID,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        assert resp.schema_version == "1.0"


# ===========================================================================
# Section 6 — Unit balance ledger
# ===========================================================================


class TestUnitBalanceLedger:
    def test_credit_units_increases_balance(self, svc: StripeService) -> None:
        resp = svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        assert resp.balance == _PKG_STARTER_UNITS
        assert resp.org_id == _TEST_ORG

    def test_credit_units_accumulates(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        assert resp.balance == _PKG_STARTER_UNITS * 2

    def test_credit_units_zero_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc.credit_units(_TEST_ORG, 0, StripeUnitEventReason.MANUAL_CREDIT)

    def test_credit_units_negative_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc.credit_units(_TEST_ORG, -1, StripeUnitEventReason.MANUAL_CREDIT)

    # --- debit_units ---

    def test_debit_units_decreases_balance(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_TEAM_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == _PKG_TEAM_UNITS - _PKG_STARTER_UNITS

    def test_debit_units_insufficient_raises_specific_error(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, 10, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError) as exc_info:
            svc.debit_units(_TEST_ORG, 11, StripeUnitEventReason.METERED_SYNC)
        assert exc_info.value.org_id == _TEST_ORG
        assert exc_info.value.have == 10
        assert exc_info.value.need == 11

    def test_debit_units_insufficient_is_stripe_service_error(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, 5, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeServiceError, match="insufficient"):
            svc.debit_units(_TEST_ORG, 10, StripeUnitEventReason.METERED_SYNC)

    def test_debit_units_zero_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc.debit_units(_TEST_ORG, 0, StripeUnitEventReason.METERED_SYNC)

    def test_debit_units_unknown_org_is_insufficient(self, svc: StripeService) -> None:
        """Org with no balance at all → StripeInsufficientUnitsError (balance=0)."""
        with pytest.raises(StripeInsufficientUnitsError) as exc_info:
            svc.debit_units("org-brand-new-unknown", 1, StripeUnitEventReason.METERED_SYNC)
        assert exc_info.value.have == 0
        assert exc_info.value.need == 1

    def test_debit_units_exact_balance_succeeds(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, 50, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units(_TEST_ORG, 50, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == 0

    def test_get_unit_balance_default_zero(self, svc: StripeService) -> None:
        resp = svc.get_unit_balance("org-new-unknown")
        assert resp.balance == 0

    def test_get_unit_balance_reflects_credits(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_TEAM_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        resp = svc.get_unit_balance(_TEST_ORG)
        assert resp.balance == _PKG_TEAM_UNITS

    def test_get_unit_balance_returns_unit_balance_response(self, svc: StripeService) -> None:
        resp = svc.get_unit_balance(_TEST_ORG)
        assert isinstance(resp, UnitBalanceResponse)

    def test_adjust_unit_balance_sets_exact_value(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.adjust_unit_balance(_TEST_ORG, _PKG_STARTER_UNITS)
        assert resp.balance == _PKG_STARTER_UNITS

    def test_adjust_unit_balance_negative_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc.adjust_unit_balance(_TEST_ORG, -1)

    def test_ledger_records_credit_entry(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE, reference_id="ref-1")
        resp = svc.get_unit_balance(_TEST_ORG)
        assert len(resp.ledger_entries) == 1
        entry = resp.ledger_entries[0]
        assert entry["delta"] == _PKG_STARTER_UNITS
        assert entry["reason"] == "checkout.complete"
        assert entry["reference_id"] == "ref-1"
        assert entry["balance_after"] == _PKG_STARTER_UNITS

    def test_ledger_records_debit_as_negative_delta(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_TEAM_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        svc.debit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.METERED_SYNC)
        resp = svc.get_unit_balance(_TEST_ORG)
        debit_entry = next(e for e in resp.ledger_entries if e["delta"] < 0)
        assert debit_entry["delta"] == -_PKG_STARTER_UNITS

    def test_ledger_isolated_by_org(self, svc: StripeService) -> None:
        svc.credit_units("org-a", _PKG_STARTER_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        svc.credit_units("org-b", _PKG_TEAM_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        resp_a = svc.get_unit_balance("org-a")
        resp_b = svc.get_unit_balance("org-b")
        assert resp_a.balance == _PKG_STARTER_UNITS
        assert resp_b.balance == _PKG_TEAM_UNITS

    def test_unit_balance_thread_safety(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_ENTERPRISE_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        errors: list[Exception] = []

        def _debit() -> None:
            try:
                svc.debit_units(_TEST_ORG, 1, StripeUnitEventReason.METERED_SYNC)
            except StripeServiceError:
                pass
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_debit) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []

    def test_insufficient_units_callback_invoked(self) -> None:
        cb_calls: list[tuple[str, int, int]] = []

        def _cb(org_id: str, have: int, need: int) -> None:
            cb_calls.append((org_id, have, need))

        svc = StripeService(on_insufficient_units=_cb)
        svc.credit_units(_TEST_ORG, 5, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units(_TEST_ORG, 10, StripeUnitEventReason.METERED_SYNC)
        assert len(cb_calls) == 1
        assert cb_calls[0] == (_TEST_ORG, 5, 10)


# ===========================================================================
# Section 7 — Subscription lifecycle
# ===========================================================================


class TestSubscriptionLifecycle:
    def _upsert(self, svc: StripeService, **overrides: Any) -> SubscriptionResponse:
        defaults: dict[str, Any] = dict(
            subscription_id=_TEST_SUB_ID,
            org_id=_TEST_ORG,
            customer_id=_TEST_CUSTOMER_ID,
            price_id=_TEST_PRICE_ID,
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        defaults.update(overrides)
        return svc.upsert_subscription(**defaults)

    def test_upsert_subscription_creates_record(self, svc: StripeService) -> None:
        resp = self._upsert(svc)
        assert resp.subscription_id == _TEST_SUB_ID
        assert resp.status == "active"
        assert resp.org_id == _TEST_ORG

    def test_upsert_subscription_updates_existing(self, svc: StripeService) -> None:
        self._upsert(svc)
        updated = self._upsert(svc, status=StripeSubscriptionStatus.PAST_DUE)
        assert updated.status == "past_due"

    def test_upsert_preserves_created_at(self, svc: StripeService) -> None:
        first = self._upsert(svc)
        time.sleep(0.01)
        second = self._upsert(svc, status=StripeSubscriptionStatus.TRIALING)
        assert first.created_at == second.created_at

    def test_get_subscription_returns_record(self, svc: StripeService) -> None:
        self._upsert(svc)
        resp = svc.get_subscription(_TEST_SUB_ID)
        assert resp is not None
        assert resp.subscription_id == _TEST_SUB_ID

    def test_get_subscription_missing_returns_none(self, svc: StripeService) -> None:
        assert svc.get_subscription("sub_ghost") is None

    def test_get_active_subscription_for_org(self, svc: StripeService) -> None:
        self._upsert(svc, status=StripeSubscriptionStatus.ACTIVE)
        resp = svc.get_active_subscription_for_org(_TEST_ORG)
        assert resp is not None
        assert resp.status == "active"

    def test_get_active_subscription_excludes_canceled(self, svc: StripeService) -> None:
        self._upsert(svc, status=StripeSubscriptionStatus.CANCELED)
        assert svc.get_active_subscription_for_org(_TEST_ORG) is None

    def test_get_active_subscription_trialing_included(self, svc: StripeService) -> None:
        self._upsert(svc, status=StripeSubscriptionStatus.TRIALING)
        assert svc.get_active_subscription_for_org(_TEST_ORG) is not None

    def test_get_active_subscription_past_due_included(self, svc: StripeService) -> None:
        self._upsert(svc, status=StripeSubscriptionStatus.PAST_DUE)
        assert svc.get_active_subscription_for_org(_TEST_ORG) is not None

    def test_cancel_subscription_marks_canceled(self, svc: StripeService) -> None:
        self._upsert(svc)
        resp = svc.cancel_subscription(_TEST_SUB_ID)
        assert resp is not None
        assert resp.status == "canceled"
        assert resp.cancel_at_period_end is True

    def test_cancel_nonexistent_returns_none(self, svc: StripeService) -> None:
        assert svc.cancel_subscription("sub_ghost") is None

    def test_list_subscriptions_all(self, svc: StripeService) -> None:
        self._upsert(svc, subscription_id="sub_1", org_id="org-1")
        self._upsert(svc, subscription_id="sub_2", org_id="org-2")
        assert len(svc.list_subscriptions()) == 2

    def test_list_subscriptions_filter_org(self, svc: StripeService) -> None:
        self._upsert(svc, subscription_id="sub_a", org_id="org-filter-a")
        self._upsert(svc, subscription_id="sub_b", org_id="org-filter-b")
        results = svc.list_subscriptions(org_id="org-filter-a")
        assert len(results) == 1
        assert results[0]["org_id"] == "org-filter-a"

    def test_cancel_subscription_remote_calls_api(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        self._upsert(svc_with_client)
        mock_client.post.return_value = {
            "id": _TEST_SUB_ID,
            "status": "active",
            "customer": _TEST_CUSTOMER_ID,
            "cancel_at_period_end": True,
        }
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        resp = svc_with_client.cancel_subscription_remote(_TEST_SUB_ID)
        assert resp is not None
        mock_client.post.assert_called_once()
        call_path = mock_client.post.call_args[0][0]
        assert _TEST_SUB_ID in call_path

    def test_subscription_response_has_schema_version(self, svc: StripeService) -> None:
        resp = self._upsert(svc)
        assert resp.schema_version == "1.0"


# ===========================================================================
# Section 8 — Metered usage
# ===========================================================================


class TestMeteredUsage:
    def test_report_metered_usage_success(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_test_123"}
        resp = svc_with_client.report_metered_usage(
            org_id=_TEST_ORG,
            subscription_item_id="si_test_abc",
            quantity=50,
        )
        assert resp.success is True
        assert resp.stripe_usage_record_id == "mbur_test_123"
        assert resp.quantity == 50

    def test_report_metered_usage_negative_quantity_raises(self, svc_with_client: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc_with_client.report_metered_usage(
                org_id=_TEST_ORG,
                subscription_item_id="si_test",
                quantity=-1,
            )

    def test_report_metered_usage_zero_allowed(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_zero"}
        resp = svc_with_client.report_metered_usage(
            org_id=_TEST_ORG,
            subscription_item_id="si_test",
            quantity=0,
        )
        assert resp.success is True

    def test_report_metered_usage_api_error_captured(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.side_effect = StripeAPIError("quota exceeded", http_status=429)
        resp = svc_with_client.report_metered_usage(
            org_id=_TEST_ORG,
            subscription_item_id="si_fail",
            quantity=10,
        )
        assert resp.success is False
        assert resp.error is not None
        assert "quota exceeded" in resp.error

    def test_report_metered_usage_appends_to_log(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_log"}
        svc_with_client.report_metered_usage(
            org_id=_TEST_ORG,
            subscription_item_id="si_log",
            quantity=25,
        )
        log = svc_with_client.get_metered_usage_log(org_id=_TEST_ORG)
        assert len(log) == 1
        assert log[0]["quantity"] == 25

    def test_get_metered_usage_log_returns_entries(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_entries"}
        for i in range(3):
            svc_with_client.report_metered_usage(_TEST_ORG, "si_entries", quantity=i + 1)
        log = svc_with_client.get_metered_usage_log(org_id=_TEST_ORG)
        assert len(log) == 3
        quantities = {e["quantity"] for e in log}
        assert quantities == {1, 2, 3}

    def test_get_metered_usage_log_empty_log(self, svc: StripeService) -> None:
        log = svc.get_metered_usage_log()
        assert log == []

    def test_get_metered_usage_log_empty_for_org_with_no_entries(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_other"}
        svc_with_client.report_metered_usage("org-other", "si_other", quantity=5)
        log = svc_with_client.get_metered_usage_log(org_id="org-no-entries")
        assert log == []

    def test_get_metered_usage_log_filter_org(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_x"}
        svc_with_client.report_metered_usage("org-x", "si_x", quantity=1)
        svc_with_client.report_metered_usage("org-y", "si_y", quantity=2)
        log_x = svc_with_client.get_metered_usage_log(org_id="org-x")
        assert all(e["org_id"] == "org-x" for e in log_x)

    def test_get_metered_usage_log_limit(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_lim"}
        for _ in range(10):
            svc_with_client.report_metered_usage(_TEST_ORG, "si_lim", quantity=1)
        log = svc_with_client.get_metered_usage_log(limit=3)
        assert len(log) == 3

    def test_report_metered_usage_uses_idempotency_key(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_idem"}
        svc_with_client.report_metered_usage(_TEST_ORG, "si_idem", quantity=5, idempotency_key="idem-abc-123")
        call_kwargs = mock_client.post.call_args[1]
        assert call_kwargs.get("idempotency_key") == "idem-abc-123"

    def test_report_metered_usage_response_has_schema_version(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_sv"}
        resp = svc_with_client.report_metered_usage(_TEST_ORG, "si_sv", quantity=1)
        assert resp.schema_version == "1.0"


# ===========================================================================
# Section 9 — Webhook signature verification
# ===========================================================================


class TestWebhookSignatureVerification:
    def _patch_vault(self, secret: str = _TEST_WEBHOOK_SECRET, tolerance: str = "300") -> Any:
        m = MagicMock()

        def _get(key: str) -> str:
            return {
                "STRIPE_WEBHOOK_SECRET": secret,
                "STRIPE_WEBHOOK_TOLERANCE_SECONDS": tolerance,
            }.get(key, "")

        m.get.side_effect = _get
        return m

    def test_valid_signature_returns_valid_true(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_1","type":"checkout.session.completed","data":{"object":{}}}'
        sig = _make_stripe_sig(_TEST_WEBHOOK_SECRET, payload)
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is True
        assert result.event_type == "checkout.session.completed"
        assert result.event_id == "evt_1"

    def test_verify_webhook_returns_webhook_verify_result(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_vr","type":"invoice.paid","data":{"object":{}}}'
        sig = _make_stripe_sig(_TEST_WEBHOOK_SECRET, payload)
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, sig)
        assert isinstance(result, WebhookVerifyResult)

    def test_wrong_secret_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_2","type":"invoice.paid","data":{"object":{}}}'
        sig = _make_stripe_sig("wrong-secret-12345678901234567890", payload)
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False
        assert "mismatch" in (result.error or "").lower()

    def test_expired_timestamp_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_3","type":"invoice.paid","data":{"object":{}}}'
        old_ts = int(time.time()) - 400
        sig = _make_stripe_sig(_TEST_WEBHOOK_SECRET, payload, timestamp=old_ts)
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False
        assert result.error is not None

    def test_future_timestamp_beyond_tolerance_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_4","type":"invoice.paid","data":{"object":{}}}'
        future_ts = int(time.time()) + 400
        sig = _make_stripe_sig(_TEST_WEBHOOK_SECRET, payload, timestamp=future_ts)
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False

    def test_malformed_header_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_5","type":"invoice.paid","data":{"object":{}}}'
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, "not-a-stripe-sig-header")
        assert result.valid is False

    def test_missing_webhook_secret_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_6","type":"invoice.paid","data":{"object":{}}}'
        sig = _make_stripe_sig(_TEST_WEBHOOK_SECRET, payload)
        m = MagicMock()
        m.get.return_value = ""
        with patch("app.services.stripe_service.vault", m):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False

    def test_payload_in_result_on_success(self, svc: StripeService) -> None:
        body = {"id": "evt_7", "type": "invoice.paid", "data": {"object": {"amount": 100}}}
        payload = json.dumps(body).encode()
        sig = _make_stripe_sig(_TEST_WEBHOOK_SECRET, payload)
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is True
        assert result.payload["id"] == "evt_7"

    def test_invalid_json_payload_returns_invalid(self, svc: StripeService) -> None:
        payload = b"not-json"
        sig = _make_stripe_sig(_TEST_WEBHOOK_SECRET, payload)
        with patch("app.services.stripe_service.vault", self._patch_vault()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False


# ===========================================================================
# Section 10 — Webhook event dispatch
# ===========================================================================


class TestWebhookEventDispatch:
    def _event(self, event_type: str, obj: dict[str, Any], event_id: str = "evt_dispatch") -> dict[str, Any]:
        return {"id": event_id, "type": event_type, "data": {"object": obj}}

    def test_checkout_completed_credits_units(self, svc: StripeService) -> None:
        obj = {
            "id": "cs_webhook_1",
            "mode": "payment",
            "customer": _TEST_CUSTOMER_ID,
            "metadata": {"org_id": _TEST_ORG, "unit_credits": str(_PKG_STARTER_UNITS)},
        }
        result = svc.handle_webhook_event(self._event("checkout.session.completed", obj))
        assert result["action"] == "processed"
        assert svc.get_unit_balance(_TEST_ORG).balance == _PKG_STARTER_UNITS

    def test_checkout_completed_no_credits_skips_credit(self, svc: StripeService) -> None:
        obj = {
            "id": "cs_webhook_2",
            "mode": "payment",
            "customer": _TEST_CUSTOMER_ID,
            "metadata": {"org_id": _TEST_ORG, "unit_credits": "0"},
        }
        svc.handle_webhook_event(self._event("checkout.session.completed", obj))
        assert svc.get_unit_balance(_TEST_ORG).balance == 0

    def test_checkout_expired_marks_session(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_session_resp()
        svc_with_client.create_checkout_session(
            org_id=_TEST_ORG,
            price_id=_TEST_PRICE_ID,
            success_url=_TEST_SUCCESS_URL,
            cancel_url=_TEST_CANCEL_URL,
        )
        obj = {"id": _TEST_SESSION_ID}
        svc_with_client.handle_webhook_event(self._event("checkout.session.expired", obj))
        record = svc_with_client.get_checkout_session(_TEST_SESSION_ID)
        assert record is not None
        assert record["status"] == "expired"

    def test_subscription_created_stores_record(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        obj = _mock_subscription_obj()
        svc.handle_webhook_event(self._event("customer.subscription.created", obj))
        sub = svc.get_subscription(_TEST_SUB_ID)
        assert sub is not None
        assert sub.status == "active"

    def test_subscription_updated_changes_status(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.handle_webhook_event(self._event("customer.subscription.created", _mock_subscription_obj()))
        updated_obj = _mock_subscription_obj(status="past_due")
        svc.handle_webhook_event(self._event("customer.subscription.updated", updated_obj))
        sub = svc.get_subscription(_TEST_SUB_ID)
        assert sub is not None
        assert sub.status == "past_due"

    def test_subscription_deleted_marks_canceled(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.handle_webhook_event(self._event("customer.subscription.created", _mock_subscription_obj()))
        obj = {"id": _TEST_SUB_ID}
        svc.handle_webhook_event(self._event("customer.subscription.deleted", obj))
        sub = svc.get_subscription(_TEST_SUB_ID)
        assert sub is not None
        assert sub.status == "canceled"

    def test_invoice_paid_restores_active_from_past_due(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.upsert_subscription(
            subscription_id=_TEST_SUB_ID,
            org_id=_TEST_ORG,
            customer_id=_TEST_CUSTOMER_ID,
            price_id=_TEST_PRICE_ID,
            status=StripeSubscriptionStatus.PAST_DUE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        obj = {
            "id": "in_test",
            "customer": _TEST_CUSTOMER_ID,
            "subscription": _TEST_SUB_ID,
            "amount_paid": _PKG_STARTER_PRICE_CENTS,
        }
        svc.handle_webhook_event(self._event("invoice.paid", obj))
        sub = svc.get_subscription(_TEST_SUB_ID)
        assert sub is not None
        assert sub.status == "active"

    def test_invoice_payment_failed_marks_past_due(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.upsert_subscription(
            subscription_id=_TEST_SUB_ID,
            org_id=_TEST_ORG,
            customer_id=_TEST_CUSTOMER_ID,
            price_id=_TEST_PRICE_ID,
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        obj = {
            "id": "in_fail",
            "customer": _TEST_CUSTOMER_ID,
            "subscription": _TEST_SUB_ID,
        }
        svc.handle_webhook_event(self._event("invoice.payment_failed", obj))
        sub = svc.get_subscription(_TEST_SUB_ID)
        assert sub is not None
        assert sub.status == "past_due"

    def test_unhandled_event_type_returns_ignored(self, svc: StripeService) -> None:
        result = svc.handle_webhook_event({"id": "evt_unknown", "type": "unknown.event.type", "data": {"object": {}}})
        assert result["action"] == "ignored"

    def test_handler_exception_returns_error_action(self, svc: StripeService) -> None:
        with patch.object(svc, "_handle_checkout_completed", side_effect=RuntimeError("boom")):
            result = svc.handle_webhook_event({"id": "evt_err", "type": "checkout.session.completed", "data": {"object": {}}})
        assert result["action"] == "error"
        assert "boom" in result["error"]

    def test_customer_created_registers_mapping(self, svc: StripeService) -> None:
        obj = {"id": _TEST_CUSTOMER_ID, "metadata": {"org_id": _TEST_ORG}}
        svc.handle_webhook_event(self._event("customer.created", obj))
        assert svc.resolve_org_from_customer(_TEST_CUSTOMER_ID) == _TEST_ORG

    # --- charge.refunded ---

    def test_charge_refunded_action_is_valid(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        obj = _make_charge_refunded_obj()
        result = svc.handle_webhook_event(self._event("charge.refunded", obj))
        assert result["action"] in ("processed", "ignored")

    def test_charge_refunded_event_type_enum_value(self) -> None:
        assert StripeWebhookEventType.CHARGE_REFUNDED == "charge.refunded"

    # --- payment_intent.succeeded ---

    def test_payment_intent_succeeded_event_type_enum_value(self) -> None:
        assert StripeWebhookEventType.PAYMENT_INTENT_SUCCEEDED == "payment_intent.succeeded"

    def test_payment_intent_succeeded_dispatched_without_exception(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        obj = _make_payment_intent_obj(status="succeeded")
        result = svc.handle_webhook_event(self._event("payment_intent.succeeded", obj))
        assert result["action"] in ("processed", "ignored")

    def test_payment_intent_succeeded_does_not_corrupt_balance(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        obj = _make_payment_intent_obj(status="succeeded")
        svc.handle_webhook_event(self._event("payment_intent.succeeded", obj))
        assert svc.get_unit_balance(_TEST_ORG).balance == _PKG_STARTER_UNITS

    # --- payment_intent.payment_failed ---

    def test_payment_intent_payment_failed_event_type_enum_value(self) -> None:
        assert StripeWebhookEventType.PAYMENT_INTENT_PAYMENT_FAILED == "payment_intent.payment_failed"

    def test_payment_intent_payment_failed_dispatched_without_exception(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        obj = _make_payment_intent_obj(status="requires_payment_method")
        result = svc.handle_webhook_event(self._event("payment_intent.payment_failed", obj))
        assert result["action"] in ("processed", "ignored")

    def test_payment_intent_payment_failed_does_not_corrupt_balance(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.credit_units(_TEST_ORG, _PKG_TEAM_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        obj = _make_payment_intent_obj(status="requires_payment_method")
        svc.handle_webhook_event(self._event("payment_intent.payment_failed", obj))
        assert svc.get_unit_balance(_TEST_ORG).balance == _PKG_TEAM_UNITS

    # --- invoice.upcoming ---

    def test_invoice_upcoming_event_type_enum_value(self) -> None:
        assert StripeWebhookEventType.INVOICE_UPCOMING == "invoice.upcoming"

    def test_invoice_upcoming_dispatched_without_exception(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.upsert_subscription(
            subscription_id=_TEST_SUB_ID,
            org_id=_TEST_ORG,
            customer_id=_TEST_CUSTOMER_ID,
            price_id=_TEST_PRICE_ID,
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        obj = _make_invoice_upcoming_obj()
        result = svc.handle_webhook_event(self._event("invoice.upcoming", obj))
        assert result["action"] in ("processed", "ignored")

    def test_invoice_upcoming_does_not_alter_subscription_status(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        svc.upsert_subscription(
            subscription_id=_TEST_SUB_ID,
            org_id=_TEST_ORG,
            customer_id=_TEST_CUSTOMER_ID,
            price_id=_TEST_PRICE_ID,
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        obj = _make_invoice_upcoming_obj()
        svc.handle_webhook_event(self._event("invoice.upcoming", obj))
        sub = svc.get_subscription(_TEST_SUB_ID)
        assert sub is not None
        assert sub.status == "active"

    # --- customer.updated ---

    def test_customer_updated_event_type_enum_value(self) -> None:
        assert StripeWebhookEventType.CUSTOMER_UPDATED == "customer.updated"

    def test_customer_updated_dispatched_without_exception(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        obj = _make_customer_updated_obj()
        result = svc.handle_webhook_event(self._event("customer.updated", obj))
        assert result["action"] in ("processed", "ignored")

    def test_customer_updated_preserves_org_mapping(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        obj = _make_customer_updated_obj()
        svc.handle_webhook_event(self._event("customer.updated", obj))
        assert svc.resolve_org_from_customer(_TEST_CUSTOMER_ID) == _TEST_ORG

    # --- idempotency: duplicate event_id is ignored ---

    def test_duplicate_event_id_is_idempotent(self, svc: StripeService) -> None:
        obj = {
            "id": "cs_idem",
            "mode": "payment",
            "customer": _TEST_CUSTOMER_ID,
            "metadata": {"org_id": _TEST_ORG, "unit_credits": str(_PKG_STARTER_UNITS)},
        }
        event = self._event("checkout.session.completed", obj, event_id="evt_idempotent_1")
        svc.handle_webhook_event(event)
        svc.handle_webhook_event(event)
        # Balance must not double-credit
        assert svc.get_unit_balance(_TEST_ORG).balance == _PKG_STARTER_UNITS


# ===========================================================================
# Section 11 — Reset / state isolation
# ===========================================================================


class TestServiceReset:
    def test_reset_clears_unit_balances(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        svc.reset()
        assert svc.get_unit_balance(_TEST_ORG).balance == 0

    def test_reset_clears_subscriptions(self, svc: StripeService) -> None:
        svc.upsert_subscription(
            subscription_id=_TEST_SUB_ID,
            org_id=_TEST_ORG,
            customer_id=_TEST_CUSTOMER_ID,
            price_id=_TEST_PRICE_ID,
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        svc.reset()
        assert svc.get_subscription(_TEST_SUB_ID) is None

    def test_reset_clears_customer_maps(self, svc: StripeService) -> None:
        svc.register_customer_mapping("org-r", "cus_r")
        svc.reset()
        assert svc.resolve_org_from_customer("cus_r") is None

    def test_reset_clears_metered_log(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_reset"}
        svc_with_client.report_metered_usage(_TEST_ORG, "si_r", quantity=1)
        svc_with_client.reset()
        assert svc_with_client.get_metered_usage_log() == []

    def test_reset_clears_client_reference(self, svc: StripeService, mock_client: MagicMock) -> None:
        svc._override_client(mock_client)
        svc.reset()
        assert svc._client is None

    def test_reset_clears_payment_methods(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        svc_with_client.reset()
        assert svc_with_client.list_payment_methods(_TEST_CUSTOMER_ID) == []

    def test_reset_clears_invoice_cache(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        svc_with_client.get_invoices_for_org(_TEST_ORG)
        svc_with_client.reset()
        assert svc_with_client._invoice_cache == {}

    def test_module_reset_clears_singleton_state(self) -> None:
        svc = get_stripe_service()
        svc.credit_units("org-module-reset", _PKG_STARTER_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        reset_stripe_service()
        assert get_stripe_service().get_unit_balance("org-module-reset").balance == 0

    # --- reset_processed_events ---

    def test_reset_processed_events_clears_event_set(self, svc: StripeService) -> None:
        """After processing an event, reset_processed_events() must allow re-dispatch."""
        obj = {
            "id": "cs_re_process",
            "mode": "payment",
            "customer": _TEST_CUSTOMER_ID,
            "metadata": {"org_id": _TEST_ORG, "unit_credits": str(_PKG_STARTER_UNITS)},
        }
        event = {"id": "evt_to_clear", "type": "checkout.session.completed", "data": {"object": obj}}
        svc.handle_webhook_event(event)
        # Balance = PKG_STARTER_UNITS now
        svc.reset_processed_events()
        # After clearing, re-dispatch same event must be re-processed
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_TEST_ORG).balance == _PKG_STARTER_UNITS * 2

    def test_reset_processed_events_is_idempotent(self, svc: StripeService) -> None:
        """Calling reset_processed_events() on an already-empty set must not raise."""
        svc.reset_processed_events()
        svc.reset_processed_events()

    def test_reset_processed_events_does_not_clear_balances(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_TEAM_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        svc.reset_processed_events()
        assert svc.get_unit_balance(_TEST_ORG).balance == _PKG_TEAM_UNITS

    def test_reset_processed_events_does_not_clear_subscriptions(self, svc: StripeService) -> None:
        svc.upsert_subscription(
            subscription_id=_TEST_SUB_ID,
            org_id=_TEST_ORG,
            customer_id=_TEST_CUSTOMER_ID,
            price_id=_TEST_PRICE_ID,
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        svc.reset_processed_events()
        assert svc.get_subscription(_TEST_SUB_ID) is not None


# ===========================================================================
# Section 12 — _StripeHTTPClient unit tests
# ===========================================================================


class TestStripeHTTPClient:
    def test_encode_params_flat(self) -> None:
        client = _StripeHTTPClient(_TEST_API_KEY)
        encoded = client._encode_params({"mode": "payment", "quantity": 1}).decode()
        assert "mode=payment" in encoded
        assert "quantity=1" in encoded

    def test_encode_params_nested_dict(self) -> None:
        client = _StripeHTTPClient(_TEST_API_KEY)
        encoded = client._encode_params({"metadata": {"org_id": "org-a"}}).decode()
        assert "org_id" in encoded
        assert "org-a" in encoded

    def test_encode_params_list(self) -> None:
        client = _StripeHTTPClient(_TEST_API_KEY)
        encoded = client._encode_params({"items": ["a", "b"]}).decode()
        assert "items" in encoded

    def test_headers_include_auth(self) -> None:
        client = _StripeHTTPClient(_TEST_API_KEY)
        headers = client._headers()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    def test_headers_include_stripe_version(self) -> None:
        client = _StripeHTTPClient(_TEST_API_KEY)
        headers = client._headers()
        assert "Stripe-Version" in headers

    def test_headers_include_idempotency_key_when_provided(self) -> None:
        client = _StripeHTTPClient(_TEST_API_KEY)
        headers = client._headers(idempotency_key="idem-key-xyz")
        assert headers.get("Idempotency-Key") == "idem-key-xyz"

    def test_headers_no_idempotency_key_when_not_provided(self) -> None:
        client = _StripeHTTPClient(_TEST_API_KEY)
        headers = client._headers()
        assert "Idempotency-Key" not in headers

    def test_post_raises_stripe_api_error_on_http_error(self) -> None:
        import urllib.error

        client = _StripeHTTPClient(_TEST_API_KEY)
        error_body = json.dumps({"error": {"message": "card_declined", "code": "card_declined"}}).encode()
        http_err = urllib.error.HTTPError(url="", code=402, msg="Payment Required", hdrs=None, fp=None)  # type: ignore[arg-type]
        http_err.read = lambda: error_body  # type: ignore[method-assign]

        with patch("urllib.request.urlopen", side_effect=http_err):
            with pytest.raises(StripeAPIError) as exc_info:
                client.post("/charges", {"amount": "100"})

        assert exc_info.value.http_status == 402
        assert "card_declined" in str(exc_info.value)

    def test_get_raises_stripe_api_error_on_http_error(self) -> None:
        import urllib.error

        client = _StripeHTTPClient(_TEST_API_KEY)
        error_body = json.dumps({"error": {"message": "not found", "code": "resource_missing"}}).encode()
        http_err = urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs=None, fp=None)  # type: ignore[arg-type]
        http_err.read = lambda: error_body  # type: ignore[method-assign]

        with patch("urllib.request.urlopen", side_effect=http_err):
            with pytest.raises(StripeAPIError) as exc_info:
                client.get("/customers/cus_missing")

        assert exc_info.value.http_status == 404

    def test_stripe_api_error_stores_http_status(self) -> None:
        err = StripeAPIError("rate limited", http_status=429, stripe_code="rate_limit")
        assert err.http_status == 429
        assert err.stripe_code == "rate_limit"

    def test_stripe_api_error_is_stripe_service_error(self) -> None:
        err = StripeAPIError("oops")
        assert isinstance(err, StripeServiceError)

    def test_delete_raises_stripe_api_error_on_http_error(self) -> None:
        import urllib.error

        client = _StripeHTTPClient(_TEST_API_KEY)
        error_body = json.dumps({"error": {"message": "forbidden", "code": "forbidden"}}).encode()
        http_err = urllib.error.HTTPError(url="", code=403, msg="Forbidden", hdrs=None, fp=None)  # type: ignore[arg-type]
        http_err.read = lambda: error_body  # type: ignore[method-assign]

        with patch("urllib.request.urlopen", side_effect=http_err):
            with pytest.raises(StripeAPIError) as exc_info:
                client.delete("/payment_methods/pm_gone")

        assert exc_info.value.http_status == 403


# ===========================================================================
# Section 13 — Package catalogue correctness
# ===========================================================================


class TestPackageCatalogue:
    def test_tokens_per_unit_is_25000(self) -> None:
        assert _TOKENS_PER_UNIT == 25_000

    def test_starter_units(self) -> None:
        assert _PKG_STARTER_UNITS == 5_000

    def test_starter_price_usd(self) -> None:
        assert _PKG_STARTER_PRICE_USD == 20

    def test_starter_price_cents(self) -> None:
        assert _PKG_STARTER_PRICE_CENTS == 2_000

    def test_team_units(self) -> None:
        assert _PKG_TEAM_UNITS == 25_000

    def test_team_price_usd(self) -> None:
        assert _PKG_TEAM_PRICE_USD == 90

    def test_team_price_cents(self) -> None:
        assert _PKG_TEAM_PRICE_CENTS == 9_000

    def test_enterprise_units(self) -> None:
        assert _PKG_ENTERPRISE_UNITS == 60_000

    def test_enterprise_price_usd(self) -> None:
        assert _PKG_ENTERPRISE_PRICE_USD == 180

    def test_enterprise_price_cents(self) -> None:
        assert _PKG_ENTERPRISE_PRICE_CENTS == 18_000

    def test_starter_token_coverage(self) -> None:
        assert _PKG_STARTER_UNITS * _TOKENS_PER_UNIT == 125_000_000

    def test_team_token_coverage(self) -> None:
        assert _PKG_TEAM_UNITS * _TOKENS_PER_UNIT == 625_000_000

    def test_enterprise_token_coverage(self) -> None:
        assert _PKG_ENTERPRISE_UNITS * _TOKENS_PER_UNIT == 1_500_000_000

    def test_tier_ordering_by_units(self) -> None:
        assert _PKG_STARTER_UNITS < _PKG_TEAM_UNITS < _PKG_ENTERPRISE_UNITS

    def test_tier_ordering_by_price(self) -> None:
        assert _PKG_STARTER_PRICE_USD < _PKG_TEAM_PRICE_USD < _PKG_ENTERPRISE_PRICE_USD

    def test_package_catalogue_has_three_tiers(self) -> None:
        assert set(PACKAGE_CATALOGUE.keys()) == {"starter", "team", "enterprise"}

    def test_package_catalogue_starter_units_match_constant(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["units"] == _PKG_STARTER_UNITS

    def test_package_catalogue_team_price_matches_constant(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["price_usd"] == _PKG_TEAM_PRICE_USD

    def test_package_catalogue_enterprise_tokens_per_unit(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["tokens_per_unit"] == _TOKENS_PER_UNIT

    def test_all_tiers_have_required_keys(self) -> None:
        required = {"label", "units", "price_usd", "tokens_per_unit", "notes"}
        for tier, data in PACKAGE_CATALOGUE.items():
            assert required.issubset(data.keys()), f"tier {tier!r} missing keys"


# ===========================================================================
# Section 14 — units_for_tokens() boundary conditions
# ===========================================================================


class TestUnitsForTokens:
    """
    Tests call the canonical units_for_tokens() imported from stripe_service
    directly — not a local re-implementation — so changes to the function
    are caught here automatically.
    """

    def test_zero_tokens_requires_zero_units(self) -> None:
        assert units_for_tokens(0) == 0

    def test_negative_tokens_requires_zero_units(self) -> None:
        assert units_for_tokens(-1) == 0

    def test_one_token_requires_one_unit(self) -> None:
        assert units_for_tokens(1) == 1

    def test_exact_one_chunk_requires_one_unit(self) -> None:
        assert units_for_tokens(25_000) == 1

    def test_one_over_first_chunk_requires_two_units(self) -> None:
        assert units_for_tokens(25_001) == 2

    def test_exact_two_chunks_requires_two_units(self) -> None:
        assert units_for_tokens(50_000) == 2

    def test_one_over_two_chunks_requires_three_units(self) -> None:
        assert units_for_tokens(50_001) == 3

    def test_exact_three_chunks_requires_three_units(self) -> None:
        assert units_for_tokens(75_000) == 3

    def test_one_over_three_chunks_requires_four_units(self) -> None:
        assert units_for_tokens(75_001) == 4

    def test_non_multiple_mid_chunk(self) -> None:
        assert units_for_tokens(12_500) == 1

    def test_non_multiple_straddles_boundary(self) -> None:
        assert units_for_tokens(37_500) == 2

    def test_starter_package_token_ceiling(self) -> None:
        max_tokens = _PKG_STARTER_UNITS * _TOKENS_PER_UNIT
        assert units_for_tokens(max_tokens) == _PKG_STARTER_UNITS

    def test_starter_package_one_over_ceiling(self) -> None:
        max_tokens = _PKG_STARTER_UNITS * _TOKENS_PER_UNIT
        assert units_for_tokens(max_tokens + 1) == _PKG_STARTER_UNITS + 1

    def test_team_package_token_ceiling(self) -> None:
        max_tokens = _PKG_TEAM_UNITS * _TOKENS_PER_UNIT
        assert units_for_tokens(max_tokens) == _PKG_TEAM_UNITS

    def test_enterprise_package_token_ceiling(self) -> None:
        max_tokens = _PKG_ENTERPRISE_UNITS * _TOKENS_PER_UNIT
        assert units_for_tokens(max_tokens) == _PKG_ENTERPRISE_UNITS

    def test_large_token_count_scales_correctly(self) -> None:
        assert units_for_tokens(1_000_000) == 40

    def test_result_is_ceiling_division(self) -> None:
        for n in range(1, 5):
            for offset in range(0, _TOKENS_PER_UNIT + 1, 1000):
                token_count = (n - 1) * _TOKENS_PER_UNIT + offset
                expected = math.ceil(token_count / _TOKENS_PER_UNIT) if token_count > 0 else 0
                assert units_for_tokens(token_count) == expected


# ===========================================================================
# Section 15 — Exception shapes
# ===========================================================================


class TestExceptionShapes:
    def test_stripe_insufficient_units_error_attributes(self) -> None:
        err = StripeInsufficientUnitsError("org-x", have=10, need=20)
        assert err.org_id == "org-x"
        assert err.have == 10
        assert err.need == 20
        assert isinstance(err, StripeServiceError)

    def test_stripe_insufficient_units_message(self) -> None:
        err = StripeInsufficientUnitsError("org-y", have=0, need=5)
        assert "insufficient" in str(err).lower()
        assert "org-y" in str(err)

    def test_stripe_payment_method_not_found_attributes(self) -> None:
        err = StripePaymentMethodNotFoundError("pm_missing")
        assert err.payment_method_id == "pm_missing"
        assert isinstance(err, StripeServiceError)

    def test_stripe_idempotency_error_attributes(self) -> None:
        err = StripeIdempotencyError("idem-key-123", "conflicting payload")
        assert err.idempotency_key == "idem-key-123"
        assert isinstance(err, StripeServiceError)

    def test_stripe_webhook_signature_error_is_service_error(self) -> None:
        err = StripeWebhookSignatureError("bad sig")
        assert isinstance(err, StripeServiceError)

    def test_stripe_config_error_is_service_error(self) -> None:
        err = StripeConfigError("no key")
        assert isinstance(err, StripeServiceError)

    def test_stripe_session_not_found_is_service_error(self) -> None:
        err = StripeSessionNotFoundError("cs_gone")
        assert isinstance(err, StripeServiceError)

    def test_stripe_subscription_not_found_is_service_error(self) -> None:
        err = StripeSubscriptionNotFoundError("sub_gone")
        assert isinstance(err, StripeServiceError)

    def test_stripe_api_error_raw_defaults_to_empty_dict(self) -> None:
        err = StripeAPIError("msg")
        assert err.raw == {}

    def test_stripe_api_error_http_status_defaults_zero(self) -> None:
        err = StripeAPIError("msg")
        assert err.http_status == 0


# ===========================================================================
# Section 16 — Payment methods
# ===========================================================================


class TestPaymentMethods:
    def test_attach_payment_method_returns_response(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        resp = svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        assert isinstance(resp, PaymentMethodResponse)
        assert resp.payment_method_id == _TEST_PM_ID
        assert resp.customer_id == _TEST_CUSTOMER_ID

    def test_attach_payment_method_stores_locally(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        methods = svc_with_client.list_payment_methods(_TEST_CUSTOMER_ID)
        assert any(m.payment_method_id == _TEST_PM_ID for m in methods)

    def test_attach_payment_method_calls_stripe(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        call_path = mock_client.post.call_args[0][0]
        assert "/attach" in call_path
        assert _TEST_PM_ID in call_path

    def test_attach_payment_method_idempotent_same_payload(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        r1 = svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        r2 = svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        assert r1.payment_method_id == r2.payment_method_id
        assert mock_client.post.call_count == 1

    def test_attach_payment_method_set_as_default(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        # attach (1 post) + set_default customer update (1 post) = 2 total
        mock_client.post.side_effect = [
            _mock_pm_resp(),
            {},  # /customers/{id} update from set_default_payment_method
        ]
        resp = svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID, set_as_default=True)
        assert resp.is_default is True

    def test_detach_payment_method_removes_from_cache(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        mock_client.post.return_value = {}
        svc_with_client.detach_payment_method(_TEST_PM_ID)
        methods = svc_with_client.list_payment_methods(_TEST_CUSTOMER_ID)
        assert all(m.payment_method_id != _TEST_PM_ID for m in methods)

    def test_detach_payment_method_not_found_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripePaymentMethodNotFoundError):
            svc.detach_payment_method("pm_nonexistent")

    def test_list_payment_methods_empty_when_none_attached(self, svc: StripeService) -> None:
        assert svc.list_payment_methods("cus_empty") == []

    def test_list_payment_methods_filters_by_customer(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.side_effect = [_mock_pm_resp(_TEST_PM_ID, "cus_A"), _mock_pm_resp(_TEST_PM_ID_2, "cus_B")]
        svc_with_client.attach_payment_method("cus_A", _TEST_PM_ID)
        svc_with_client.attach_payment_method("cus_B", _TEST_PM_ID_2)
        methods_a = svc_with_client.list_payment_methods("cus_A")
        assert len(methods_a) == 1
        assert methods_a[0].customer_id == "cus_A"

    def test_set_default_payment_method_marks_default(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.side_effect = [
            _mock_pm_resp(_TEST_PM_ID),
            _mock_pm_resp(_TEST_PM_ID_2),
            {},  # /customers/{id} update from set_default_payment_method
        ]
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID_2)
        resp = svc_with_client.set_default_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID_2)
        assert resp.is_default is True

    def test_set_default_clears_previous_default(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        # Call sequence:
        # 1. attach pm1 → /payment_methods/pm1/attach
        # 2. set_default (triggered by set_as_default=True) → /customers/{id}
        # 3. attach pm2 → /payment_methods/pm2/attach
        # 4. set_default pm2 → /customers/{id}
        mock_client.post.side_effect = [
            _mock_pm_resp(_TEST_PM_ID),  # call 1: attach pm1
            {},  # call 2: /customers/{id} for set_default of pm1
            _mock_pm_resp(_TEST_PM_ID_2),  # call 3: attach pm2
            {},  # call 4: /customers/{id} for set_default of pm2
        ]
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID, set_as_default=True)
        svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID_2)
        svc_with_client.set_default_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID_2)
        methods = svc_with_client.list_payment_methods(_TEST_CUSTOMER_ID)
        defaults = [m for m in methods if m.is_default]
        assert len(defaults) == 1
        assert defaults[0].payment_method_id == _TEST_PM_ID_2

    def test_set_default_not_found_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripePaymentMethodNotFoundError):
            svc.set_default_payment_method(_TEST_CUSTOMER_ID, "pm_ghost")

    def test_payment_method_response_has_schema_version(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        resp = svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        assert resp.schema_version == "1.0"

    def test_payment_method_response_to_dict(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = _mock_pm_resp()
        resp = svc_with_client.attach_payment_method(_TEST_CUSTOMER_ID, _TEST_PM_ID)
        d = resp.to_dict()
        assert d["payment_method_id"] == _TEST_PM_ID
        assert d["brand"] == "visa"
        assert d["last4"] == "4242"


# ===========================================================================
# Section 17 — Invoices
# ===========================================================================


class TestInvoices:
    def test_get_invoices_returns_list(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        results = svc_with_client.get_invoices_for_org(_TEST_ORG)
        assert isinstance(results, list)
        assert len(results) == 2

    def test_get_invoices_returns_invoice_response_objects(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        results = svc_with_client.get_invoices_for_org(_TEST_ORG)
        assert all(isinstance(r, InvoiceResponse) for r in results)

    def test_get_invoices_cached_on_second_call(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        svc_with_client.get_invoices_for_org(_TEST_ORG)
        svc_with_client.get_invoices_for_org(_TEST_ORG)
        assert mock_client.get.call_count == 1

    def test_get_invoices_force_refresh_bypasses_cache(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        svc_with_client.get_invoices_for_org(_TEST_ORG)
        svc_with_client.get_invoices_for_org(_TEST_ORG, force_refresh=True)
        assert mock_client.get.call_count == 2

    def test_get_invoices_empty_when_no_customer_mapping(self, svc_with_client: StripeService) -> None:
        results = svc_with_client.get_invoices_for_org("org-no-customer")
        assert results == []

    def test_get_invoices_org_id_set_correctly(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        results = svc_with_client.get_invoices_for_org(_TEST_ORG)
        assert all(r.org_id == _TEST_ORG for r in results)

    def test_invalidate_invoice_cache_specific_org(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        svc_with_client.get_invoices_for_org(_TEST_ORG)
        svc_with_client.invalidate_invoice_cache(_TEST_ORG)
        svc_with_client.get_invoices_for_org(_TEST_ORG)
        assert mock_client.get.call_count == 2

    def test_invalidate_invoice_cache_all(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        for org in ("org-inv-1", "org-inv-2"):
            svc_with_client.register_customer_mapping(org, f"cus_{org}")
            mock_client.get.return_value = _mock_invoice_list(f"cus_{org}")
            svc_with_client.get_invoices_for_org(org)
        svc_with_client.invalidate_invoice_cache()
        assert svc_with_client._invoice_cache == {}

    def test_invoice_response_has_schema_version(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        results = svc_with_client.get_invoices_for_org(_TEST_ORG)
        assert all(r.schema_version == "1.0" for r in results)

    def test_invoice_response_to_dict(self, svc_with_client: StripeService, mock_client: MagicMock) -> None:
        svc_with_client.register_customer_mapping(_TEST_ORG, _TEST_CUSTOMER_ID)
        mock_client.get.return_value = _mock_invoice_list()
        results = svc_with_client.get_invoices_for_org(_TEST_ORG)
        d = results[0].to_dict()
        assert "invoice_id" in d
        assert "org_id" in d
        assert d["currency"] == "usd"


# ===========================================================================
# Section 18 — StripeWebhookEventType enum completeness
# ===========================================================================


class TestStripeWebhookEventType:
    def test_checkout_session_completed_value(self) -> None:
        assert StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED == "checkout.session.completed"

    def test_checkout_session_expired_value(self) -> None:
        assert StripeWebhookEventType.CHECKOUT_SESSION_EXPIRED == "checkout.session.expired"

    def test_invoice_paid_value(self) -> None:
        assert StripeWebhookEventType.INVOICE_PAID == "invoice.paid"

    def test_invoice_payment_failed_value(self) -> None:
        assert StripeWebhookEventType.INVOICE_PAYMENT_FAILED == "invoice.payment_failed"

    def test_invoice_upcoming_value(self) -> None:
        assert StripeWebhookEventType.INVOICE_UPCOMING == "invoice.upcoming"

    def test_customer_subscription_created_value(self) -> None:
        assert StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_CREATED == "customer.subscription.created"

    def test_customer_subscription_updated_value(self) -> None:
        assert StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_UPDATED == "customer.subscription.updated"

    def test_customer_subscription_deleted_value(self) -> None:
        assert StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_DELETED == "customer.subscription.deleted"

    def test_customer_created_value(self) -> None:
        assert StripeWebhookEventType.CUSTOMER_CREATED == "customer.created"

    def test_customer_updated_value(self) -> None:
        assert StripeWebhookEventType.CUSTOMER_UPDATED == "customer.updated"

    def test_charge_refunded_value(self) -> None:
        assert StripeWebhookEventType.CHARGE_REFUNDED == "charge.refunded"

    def test_payment_intent_succeeded_value(self) -> None:
        assert StripeWebhookEventType.PAYMENT_INTENT_SUCCEEDED == "payment_intent.succeeded"

    def test_payment_intent_payment_failed_value(self) -> None:
        assert StripeWebhookEventType.PAYMENT_INTENT_PAYMENT_FAILED == "payment_intent.payment_failed"

    def test_all_event_types_are_strings(self) -> None:
        for member in StripeWebhookEventType:
            assert isinstance(member.value, str)

    def test_all_event_types_count(self) -> None:
        # 13 enum members — assert completeness
        assert len(list(StripeWebhookEventType)) == 13
