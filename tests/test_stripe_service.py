from __future__ import annotations

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
    CheckoutSessionResponse,
    StripeAPIError,
    StripeBillingInterval,
    StripeCheckoutMode,
    StripeConfigError,
    StripeService,
    StripeServiceError,
    StripeSubscriptionStatus,
    StripeUnitEventReason,
    SubscriptionResponse,
    _new_id,
    _StripeHTTPClient,
    _utcnow_iso,
    get_stripe_service,
    reset_stripe_service,
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
_TEST_PRICE_ID = "price_test_abc123"
_TEST_SUCCESS_URL = "https://example.com/success"
_TEST_CANCEL_URL = "https://example.com/cancel"
_TEST_CUSTOMER_ID = "cus_test_abc123"
_TEST_SUB_ID = "sub_test_abc123"
_TEST_SESSION_ID = "cs_test_abc123"
_TEST_WEBHOOK_SECRET = "whsec_testsecret1234567890abcdefghij"
_TEST_API_KEY = "sk_test_ironclaw_key_abc123456789"

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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_service() -> None:
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

    def test_debit_units_decreases_balance(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_TEAM_UNITS, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units(_TEST_ORG, _PKG_STARTER_UNITS, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == _PKG_TEAM_UNITS - _PKG_STARTER_UNITS

    def test_debit_units_insufficient_raises(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, 10, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeServiceError, match="insufficient"):
            svc.debit_units(_TEST_ORG, 11, StripeUnitEventReason.METERED_SYNC)

    def test_debit_units_zero_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc.debit_units(_TEST_ORG, 0, StripeUnitEventReason.METERED_SYNC)

    def test_get_unit_balance_default_zero(self, svc: StripeService) -> None:
        resp = svc.get_unit_balance("org-new-unknown")
        assert resp.balance == 0

    def test_get_unit_balance_reflects_credits(self, svc: StripeService) -> None:
        svc.credit_units(_TEST_ORG, _PKG_TEAM_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        resp = svc.get_unit_balance(_TEST_ORG)
        assert resp.balance == _PKG_TEAM_UNITS

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

    def test_module_reset_clears_singleton_state(self) -> None:
        svc = get_stripe_service()
        svc.credit_units("org-module-reset", _PKG_STARTER_UNITS, StripeUnitEventReason.MANUAL_CREDIT)
        reset_stripe_service()
        assert get_stripe_service().get_unit_balance("org-module-reset").balance == 0


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


# ===========================================================================
# Section 14 — units_for_tokens() boundary conditions
# ===========================================================================


class TestUnitsForTokens:
    """
    Each protection unit covers exactly TOKENS_PER_UNIT (25,000) tokens.
    Any partial chunk beyond a full unit consumes an additional whole unit
    (ceiling division). This section validates every boundary condition.
    """

    def _units_for_tokens(self, token_count: int) -> int:
        if token_count <= 0:
            return 0
        return math.ceil(token_count / _TOKENS_PER_UNIT)

    def test_zero_tokens_requires_zero_units(self) -> None:
        assert self._units_for_tokens(0) == 0

    def test_negative_tokens_requires_zero_units(self) -> None:
        assert self._units_for_tokens(-1) == 0

    def test_one_token_requires_one_unit(self) -> None:
        assert self._units_for_tokens(1) == 1

    def test_exact_one_chunk_requires_one_unit(self) -> None:
        assert self._units_for_tokens(25_000) == 1

    def test_one_over_first_chunk_requires_two_units(self) -> None:
        assert self._units_for_tokens(25_001) == 2

    def test_exact_two_chunks_requires_two_units(self) -> None:
        assert self._units_for_tokens(50_000) == 2

    def test_one_over_two_chunks_requires_three_units(self) -> None:
        assert self._units_for_tokens(50_001) == 3

    def test_exact_three_chunks_requires_three_units(self) -> None:
        assert self._units_for_tokens(75_000) == 3

    def test_one_over_three_chunks_requires_four_units(self) -> None:
        assert self._units_for_tokens(75_001) == 4

    def test_non_multiple_mid_chunk(self) -> None:
        assert self._units_for_tokens(12_500) == 1

    def test_non_multiple_straddles_boundary(self) -> None:
        assert self._units_for_tokens(37_500) == 2

    def test_starter_package_token_ceiling(self) -> None:
        max_tokens = _PKG_STARTER_UNITS * _TOKENS_PER_UNIT
        assert self._units_for_tokens(max_tokens) == _PKG_STARTER_UNITS

    def test_starter_package_one_over_ceiling(self) -> None:
        max_tokens = _PKG_STARTER_UNITS * _TOKENS_PER_UNIT
        assert self._units_for_tokens(max_tokens + 1) == _PKG_STARTER_UNITS + 1

    def test_team_package_token_ceiling(self) -> None:
        max_tokens = _PKG_TEAM_UNITS * _TOKENS_PER_UNIT
        assert self._units_for_tokens(max_tokens) == _PKG_TEAM_UNITS

    def test_enterprise_package_token_ceiling(self) -> None:
        max_tokens = _PKG_ENTERPRISE_UNITS * _TOKENS_PER_UNIT
        assert self._units_for_tokens(max_tokens) == _PKG_ENTERPRISE_UNITS
