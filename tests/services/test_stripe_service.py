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
    PACKAGE_CATALOGUE,
    StripeInsufficientUnitsError,
    StripeService,
    StripeServiceError,
    StripeUnitEventReason,
    StripeWebhookEventType,
    UnitBalanceResponse,
    WebhookVerifyResult,
    _StripeHTTPClient,
    units_for_tokens,
)
from app.supabaseclient import TOKENS_PER_UNIT

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_ORG = "org-svc-stripe-test-001"
_CUSTOMER_ID = "cus_svctest_abc123"
_SUB_ID = "sub_svctest_abc123"
_WEBHOOK_SECRET = "whsec_svctest_secret1234567890abcde"
_API_KEY = "sk_test_svctest_key_abcdefgh123456"
_TOLERANCE = 300


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sig(secret: str, payload: bytes, timestamp: int | None = None) -> str:
    ts = timestamp if timestamp is not None else int(time.time())
    signed = f"{ts}.".encode() + payload
    sig = _hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _vault_mock(secret: str = _WEBHOOK_SECRET, tolerance: str = str(_TOLERANCE)) -> MagicMock:
    m = MagicMock()

    def _get(key: str, default: str | None = None) -> str | None:
        return {
            "STRIPE_WEBHOOK_SECRET": secret,
            "STRIPE_WEBHOOK_TOLERANCE_SECONDS": tolerance,
        }.get(key, default or "")

    m.get.side_effect = _get
    return m


def _build_invoice_paid_event(
    *,
    customer_id: str = _CUSTOMER_ID,
    sub_id: str = _SUB_ID,
    unit_credits: int = 0,
    amount_paid: int = 9000,
) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "id": "in_svctest_001",
        "customer": customer_id,
        "subscription": sub_id,
        "amount_paid": amount_paid,
        "metadata": {},
    }
    if unit_credits:
        obj["metadata"]["unit_credits"] = str(unit_credits)
    return {"id": "evt_inv_paid", "type": StripeWebhookEventType.INVOICE_PAID.value, "data": {"object": obj}}


def _build_checkout_completed_event(
    *,
    org_id: str = _ORG,
    customer_id: str = _CUSTOMER_ID,
    unit_credits: int = 0,
    session_id: str = "cs_svctest_001",
) -> dict[str, Any]:
    return {
        "id": "evt_co_done",
        "type": StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED.value,
        "data": {
            "object": {
                "id": session_id,
                "mode": "payment",
                "customer": customer_id,
                "metadata": {
                    "org_id": org_id,
                    "unit_credits": str(unit_credits),
                },
            }
        },
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def svc() -> StripeService:
    s = StripeService()
    s.reset()
    return s


@pytest.fixture()
def mock_client() -> MagicMock:
    return MagicMock(spec=_StripeHTTPClient)


@pytest.fixture()
def svc_wired(svc: StripeService, mock_client: MagicMock) -> StripeService:
    svc._override_client(mock_client)
    return svc


# ===========================================================================
# Section A — units_for_tokens() boundary cases
# ===========================================================================


class TestUnitsForTokensBoundary:
    def test_zero_tokens_returns_zero_units(self) -> None:
        assert units_for_tokens(0) == 0

    def test_negative_tokens_returns_zero_units(self) -> None:
        assert units_for_tokens(-1) == 0
        assert units_for_tokens(-999) == 0
        assert units_for_tokens(-25_000) == 0

    def test_one_token_requires_one_unit(self) -> None:
        assert units_for_tokens(1) == 1

    def test_exact_25000_tokens_requires_one_unit(self) -> None:
        assert units_for_tokens(25_000) == 1

    def test_25001_tokens_requires_two_units(self) -> None:
        assert units_for_tokens(25_001) == 2

    def test_exact_75000_tokens_requires_three_units(self) -> None:
        assert units_for_tokens(75_000) == 3

    def test_1_000_000_tokens_requires_40_units(self) -> None:
        assert units_for_tokens(1_000_000) == 40

    def test_result_equals_ceil_division(self) -> None:
        for n in [1, 100, 12_500, 24_999, 25_000, 25_001, 49_999, 50_000, 50_001, 74_999, 75_000, 75_001]:
            expected = math.ceil(n / TOKENS_PER_UNIT)
            assert units_for_tokens(n) == expected, f"failed for n={n}"


# ===========================================================================
# Section B — credit_units / debit_units happy path and ledger correctness
# ===========================================================================


class TestCreditDebitHappyPath:
    def test_credit_units_increases_balance(self, svc: StripeService) -> None:
        resp = svc.credit_units(_ORG, 500, StripeUnitEventReason.CHECKOUT_COMPLETE)
        assert isinstance(resp, UnitBalanceResponse)
        assert resp.balance == 500
        assert resp.org_id == _ORG

    def test_credit_units_accumulates_correctly(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 200, StripeUnitEventReason.MANUAL_CREDIT)
        resp = svc.credit_units(_ORG, 300, StripeUnitEventReason.MANUAL_CREDIT)
        assert resp.balance == 500

    def test_debit_units_reduces_balance(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 1000, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units(_ORG, 400, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == 600

    def test_debit_units_exact_balance_reaches_zero(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 100, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units(_ORG, 100, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == 0

    def test_credit_ledger_entry_correct(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 750, StripeUnitEventReason.SUBSCRIPTION_RENEWED, reference_id="ref-cred-01")
        resp = svc.get_unit_balance(_ORG)
        assert len(resp.ledger_entries) == 1
        entry = resp.ledger_entries[0]
        assert entry["delta"] == 750
        assert entry["balance_after"] == 750
        assert entry["reason"] == StripeUnitEventReason.SUBSCRIPTION_RENEWED.value
        assert entry["reference_id"] == "ref-cred-01"
        assert entry["org_id"] == _ORG
        assert "entry_id" in entry
        assert "recorded_at" in entry

    def test_debit_ledger_entry_has_negative_delta(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 1000, StripeUnitEventReason.CHECKOUT_COMPLETE)
        svc.debit_units(_ORG, 250, StripeUnitEventReason.METERED_SYNC, reference_id="ref-deb-01")
        resp = svc.get_unit_balance(_ORG)
        debit_entry = next(e for e in resp.ledger_entries if e["delta"] < 0)
        assert debit_entry["delta"] == -250
        assert debit_entry["balance_after"] == 750
        assert debit_entry["reason"] == StripeUnitEventReason.METERED_SYNC.value
        assert debit_entry["reference_id"] == "ref-deb-01"

    def test_ledger_entries_ordered_chronologically(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 100, StripeUnitEventReason.MANUAL_CREDIT)
        svc.credit_units(_ORG, 200, StripeUnitEventReason.MANUAL_CREDIT)
        svc.credit_units(_ORG, 300, StripeUnitEventReason.MANUAL_CREDIT)
        resp = svc.get_unit_balance(_ORG)
        balance_afters = [e["balance_after"] for e in resp.ledger_entries]
        assert balance_afters == [100, 300, 600]

    def test_ledger_capped_at_50_entries(self, svc: StripeService) -> None:
        for _ in range(60):
            svc.credit_units(_ORG, 1, StripeUnitEventReason.MANUAL_CREDIT)
        resp = svc.get_unit_balance(_ORG)
        assert len(resp.ledger_entries) <= 50

    def test_ledger_isolated_per_org(self, svc: StripeService) -> None:
        svc.credit_units("org-aa", 100, StripeUnitEventReason.MANUAL_CREDIT)
        svc.credit_units("org-bb", 200, StripeUnitEventReason.MANUAL_CREDIT)
        resp_aa = svc.get_unit_balance("org-aa")
        resp_bb = svc.get_unit_balance("org-bb")
        assert resp_aa.balance == 100
        assert resp_bb.balance == 200
        assert all(e["org_id"] == "org-aa" for e in resp_aa.ledger_entries)
        assert all(e["org_id"] == "org-bb" for e in resp_bb.ledger_entries)


# ===========================================================================
# Section C — debit_units raises StripeInsufficientUnitsError on shortfall
# ===========================================================================


class TestDebitInsufficientUnits:
    def test_debit_over_balance_raises_insufficient_units_error(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 10, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units(_ORG, 11, StripeUnitEventReason.METERED_SYNC)

    def test_raises_insufficient_units_error_not_bare_service_error(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 5, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError) as exc_info:
            svc.debit_units(_ORG, 6, StripeUnitEventReason.METERED_SYNC)
        assert type(exc_info.value) is StripeInsufficientUnitsError

    def test_insufficient_error_is_subclass_of_service_error(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 1, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeServiceError):
            svc.debit_units(_ORG, 2, StripeUnitEventReason.METERED_SYNC)

    def test_insufficient_error_carries_org_have_need(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 7, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError) as exc_info:
            svc.debit_units(_ORG, 10, StripeUnitEventReason.METERED_SYNC)
        err = exc_info.value
        assert err.org_id == _ORG
        assert err.have == 7
        assert err.need == 10

    def test_zero_balance_org_debit_raises(self, svc: StripeService) -> None:
        with pytest.raises(StripeInsufficientUnitsError) as exc_info:
            svc.debit_units(_ORG, 1, StripeUnitEventReason.METERED_SYNC)
        assert exc_info.value.have == 0
        assert exc_info.value.need == 1

    def test_balance_unchanged_after_failed_debit(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 5, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units(_ORG, 6, StripeUnitEventReason.METERED_SYNC)
        assert svc.get_unit_balance(_ORG).balance == 5

    def test_ledger_unchanged_after_failed_debit(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 5, StripeUnitEventReason.CHECKOUT_COMPLETE)
        pre_count = len(svc.get_unit_balance(_ORG).ledger_entries)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units(_ORG, 100, StripeUnitEventReason.METERED_SYNC)
        post_count = len(svc.get_unit_balance(_ORG).ledger_entries)
        assert post_count == pre_count


# ===========================================================================
# Section D — on_insufficient_units callback fires before raising
# ===========================================================================


class TestOnInsufficientUnitsCallback:
    def test_callback_fires_on_shortfall(self) -> None:
        fired: list[tuple[str, int, int]] = []

        def _cb(org_id: str, have: int, need: int) -> None:
            fired.append((org_id, have, need))

        svc = StripeService(on_insufficient_units=_cb)
        svc.credit_units(_ORG, 3, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units(_ORG, 5, StripeUnitEventReason.METERED_SYNC)

        assert len(fired) == 1
        assert fired[0] == (_ORG, 3, 5)

    def test_callback_fires_before_exception_propagates(self) -> None:
        sequence: list[str] = []

        def _cb(org_id: str, have: int, need: int) -> None:
            sequence.append("callback")

        svc = StripeService(on_insufficient_units=_cb)
        svc.credit_units(_ORG, 1, StripeUnitEventReason.CHECKOUT_COMPLETE)
        try:
            svc.debit_units(_ORG, 2, StripeUnitEventReason.METERED_SYNC)
        except StripeInsufficientUnitsError:
            sequence.append("exception")

        assert sequence == ["callback", "exception"]

    def test_callback_not_fired_when_sufficient_balance(self) -> None:
        fired: list[Any] = []

        def _cb(org_id: str, have: int, need: int) -> None:
            fired.append((org_id, have, need))

        svc = StripeService(on_insufficient_units=_cb)
        svc.credit_units(_ORG, 100, StripeUnitEventReason.CHECKOUT_COMPLETE)
        svc.debit_units(_ORG, 50, StripeUnitEventReason.METERED_SYNC)
        assert fired == []

    def test_callback_receives_correct_org_have_need(self) -> None:
        received: list[tuple[str, int, int]] = []

        def _cb(org_id: str, have: int, need: int) -> None:
            received.append((org_id, have, need))

        svc = StripeService(on_insufficient_units=_cb)
        svc.credit_units("org-cb-exact", 42, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units("org-cb-exact", 99, StripeUnitEventReason.METERED_SYNC)

        assert received[0] == ("org-cb-exact", 42, 99)

    def test_callback_exception_does_not_swallow_insufficient_error(self) -> None:
        def _cb_raises(org_id: str, have: int, need: int) -> None:
            raise RuntimeError("callback exploded")

        svc = StripeService(on_insufficient_units=_cb_raises)
        svc.credit_units(_ORG, 1, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units(_ORG, 5, StripeUnitEventReason.METERED_SYNC)

    def test_no_callback_set_still_raises_insufficient_error(self) -> None:
        svc = StripeService()
        svc.credit_units(_ORG, 1, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units(_ORG, 2, StripeUnitEventReason.METERED_SYNC)


# ===========================================================================
# Section E — debit_units_for_tokens edge cases
# ===========================================================================


class TestDebitUnitsForTokens:
    def test_negative_token_count_logs_warning_returns_zero_debit(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 100, StripeUnitEventReason.CHECKOUT_COMPLETE)
        import logging

        with patch.object(logging.getLogger("app.services.stripe_service"), "warning") as mock_warn:
            resp = svc.debit_units_for_tokens(_ORG, -50, StripeUnitEventReason.METERED_SYNC)

        mock_warn.assert_called_once()
        call_args = mock_warn.call_args
        assert "negative" in call_args[0][0].lower() or "-50" in str(call_args)
        assert resp.balance == 100
        assert resp.org_id == _ORG

    def test_negative_token_count_does_not_debit_balance(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 200, StripeUnitEventReason.CHECKOUT_COMPLETE)
        pre_ledger_len = len(svc.get_unit_balance(_ORG).ledger_entries)
        svc.debit_units_for_tokens(_ORG, -1, StripeUnitEventReason.METERED_SYNC)
        assert svc.get_unit_balance(_ORG).balance == 200
        assert len(svc.get_unit_balance(_ORG).ledger_entries) == pre_ledger_len

    def test_zero_token_count_returns_balance_without_debit(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 150, StripeUnitEventReason.CHECKOUT_COMPLETE)
        pre_ledger_len = len(svc.get_unit_balance(_ORG).ledger_entries)
        resp = svc.debit_units_for_tokens(_ORG, 0, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == 150
        assert len(svc.get_unit_balance(_ORG).ledger_entries) == pre_ledger_len

    def test_zero_token_count_returns_current_balance_response(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 999, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units_for_tokens(_ORG, 0, StripeUnitEventReason.METERED_SYNC)
        assert isinstance(resp, UnitBalanceResponse)
        assert resp.balance == 999

    def test_25000_tokens_debits_one_unit(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 10, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units_for_tokens(_ORG, 25_000, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == 9

    def test_25001_tokens_debits_two_units(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 10, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units_for_tokens(_ORG, 25_001, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == 8

    def test_insufficient_balance_for_tokens_raises(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 1, StripeUnitEventReason.CHECKOUT_COMPLETE)
        with pytest.raises(StripeInsufficientUnitsError):
            svc.debit_units_for_tokens(_ORG, 50_001, StripeUnitEventReason.METERED_SYNC)

    def test_negative_large_value_treated_as_zero(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 50, StripeUnitEventReason.CHECKOUT_COMPLETE)
        resp = svc.debit_units_for_tokens(_ORG, -1_000_000, StripeUnitEventReason.METERED_SYNC)
        assert resp.balance == 50


# ===========================================================================
# Section F — _handle_invoice_paid credits renewal_units_credited
# ===========================================================================


class TestHandleInvoicePaid:
    def _register_sub(self, svc: StripeService, *, org_id: str = _ORG) -> None:
        from app.services.stripe_service import StripeBillingInterval, StripeSubscriptionStatus

        svc.register_customer_mapping(org_id, _CUSTOMER_ID)
        svc.upsert_subscription(
            subscription_id=_SUB_ID,
            org_id=org_id,
            customer_id=_CUSTOMER_ID,
            price_id="price_svctest_001",
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2026-01-01T00:00:00Z",
            current_period_end="2026-02-01T00:00:00Z",
        )

    def test_invoice_paid_with_unit_credits_metadata_credits_org(self, svc: StripeService) -> None:
        self._register_sub(svc)
        event = _build_invoice_paid_event(unit_credits=500)
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 500

    def test_invoice_paid_unit_credits_ledger_reason_subscription_renewed(self, svc: StripeService) -> None:
        self._register_sub(svc)
        event = _build_invoice_paid_event(unit_credits=250)
        svc.handle_webhook_event(event)
        resp = svc.get_unit_balance(_ORG)
        assert any(e["reason"] == StripeUnitEventReason.SUBSCRIPTION_RENEWED.value for e in resp.ledger_entries)

    def test_invoice_paid_without_unit_credits_metadata_no_credit(self, svc: StripeService) -> None:
        self._register_sub(svc)
        event = _build_invoice_paid_event(unit_credits=0)
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_invoice_paid_credits_exact_amount_from_metadata(self, svc: StripeService) -> None:
        self._register_sub(svc)
        event = _build_invoice_paid_event(unit_credits=1337)
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 1337

    def test_invoice_paid_result_action_is_processed(self, svc: StripeService) -> None:
        self._register_sub(svc)
        event = _build_invoice_paid_event(unit_credits=100)
        result = svc.handle_webhook_event(event)
        assert result["action"] == "processed"


# ===========================================================================
# Section G — _handle_checkout_completed credits units and returns tokens_covered
# ===========================================================================


class TestHandleCheckoutCompleted:
    def test_checkout_completed_credits_units(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=5_000)
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 5_000

    def test_checkout_completed_zero_credits_no_balance_change(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=0)
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_checkout_completed_result_action_processed(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=100)
        result = svc.handle_webhook_event(event)
        assert result["action"] == "processed"

    def test_checkout_completed_tokens_covered_equals_units_times_tokens_per_unit(self, svc: StripeService) -> None:
        unit_credits = 25
        event = _build_checkout_completed_event(unit_credits=unit_credits)
        svc.handle_webhook_event(event)
        expected_tokens = unit_credits * TOKENS_PER_UNIT
        resp = svc.get_unit_balance(_ORG)
        assert resp.balance == unit_credits
        assert resp.balance * TOKENS_PER_UNIT == expected_tokens

    def test_checkout_completed_registers_customer_mapping(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=50, customer_id=_CUSTOMER_ID)
        svc.handle_webhook_event(event)
        resolved = svc.resolve_org_from_customer(_CUSTOMER_ID)
        assert resolved == _ORG

    def test_checkout_completed_multiple_events_accumulate_balance(self, svc: StripeService) -> None:
        for _ in range(3):
            svc.handle_webhook_event(_build_checkout_completed_event(unit_credits=100))
        assert svc.get_unit_balance(_ORG).balance == 300


# ===========================================================================
# Section H — verify_webhook_signature valid and invalid paths
# ===========================================================================


class TestVerifyWebhookSignatureService:
    def test_valid_signature_returns_valid_true(self, svc: StripeService) -> None:
        body = {"id": "evt_valid_1", "type": "invoice.paid", "data": {"object": {}}}
        payload = json.dumps(body).encode()
        sig = _make_sig(_WEBHOOK_SECRET, payload)
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, sig)
        assert isinstance(result, WebhookVerifyResult)
        assert result.valid is True
        assert result.event_type == "invoice.paid"
        assert result.event_id == "evt_valid_1"
        assert result.error is None

    def test_valid_signature_payload_present_in_result(self, svc: StripeService) -> None:
        body = {"id": "evt_valid_2", "type": "checkout.session.completed", "data": {"object": {"amount": 9000}}}
        payload = json.dumps(body).encode()
        sig = _make_sig(_WEBHOOK_SECRET, payload)
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is True
        assert result.payload.get("id") == "evt_valid_2"

    def test_bad_secret_returns_invalid_with_mismatch_error(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_bad_1","type":"invoice.paid","data":{"object":{}}}'
        sig = _make_sig("wrong-secret-that-is-definitely-not-correct", payload)
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False
        assert result.error is not None
        assert "mismatch" in result.error.lower()

    def test_expired_timestamp_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_exp_1","type":"invoice.paid","data":{"object":{}}}'
        old_ts = int(time.time()) - (_TOLERANCE + 60)
        sig = _make_sig(_WEBHOOK_SECRET, payload, timestamp=old_ts)
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False
        assert result.error is not None

    def test_future_timestamp_beyond_tolerance_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_fut_1","type":"invoice.paid","data":{"object":{}}}'
        future_ts = int(time.time()) + (_TOLERANCE + 60)
        sig = _make_sig(_WEBHOOK_SECRET, payload, timestamp=future_ts)
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False

    def test_malformed_header_no_t_field_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_mal_1","type":"invoice.paid","data":{"object":{}}}'
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, "not-a-stripe-sig-at-all")
        assert result.valid is False
        assert result.error is not None

    def test_malformed_header_missing_v1_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_mal_2","type":"invoice.paid","data":{"object":{}}}'
        ts = int(time.time())
        malformed = f"t={ts},v0=deadbeef"
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, malformed)
        assert result.valid is False

    def test_empty_sig_header_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_empty_1","type":"invoice.paid","data":{"object":{}}}'
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, "")
        assert result.valid is False

    def test_invalid_json_payload_returns_invalid(self, svc: StripeService) -> None:
        payload = b"this-is-not-json"
        sig = _make_sig(_WEBHOOK_SECRET, payload)
        with patch("app.services.stripe_service.vault", _vault_mock()):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False

    def test_missing_webhook_secret_returns_invalid(self, svc: StripeService) -> None:
        payload = b'{"id":"evt_nocfg_1","type":"invoice.paid","data":{"object":{}}}'
        sig = _make_sig(_WEBHOOK_SECRET, payload)
        empty_vault = MagicMock()
        empty_vault.get.return_value = ""
        with patch("app.services.stripe_service.vault", empty_vault):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False


# ===========================================================================
# Section I — reset() clears all state including _client
# ===========================================================================


class TestResetClearsAllState:
    def test_reset_clears_unit_balances(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 999, StripeUnitEventReason.MANUAL_CREDIT)
        svc.reset()
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_reset_clears_unit_ledger(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 100, StripeUnitEventReason.MANUAL_CREDIT)
        svc.reset()
        assert svc.get_unit_balance(_ORG).ledger_entries == []

    def test_reset_clears_subscriptions(self, svc: StripeService) -> None:
        from app.services.stripe_service import StripeBillingInterval, StripeSubscriptionStatus

        svc.upsert_subscription(
            subscription_id=_SUB_ID,
            org_id=_ORG,
            customer_id=_CUSTOMER_ID,
            price_id="price_rst_001",
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2026-01-01T00:00:00Z",
            current_period_end="2026-02-01T00:00:00Z",
        )
        svc.reset()
        assert svc.get_subscription(_SUB_ID) is None

    def test_reset_clears_customer_org_maps(self, svc: StripeService) -> None:
        svc.register_customer_mapping("org-rst-a", "cus_rst_a")
        svc.reset()
        assert svc.resolve_org_from_customer("cus_rst_a") is None
        assert svc._org_customer_map == {}
        assert svc._customer_org_map == {}

    def test_reset_clears_client_reference(self, svc: StripeService) -> None:
        mock_client = MagicMock(spec=_StripeHTTPClient)
        svc._override_client(mock_client)
        assert svc._client is mock_client
        svc.reset()
        assert svc._client is None

    def test_reset_clears_checkout_sessions(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {
            "id": "cs_rst_001",
            "url": "https://checkout.stripe.com/rst",
            "customer": _CUSTOMER_ID,
            "expires_at": int(time.time()) + 1800,
        }
        svc_wired.create_checkout_session(
            org_id=_ORG,
            price_id="price_rst_002",
            success_url="https://example.com/ok",
            cancel_url="https://example.com/cancel",
        )
        svc_wired.reset()
        assert svc_wired.get_checkout_session("cs_rst_001") is None

    def test_reset_clears_metered_usage_log(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": "mbur_rst_001"}
        svc_wired.report_metered_usage(_ORG, "si_rst_001", quantity=10)
        svc_wired.reset()
        assert svc_wired.get_metered_usage_log() == []

    def test_reset_allows_fresh_credit_after_clear(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 500, StripeUnitEventReason.MANUAL_CREDIT)
        svc.reset()
        svc.credit_units(_ORG, 100, StripeUnitEventReason.MANUAL_CREDIT)
        assert svc.get_unit_balance(_ORG).balance == 100


# ===========================================================================
# Section J — Thread safety: concurrent credit/debit produces correct balance
# ===========================================================================


class TestThreadSafety:
    def test_concurrent_credits_produce_correct_final_balance(self, svc: StripeService) -> None:
        n_threads = 50
        amount_per_thread = 10
        errors: list[Exception] = []

        def _credit() -> None:
            try:
                svc.credit_units(_ORG, amount_per_thread, StripeUnitEventReason.MANUAL_CREDIT)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_credit) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert svc.get_unit_balance(_ORG).balance == n_threads * amount_per_thread

    def test_concurrent_debits_produce_correct_final_balance(self, svc: StripeService) -> None:
        n_threads = 20
        amount_per_thread = 5
        initial_balance = n_threads * amount_per_thread
        svc.credit_units(_ORG, initial_balance, StripeUnitEventReason.MANUAL_CREDIT)
        errors: list[Exception] = []

        def _debit() -> None:
            try:
                svc.debit_units(_ORG, amount_per_thread, StripeUnitEventReason.METERED_SYNC)
            except StripeInsufficientUnitsError:
                pass
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_debit) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_concurrent_mixed_credits_and_debits_no_negative_balance(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 1000, StripeUnitEventReason.MANUAL_CREDIT)
        errors: list[Exception] = []

        def _mixed(index: int) -> None:
            try:
                if index % 2 == 0:
                    svc.credit_units(_ORG, 1, StripeUnitEventReason.MANUAL_CREDIT)
                else:
                    svc.debit_units(_ORG, 1, StripeUnitEventReason.METERED_SYNC)
            except StripeInsufficientUnitsError:
                pass
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_mixed, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert svc.get_unit_balance(_ORG).balance >= 0

    def test_concurrent_credits_ledger_entry_count_matches_threads(self, svc: StripeService) -> None:
        n_threads = 30
        errors: list[Exception] = []

        def _credit() -> None:
            try:
                svc.credit_units(_ORG, 1, StripeUnitEventReason.MANUAL_CREDIT)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_credit) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        resp = svc.get_unit_balance(_ORG)
        assert len(resp.ledger_entries) == n_threads


# ===========================================================================
# Section K — PACKAGE_CATALOGUE tokens_per_unit == TOKENS_PER_UNIT
# ===========================================================================


class TestPackageCatalogueTokensPerUnit:
    def test_all_catalogue_entries_have_tokens_per_unit_key(self) -> None:
        for name, entry in PACKAGE_CATALOGUE.items():
            assert "tokens_per_unit" in entry, f"missing tokens_per_unit in catalogue entry '{name}'"

    def test_starter_tokens_per_unit_equals_constant(self) -> None:
        assert PACKAGE_CATALOGUE["starter"]["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_team_tokens_per_unit_equals_constant(self) -> None:
        assert PACKAGE_CATALOGUE["team"]["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_enterprise_tokens_per_unit_equals_constant(self) -> None:
        assert PACKAGE_CATALOGUE["enterprise"]["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_all_entries_tokens_per_unit_equals_25000(self) -> None:
        for name, entry in PACKAGE_CATALOGUE.items():
            assert entry["tokens_per_unit"] == 25_000, f"PACKAGE_CATALOGUE['{name}']['tokens_per_unit'] is {entry['tokens_per_unit']}, expected 25_000"

    def test_tokens_per_unit_constant_is_25000(self) -> None:
        assert TOKENS_PER_UNIT == 25_000

    def test_catalogue_contains_all_three_tiers(self) -> None:
        assert set(PACKAGE_CATALOGUE.keys()) == {"starter", "team", "enterprise"}

    def test_catalogue_tokens_per_unit_consistent_across_all_tiers(self) -> None:
        tpu_values = {entry["tokens_per_unit"] for entry in PACKAGE_CATALOGUE.values()}
        assert len(tpu_values) == 1, f"tokens_per_unit is not uniform across tiers: {tpu_values}"
        assert tpu_values.pop() == TOKENS_PER_UNIT
