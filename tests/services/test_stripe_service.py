from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import math
import os
import threading
import time
from types import SimpleNamespace
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
    InvoiceResponse,
    PaymentMethodResponse,
    StripeAPIError,
    StripeBillingInterval,
    StripeIdempotencyError,
    StripeInsufficientUnitsError,
    StripePaymentMethodNotFoundError,
    StripePersistenceError,
    StripeService,
    StripeServiceError,
    StripeSessionNotFoundError,
    StripeSubscriptionNotFoundError,
    StripeSubscriptionStatus,
    StripeUnitEventReason,
    StripeWebhookEventType,
    SubscriptionResponse,
    UnitBalanceResponse,
    WebhookVerifyResult,
    _PaymentMethodRecord,
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
_PM_ID = "pm_svctest_card_001"
_INVOICE_ID = "in_svctest_inv_001"
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
        "id": _INVOICE_ID,
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
    event_id: str = "evt_co_done",
    owner_key: str | None = None,
    payment_intent: str | None = "pi_svctest_001",
) -> dict[str, Any]:
    metadata = {
        "org_id": org_id,
        "unit_credits": str(unit_credits),
        "package_id": "pkg_5000",
        "ironclaw_checkout_version": "1",
        "ironclaw_checkout_price_id": "price_test_package",
        "ironclaw_checkout_quantity": "1",
        "ironclaw_checkout_mode": "payment",
    }
    if owner_key is not None:
        metadata["owner_key"] = owner_key
    integrity_payload = {
        "version": metadata["ironclaw_checkout_version"],
        "org_id": metadata["org_id"],
        "owner_key": str(metadata.get("owner_key") or "").strip().lower(),
        "package_id": metadata["package_id"],
        "price_id": metadata["ironclaw_checkout_price_id"],
        "quantity": metadata["ironclaw_checkout_quantity"],
        "unit_credits": metadata["unit_credits"],
        "mode": metadata["ironclaw_checkout_mode"],
    }
    signed_payload = json.dumps(integrity_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    metadata["ironclaw_checkout_signature"] = _hmac.new(
        _WEBHOOK_SECRET.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "id": event_id,
        "type": StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED.value,
        "data": {
            "object": {
                "id": session_id,
                "mode": "payment",
                "customer": customer_id,
                "payment_intent": payment_intent,
                "payment_status": "paid",
                "metadata": metadata,
            }
        },
    }


def _build_charge_refunded_event(
    *,
    customer_id: str = _CUSTOMER_ID,
    amount_refunded: int = 2000,
) -> dict[str, Any]:
    return {
        "id": "evt_charge_refunded_001",
        "type": "charge.refunded",
        "data": {
            "object": {
                "id": "ch_svctest_001",
                "customer": customer_id,
                "amount_refunded": amount_refunded,
                "refunded": True,
            }
        },
    }


def _build_customer_updated_event(
    *,
    customer_id: str = _CUSTOMER_ID,
    org_id: str = _ORG,
    email: str = "updated@example.com",
) -> dict[str, Any]:
    return {
        "id": "evt_cust_updated_001",
        "type": StripeWebhookEventType.CUSTOMER_UPDATED.value,
        "data": {
            "object": {
                "id": customer_id,
                "email": email,
                "metadata": {"org_id": org_id},
            }
        },
    }


def _build_payment_method_record(
    pm_id: str = _PM_ID,
    customer_id: str = _CUSTOMER_ID,
    is_default: bool = False,
) -> _PaymentMethodRecord:
    return _PaymentMethodRecord(
        payment_method_id=pm_id,
        customer_id=customer_id,
        type="card",
        brand="visa",
        last4="4242",
        exp_month=12,
        exp_year=2028,
        is_default=is_default,
        created_at="2026-01-01T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def svc(monkeypatch: pytest.MonkeyPatch) -> StripeService:
    s = StripeService()
    s.reset()
    s.set_webhook_secret(_WEBHOOK_SECRET)
    fulfillments: dict[str, dict[str, Any]] = {}

    def record_checkout(**record: Any) -> dict[str, Any]:
        session_id = str(record["session_id"])
        existing = fulfillments.get(session_id)
        if existing is not None:
            for field in ("owner_key", "org_id", "package_id", "units"):
                if existing[field] != record[field]:
                    raise ValueError("checkout fulfillment immutable fields changed")
            if existing.get("payment_intent") and record.get("payment_intent"):
                if existing["payment_intent"] != record["payment_intent"]:
                    raise ValueError("checkout PaymentIntent changed")
        else:
            existing = dict(record)
            existing.update(
                fulfillment_status="pending",
                payment_status="pending",
                units_credited=False,
                install_keys_provisioned=False,
            )
            fulfillments[session_id] = existing
        if record.get("payment_intent") and s._wallet_registry.is_payment_refunded(  # noqa: SLF001
            record["payment_intent"],
        ):
            existing.update(fulfillment_status="refunded", payment_status="refunded")
        elif record.get("payment_intent"):
            existing["payment_intent"] = record["payment_intent"]
        return dict(existing)

    def mark_checkout(session_id: str, **updates: Any) -> dict[str, Any]:
        record = fulfillments[session_id]
        payment_intent = record.get("payment_intent")
        is_refunded = payment_intent and s._wallet_registry.is_payment_refunded(payment_intent)  # noqa: SLF001
        if record.get("fulfillment_status") == "refunded" or is_refunded:
            record.update(fulfillment_status="refunded", payment_status="refunded")
        else:
            record.update(updates)
            record["fulfillment_status"] = updates.get("status", record["fulfillment_status"])
            if updates.get("status") in {"payment_confirmed", "wallet_credited", "fulfilled"}:
                record["payment_status"] = "paid"
        return dict(record)

    def get_fulfillment_by_payment_intent(payment_intent: str) -> dict[str, Any] | None:
        return next(
            (dict(record) for record in fulfillments.values() if record.get("payment_intent") == payment_intent),
            None,
        )

    monkeypatch.setattr(s, "_is_payment_intent_refunded", lambda _: False)
    monkeypatch.setattr(s, "_record_checkout_fulfillment", record_checkout)
    monkeypatch.setattr(s, "_verify_checkout_fulfillment_storage", lambda: None)
    monkeypatch.setattr(s, "_mark_checkout_fulfillment", mark_checkout)
    monkeypatch.setattr(
        s,
        "_get_checkout_fulfillment_by_payment_intent",
        get_fulfillment_by_payment_intent,
    )
    return s


@pytest.fixture()
def mock_client() -> MagicMock:
    return MagicMock(spec=_StripeHTTPClient)


@pytest.fixture()
def svc_wired(svc: StripeService, mock_client: MagicMock) -> StripeService:
    svc._override_client(mock_client)
    return svc


@pytest.fixture()
def svc_with_sub(svc: StripeService) -> StripeService:
    svc.register_customer_mapping(_ORG, _CUSTOMER_ID)
    svc.upsert_subscription(
        subscription_id=_SUB_ID,
        org_id=_ORG,
        customer_id=_CUSTOMER_ID,
        price_id="price_svctest_001",
        status=StripeSubscriptionStatus.ACTIVE,
        billing_interval=StripeBillingInterval.MONTHLY,
        current_period_start="2026-01-01T00:00:00Z",
        current_period_end="2026-02-01T00:00:00Z",
    )
    return svc


class _FakeCustomerLinkQuery:
    def __init__(self, rows: list[dict[str, str]]) -> None:
        self._rows = rows
        self._filters: dict[str, str] = {}

    def select(self, _columns: str) -> _FakeCustomerLinkQuery:
        return self

    def eq(self, column: str, value: str) -> _FakeCustomerLinkQuery:
        self._filters[column] = value
        return self

    def limit(self, _count: int) -> _FakeCustomerLinkQuery:
        return self

    def upsert(self, payload: dict[str, str], *, on_conflict: str | None = None, returning: str | None = None) -> _FakeCustomerLinkQuery:
        self._rows[:] = [row for row in self._rows if row["org_id"] != payload["org_id"]]
        self._rows.append(dict(payload))
        return self

    def execute(self) -> SimpleNamespace:
        rows = [row for row in self._rows if all(row.get(k) == v for k, v in self._filters.items())]
        return SimpleNamespace(data=rows)


class _FakeCustomerLinkClient:
    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def table(self, name: str) -> _FakeCustomerLinkQuery:
        assert name == "stripe_customer_links"
        return _FakeCustomerLinkQuery(self.rows)


class TestCustomerLinkPersistence:
    @pytest.fixture()
    def link_store(self, monkeypatch: pytest.MonkeyPatch) -> _FakeCustomerLinkClient:
        client = _FakeCustomerLinkClient()
        monkeypatch.setattr("app.services.stripe_service._should_use_memory_fallback", lambda: False)
        monkeypatch.setattr("app.services.stripe_service.get_supabase_service_client", lambda: client)
        return client

    def test_registered_mapping_is_persisted_and_reloaded_after_memory_reset(self, svc: StripeService, link_store: _FakeCustomerLinkClient) -> None:
        svc.register_customer_mapping(_ORG, _CUSTOMER_ID)
        assert link_store.rows == [{"org_id": _ORG, "customer_id": _CUSTOMER_ID}]

        svc.reset()

        assert svc.resolve_customer_id(_ORG) == _CUSTOMER_ID
        assert svc.resolve_org_from_customer(_CUSTOMER_ID) == _ORG

    def test_get_or_create_reuses_persisted_customer_instead_of_creating_duplicate(self, svc_wired: StripeService, mock_client: MagicMock, link_store: _FakeCustomerLinkClient) -> None:
        link_store.rows.append({"org_id": _ORG, "customer_id": _CUSTOMER_ID})

        assert svc_wired.get_or_create_stripe_customer(_ORG) == _CUSTOMER_ID
        mock_client.post.assert_not_called()

    def test_customer_creation_uses_stable_stripe_idempotency_key(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        mock_client.post.return_value = {"id": _CUSTOMER_ID}

        assert svc_wired.get_or_create_stripe_customer(_ORG) == _CUSTOMER_ID

        call = mock_client.post.call_args
        assert call.kwargs["idempotency_key"].startswith("ironclaw-customer-")
        assert len(call.kwargs["idempotency_key"]) == len("ironclaw-customer-") + 64

    def test_customer_link_write_failure_is_not_cached_when_durable_storage_required(
        self,
        svc: StripeService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("IRONCLAW_PERSISTENCE_MODE", "supabase")
        monkeypatch.setattr("app.services.stripe_service._should_use_memory_fallback", lambda: False)

        class _BrokenClient:
            def table(self, _name: str):
                raise RuntimeError("database unavailable")

        monkeypatch.setattr("app.services.stripe_service.get_supabase_service_client", lambda: _BrokenClient())

        with pytest.raises(StripeServiceError, match="could not be persisted"):
            svc.register_customer_mapping(_ORG, _CUSTOMER_ID)

        assert _ORG not in svc._org_customer_map
        assert _CUSTOMER_ID not in svc._customer_org_map


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

    def test_checkout_units_credited_sums_only_matching_session(self, svc: StripeService) -> None:
        svc.credit_units(_ORG, 500, StripeUnitEventReason.CHECKOUT_COMPLETE, reference_id="cs_test_units")
        svc.credit_units(_ORG, 200, StripeUnitEventReason.CHECKOUT_COMPLETE, reference_id="cs_test_other")
        assert svc.get_checkout_units_credited("cs_test_units", _ORG) == 500
        assert svc.get_checkout_units_credited("cs_test_missing", _ORG) == 0

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
    def test_invoice_paid_with_unit_credits_metadata_credits_org(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=500)
        svc_with_sub.handle_webhook_event(event)
        assert svc_with_sub.get_unit_balance(_ORG).balance == 500

    def test_invoice_paid_unit_credits_ledger_reason_subscription_renewed(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=250)
        svc_with_sub.handle_webhook_event(event)
        resp = svc_with_sub.get_unit_balance(_ORG)
        assert any(e["reason"] == StripeUnitEventReason.SUBSCRIPTION_RENEWED.value for e in resp.ledger_entries)

    def test_invoice_paid_without_unit_credits_metadata_no_credit(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=0)
        svc_with_sub.handle_webhook_event(event)
        assert svc_with_sub.get_unit_balance(_ORG).balance == 0

    def test_invoice_paid_credits_exact_amount_from_metadata(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=1337)
        svc_with_sub.handle_webhook_event(event)
        assert svc_with_sub.get_unit_balance(_ORG).balance == 1337

    def test_invoice_paid_result_action_is_processed(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=100)
        result = svc_with_sub.handle_webhook_event(event)
        assert result["action"] == "processed"

    def test_invoice_paid_renewal_credit_path_uses_subscription_id_as_reference(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=200, sub_id=_SUB_ID)
        svc_with_sub.handle_webhook_event(event)
        resp = svc_with_sub.get_unit_balance(_ORG)
        entry = next(
            (e for e in resp.ledger_entries if e["reason"] == StripeUnitEventReason.SUBSCRIPTION_RENEWED.value),
            None,
        )
        assert entry is not None
        assert entry["reference_id"] == _SUB_ID or entry["reference_id"] == _INVOICE_ID

    def test_handle_webhook_event_duplicate_event_id_returns_duplicate_action(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=100)
        svc_with_sub.handle_webhook_event(event)
        result = svc_with_sub.handle_webhook_event(event)
        assert result["action"] == "duplicate"

    def test_handle_webhook_event_duplicate_does_not_double_credit(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=100)
        svc_with_sub.handle_webhook_event(event)
        svc_with_sub.handle_webhook_event(event)
        assert svc_with_sub.get_unit_balance(_ORG).balance == 100


# ===========================================================================
# Section G — _handle_checkout_completed credits units and returns tokens_covered
# ===========================================================================


class TestHandleCheckoutCompleted:
    def test_refund_marker_removes_checkout_from_active_credited_units(
        self,
        svc: StripeService,
    ) -> None:
        payment_intent = "pi_checkout_units_refunded_001"
        session_id = "cs_checkout_units_refunded_001"
        svc.credit_units(
            _ORG,
            5_000,
            StripeUnitEventReason.CHECKOUT_COMPLETE,
            reference_id=session_id,
            owner_key=_ORG,
            package_id="pkg_5000",
            payment_intent=payment_intent,
        )
        svc._wallet_registry.mark_payment_refunded(  # noqa: SLF001
            payment_intent,
            amount_refunded=2_000,
        )

        assert svc.get_checkout_units_credited(session_id, _ORG, owner_key=_ORG) == 0

    def test_refund_marker_prevents_later_checkout_credit(
        self,
        svc: StripeService,
    ) -> None:
        payment_intent = "pi_refunded_before_credit_001"
        svc._wallet_registry.mark_payment_refunded(  # noqa: SLF001
            payment_intent,
            amount_refunded=2_000,
        )

        result = svc.handle_webhook_event(
            _build_checkout_completed_event(
                unit_credits=5_000,
                session_id="cs_refunded_before_credit_001",
                payment_intent=payment_intent,
                owner_key="buyer@ironclaw.test",
            ),
        )

        assert result["action"] == "processed"
        assert result["detail"]["fulfillment_status"] == "refunded"
        assert result["detail"]["units_credited"] == 0
        assert svc._wallet_registry.get_wallet("buyer@ironclaw.test") is None  # noqa: SLF001

    def test_refunded_payment_intent_is_not_fulfilled(
        self,
        svc: StripeService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(svc, "_is_payment_intent_refunded", lambda _: True)
        provisioning_service = MagicMock()
        monkeypatch.setattr(
            "app.services.stripe_service.provision_install_key_service",
            lambda *args, **kwargs: provisioning_service,
        )

        result = svc.handle_webhook_event(_build_checkout_completed_event(unit_credits=5_000))

        assert result["action"] == "processed"
        assert result["detail"]["payment_confirmed"] is True
        assert result["detail"]["fulfillment_status"] == "refunded"
        assert result["detail"]["units_credited"] == 0
        assert svc.get_unit_balance(_ORG).balance == 0
        provisioning_service.provision_for_program.assert_not_called()

    def test_paid_checkout_without_payment_intent_fails_closed(self, svc: StripeService) -> None:
        result = svc.handle_webhook_event(
            _build_checkout_completed_event(unit_credits=5_000, payment_intent=None),
        )

        assert result["action"] == "error"
        assert "PaymentIntent" in result["error"]
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_checkout_completed_credits_units(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=5_000)
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 5_000

    def test_checkout_completed_success_credits_wallet_and_issues_paid_install_keys(self, svc: StripeService, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_provision(*args: Any, **kwargs: Any) -> MagicMock:
            record = MagicMock()
            record.key_id = f"ik_{kwargs['program']}_001"
            record.owner_key = kwargs["owner_key"]
            record.program = kwargs["program"]
            record.active = True
            record.masked_key = f"ic_install_{kwargs['program']}...1234"
            record.subscription_id = kwargs["subscription_id"]
            issued = MagicMock()
            issued.record = record
            return issued

        monkeypatch.setattr(
            "app.services.stripe_service.provision_install_key_service",
            lambda *args, **kwargs: MagicMock(provision_for_program=fake_provision),
        )

        owner_key = "buyer@ironclaw.test"
        event = _build_checkout_completed_event(
            unit_credits=5_000,
            org_id="org-install-keys-success",
            owner_key=owner_key,
        )
        result = svc.handle_webhook_event(event)

        assert result["action"] == "processed"
        owner_wallet = svc._wallet_registry.get_wallet(owner_key)  # noqa: SLF001
        assert owner_wallet is not None
        assert owner_wallet.balance_units == 5_000
        assert svc.get_unit_balance("org-install-keys-success").balance == 0
        install_keys = result["detail"]["install_key_issuance"]
        assert install_keys["openclaw"]["owner_key"] == owner_key
        assert install_keys["claude_code"]["owner_key"] == owner_key
        assert install_keys["openclaw"]["active"] is True
        assert install_keys["claude_code"]["active"] is True

    def test_checkout_completed_key_provisioning_failure_is_reported_for_retry(self, svc: StripeService, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_fail(*args: Any, **kwargs: Any) -> MagicMock:
            raise RuntimeError("persistence write-order failure")

        monkeypatch.setattr(
            "app.services.stripe_service.provision_install_key_service",
            lambda *args, **kwargs: MagicMock(provision_for_program=fake_fail),
        )

        event = _build_checkout_completed_event(unit_credits=5_000, org_id="org-install-keys-partial-fail")
        result = svc.handle_webhook_event(event)

        assert result["action"] == "error"
        assert "install_key_issuance" not in result
        assert svc.get_unit_balance("org-install-keys-partial-fail").balance == 5_000

    def test_checkout_completed_retries_failed_key_provisioning_without_double_credit(
        self,
        svc: StripeService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls = 0

        def fake_fail_once(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("persistence write-order failure")

            record = MagicMock()
            record.key_id = f"ik_{kwargs['program']}_001"
            record.owner_key = kwargs["owner_key"]
            record.program = kwargs["program"]
            record.active = True
            record.masked_key = f"ic_install_{kwargs['program']}_...1234"
            record.subscription_id = kwargs["subscription_id"]
            issued = MagicMock()
            issued.record = record
            return issued

        monkeypatch.setattr(
            "app.services.stripe_service.provision_install_key_service",
            lambda *args, **kwargs: MagicMock(provision_for_program=fake_fail_once),
        )

        event = _build_checkout_completed_event(unit_credits=2_000, org_id="org-replay-no-double-credit")
        first = svc.handle_webhook_event(event)
        second = svc.handle_webhook_event(event)

        assert first["action"] == "error"
        assert second["action"] == "processed"
        assert svc.get_unit_balance("org-replay-no-double-credit").balance == 2_000
        assert len(second["detail"]["install_key_issuance"]) == 7

    def test_checkout_completed_issues_paid_install_keys_for_org_owner(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=5_000, org_id="org-install-keys")
        result = svc.handle_webhook_event(event)
        install_keys = result["detail"]["install_key_issuance"]
        assert install_keys["openclaw"]["owner_key"] == "ic_org_org-install-keys"
        assert install_keys["claude_code"]["owner_key"] == "ic_org_org-install-keys"
        assert install_keys["openclaw"]["active"] is True
        assert install_keys["claude_code"]["active"] is True

    def test_checkout_completed_issues_all_supported_runtime_install_keys(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=5_000, org_id="org-install-keys-all")
        result = svc.handle_webhook_event(event)
        install_keys = result["detail"]["install_key_issuance"]
        expected_programs = {
            "openclaw",
            "claude_code",
            "cursor",
            "goose",
            "gemini_cli",
            "copilot",
            "hermes",
        }
        assert set(install_keys) == expected_programs
        assert "security_guardian" not in install_keys
        assert all(record["owner_key"] == "ic_org_org-install-keys-all" for record in install_keys.values())
        assert all(record["active"] is True for record in install_keys.values())

    def test_unrefunded_payment_intent_returns_false(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        payment_intent_id = "pi_refund_check_001"
        mock_client.get.return_value = {
            "id": payment_intent_id,
            "status": "succeeded",
            "latest_charge": {
                "id": "ch_refund_check_001",
                "payment_intent": payment_intent_id,
                "refunded": False,
                "amount_refunded": 0,
            },
        }

        assert StripeService._is_payment_intent_refunded(svc_wired, payment_intent_id) is False
        mock_client.get.assert_called_once_with(
            f"/payment_intents/{payment_intent_id}",
            params={"expand[]": "latest_charge"},
        )

    def test_partial_refund_is_not_eligible_for_unit_fulfillment(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        payment_intent_id = "pi_refund_check_002"
        mock_client.get.return_value = {
            "id": payment_intent_id,
            "status": "succeeded",
            "latest_charge": {
                "id": "ch_refund_check_002",
                "payment_intent": payment_intent_id,
                "refunded": False,
                "amount_refunded": 1,
            },
        }

        assert StripeService._is_payment_intent_refunded(svc_wired, payment_intent_id) is True

    def test_charge_is_retrieved_when_not_expanded(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        payment_intent_id = "pi_refund_check_003"
        mock_client.get.side_effect = [
            {
                "id": payment_intent_id,
                "status": "succeeded",
                "latest_charge": "ch_refund_check_003",
            },
            {
                "id": "ch_refund_check_003",
                "payment_intent": payment_intent_id,
                "refunded": True,
                "amount_refunded": 5_000,
            },
        ]

        assert StripeService._is_payment_intent_refunded(svc_wired, payment_intent_id) is True
        assert mock_client.get.call_args_list[1].args == ("/charges/ch_refund_check_003",)

    def test_stripe_failure_fails_closed(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        mock_client.get.side_effect = StripeAPIError(
            "Stripe unavailable",
            http_status=503,
        )

        with pytest.raises(StripeServiceError, match="fulfillment was not applied"):
            StripeService._is_payment_intent_refunded(svc_wired, "pi_refund_check_004")

    def test_invalid_payment_intent_id_is_rejected_without_stripe_request(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        with pytest.raises(StripeServiceError, match="invalid PaymentIntent ID"):
            StripeService._is_payment_intent_refunded(svc_wired, "pi_bad/../../charges")

        mock_client.get.assert_not_called()

    def test_issue_paid_install_keys_uses_canonical_provisioning_path_for_runtime_programs_only(self, svc: StripeService, monkeypatch: pytest.MonkeyPatch) -> None:
        provisioning_service = MagicMock()
        issued = MagicMock()
        issued.record = MagicMock(
            key_id="ik_runtime_1",
            owner_key="ic_org_org-runtime-route",
            program="openclaw",
            active=True,
            masked_key="ic_install_openclaw_...1234",
            subscription_id="checkout:cs_runtime_001",
        )
        provisioning_service.provision_for_program.return_value = issued
        monkeypatch.setattr("app.services.stripe_service.provision_install_key_service", lambda *args, **kwargs: provisioning_service)

        result = svc._issue_paid_install_keys_for_checkout(  # noqa: SLF001
            org_id="org-runtime-route",
            customer_id=_CUSTOMER_ID,
            session_id="cs_runtime_001",
            unit_credits=500,
            metadata={"payment_status": "paid"},
        )

        assert set(result) == {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes"}
        assert "security_guardian" not in result
        assert provisioning_service.provision_for_program.call_count == 7
        assert all(call.kwargs["owner_key"] == "ic_org_org-runtime-route" for call in provisioning_service.provision_for_program.call_args_list)
        assert all(call.kwargs["payment_confirmed"] is True for call in provisioning_service.provision_for_program.call_args_list)

    def test_issue_paid_install_keys_failure_in_one_program_does_not_block_others(self, svc: StripeService, monkeypatch: pytest.MonkeyPatch) -> None:
        provisioning_service = MagicMock()

        def fake_provision(**kwargs: Any) -> MagicMock:
            if kwargs["program"] == "copilot":
                raise RuntimeError("persistence write-order failure")
            issued = MagicMock()
            issued.record = MagicMock(
                key_id=f"ik_{kwargs['program']}_001",
                owner_key=kwargs["owner_key"],
                program=kwargs["program"],
                active=True,
                masked_key=f"ic_install_{kwargs['program']}_...1234",
                subscription_id=kwargs["subscription_id"],
            )
            return issued

        provisioning_service.provision_for_program.side_effect = fake_provision
        monkeypatch.setattr("app.services.stripe_service.provision_install_key_service", lambda *args, **kwargs: provisioning_service)

        with pytest.raises(StripeServiceError, match="copilot"):
            svc._issue_paid_install_keys_for_checkout(  # noqa: SLF001
                org_id="org-partial-program",
                customer_id=_CUSTOMER_ID,
                session_id="cs_partial_program_001",
                unit_credits=500,
                metadata={"payment_status": "paid"},
            )

        assert provisioning_service.provision_for_program.call_count == 7

    def test_issue_paid_install_keys_requires_successful_payment_confirmation(self, svc: StripeService) -> None:
        result = svc._issue_paid_install_keys_for_checkout(  # noqa: SLF001
            org_id="org-no-subscription",
            customer_id=_CUSTOMER_ID,
            session_id="cs_missing_entitlement",
            unit_credits=500,
            metadata={"payment_status": "paid"},
        )
        assert result["openclaw"]["owner_key"] == "ic_org_org-no-subscription"
        assert result["claude_code"]["owner_key"] == "ic_org_org-no-subscription"

    def test_issue_paid_install_keys_skips_missing_or_pending_payment_status(self, svc: StripeService) -> None:
        assert (
            svc._issue_paid_install_keys_for_checkout(  # noqa: SLF001
                org_id=_ORG,
                customer_id=_CUSTOMER_ID,
                session_id="cs_missing_status",
                unit_credits=500,
                metadata={},
            )
            == {}
        )
        assert (
            svc._issue_paid_install_keys_for_checkout(  # noqa: SLF001
                org_id=_ORG,
                customer_id=_CUSTOMER_ID,
                session_id="cs_pending_status",
                unit_credits=500,
                metadata={"payment_status": "pending"},
            )
            == {}
        )

    def test_checkout_completed_pending_payment_never_issues_install_keys(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(
            unit_credits=500,
            org_id="org-pending-checkout",
            session_id="cs_pending_001",
            event_id="evt_co_pending",
        )
        event["data"]["object"]["payment_status"] = "pending"

        result = svc.handle_webhook_event(event)
        assert result["action"] == "processed"
        assert "install_key_issuance" not in result["detail"]
        assert svc.get_unit_balance("org-pending-checkout").balance == 0

    def test_checkout_completed_status_alone_does_not_confirm_payment(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(
            unit_credits=500,
            org_id="org-status-not-payment",
        )
        checkout = event["data"]["object"]
        checkout.pop("payment_status")
        checkout["status"] = "complete"

        result = svc.handle_webhook_event(event)

        assert result["action"] == "processed"
        assert result["detail"]["payment_confirmed"] is False
        assert "install_key_issuance" not in result["detail"]
        assert svc.get_unit_balance("org-status-not-payment").balance == 0

    def test_async_payment_success_uses_confirmed_checkout_fulfillment(
        self,
        svc: StripeService,
    ) -> None:
        event = _build_checkout_completed_event(
            unit_credits=500,
            org_id="org-async-payment",
        )
        event["type"] = StripeWebhookEventType.CHECKOUT_SESSION_ASYNC_PAYMENT_SUCCEEDED.value

        result = svc.handle_webhook_event(event)

        assert result["action"] == "processed"
        assert result["detail"]["payment_confirmed"] is True
        assert svc.get_unit_balance("org-async-payment").balance == 500

    def test_checkout_completed_zero_credits_no_balance_change(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=0)
        result = svc.handle_webhook_event(event)
        assert result["action"] == "error"
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_checkout_completed_rejects_tampered_unit_metadata(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=100)
        event["data"]["object"]["metadata"]["unit_credits"] = "100000"

        result = svc.handle_webhook_event(event)

        assert result["action"] == "error"
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_checkout_completed_rejects_unsigned_legacy_metadata(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=100)
        event["data"]["object"]["metadata"].pop("ironclaw_checkout_signature")

        result = svc.handle_webhook_event(event)

        assert result["action"] == "error"
        assert svc.get_unit_balance(_ORG).balance == 0

    def test_checkout_completed_rejects_tampered_owner_metadata(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=100, owner_key="buyer@ironclaw.test")
        event["data"]["object"]["metadata"]["owner_key"] = "victim@ironclaw.test"

        result = svc.handle_webhook_event(event)

        assert result["action"] == "error"
        assert svc._wallet_registry.get_wallet("victim@ironclaw.test") is None  # noqa: SLF001

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
        for i in range(3):
            svc.handle_webhook_event(
                _build_checkout_completed_event(
                    unit_credits=100,
                    session_id=f"cs_svctest_multi_{i:03d}",
                    event_id=f"evt_co_done_{i:03d}",
                )
            )
        assert svc.get_unit_balance(_ORG).balance == 300

    def test_handle_webhook_event_duplicate_checkout_returns_duplicate_action(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=200)
        svc.handle_webhook_event(event)
        result = svc.handle_webhook_event(event)
        assert result["action"] == "duplicate"

    def test_handle_webhook_event_duplicate_checkout_does_not_double_credit(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=200)
        svc.handle_webhook_event(event)
        svc.handle_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 200


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

    def test_missing_webhook_secret_returns_invalid(self) -> None:
        svc = StripeService()
        payload = b'{"id":"evt_nocfg_1","type":"invoice.paid","data":{"object":{}}}'
        sig = _make_sig(_WEBHOOK_SECRET, payload)
        empty_vault = MagicMock()
        empty_vault.get.return_value = ""
        with patch("app.services.stripe_service.vault", empty_vault):
            result = svc.verify_webhook_signature(payload, sig)
        assert result.valid is False


# ===========================================================================
# Section I — reset() clears all state including new fields
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
        assert svc.get_subscription(_SUB_ID, strict=False) is None

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

    def test_reset_clears_payment_methods(self, svc: StripeService) -> None:
        svc._payment_methods[_PM_ID] = _build_payment_method_record()
        svc.reset()
        assert svc._payment_methods == {}

    def test_reset_clears_invoice_cache(self, svc: StripeService) -> None:
        svc._invoice_cache[_ORG] = [{"id": "in_dummy"}]
        svc.reset()
        assert svc._invoice_cache == {}

    def test_reset_clears_idempotency_store(self, svc: StripeService) -> None:
        if hasattr(svc, "_idempotency_keys"):
            svc._idempotency_keys["idem-key-001"] = "result"
            svc.reset()
            assert svc._idempotency_keys == {}

    def test_reset_clears_processed_event_ids(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=100)
        svc.handle_webhook_event(event)
        svc.reset()
        assert svc._processed_event_ids == set()

    def test_reset_allows_event_reprocessing_after_clear(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=100)
        svc.handle_webhook_event(event)
        svc.reset()
        svc.set_webhook_secret(_WEBHOOK_SECRET)
        result = svc.handle_webhook_event(event)
        assert result["action"] == "processed"
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


# ===========================================================================
# Section L — _PaymentMethodRecord and PaymentMethodResponse dataclasses
# ===========================================================================


class TestPaymentMethodDataclasses:
    def test_payment_method_record_instantiation(self) -> None:
        record = _build_payment_method_record()
        assert record.payment_method_id == _PM_ID
        assert record.customer_id == _CUSTOMER_ID
        assert record.type == "card"
        assert record.brand == "visa"
        assert record.last4 == "4242"
        assert record.exp_month == 12
        assert record.exp_year == 2028
        assert record.is_default is False

    def test_payment_method_record_to_dict_all_keys_present(self) -> None:
        record = _build_payment_method_record()
        d = record.to_dict()
        for key in ("payment_method_id", "customer_id", "type", "brand", "last4", "exp_month", "exp_year", "is_default", "created_at"):
            assert key in d, f"missing key '{key}' in _PaymentMethodRecord.to_dict()"

    def test_payment_method_record_default_flag(self) -> None:
        record = _build_payment_method_record(is_default=True)
        assert record.is_default is True
        assert record.to_dict()["is_default"] is True

    def test_payment_method_response_instantiation(self) -> None:
        resp = PaymentMethodResponse(
            payment_method_id=_PM_ID,
            customer_id=_CUSTOMER_ID,
            type="card",
            brand="visa",
            last4="4242",
            exp_month=12,
            exp_year=2028,
            is_default=False,
            created_at="2026-01-01T00:00:00Z",
        )
        assert resp.payment_method_id == _PM_ID
        assert resp.schema_version is not None

    def test_payment_method_response_to_dict_has_schema_version(self) -> None:
        resp = PaymentMethodResponse(
            payment_method_id=_PM_ID,
            customer_id=_CUSTOMER_ID,
            type="card",
            brand="visa",
            last4="4242",
            exp_month=12,
            exp_year=2028,
            is_default=False,
            created_at="2026-01-01T00:00:00Z",
        )
        d = resp.to_dict()
        assert "schema_version" in d


# ===========================================================================
# Section M — InvoiceResponse dataclass
# ===========================================================================


class TestInvoiceResponseDataclass:
    def test_invoice_response_instantiation(self) -> None:
        resp = InvoiceResponse(
            invoice_id=_INVOICE_ID,
            org_id=_ORG,
            customer_id=_CUSTOMER_ID,
            subscription_id=_SUB_ID,
            amount_paid=9000,
            currency="usd",
            status="paid",
            created_at="2026-01-01T00:00:00Z",
        )
        assert resp.invoice_id == _INVOICE_ID
        assert resp.org_id == _ORG
        assert resp.schema_version is not None

    def test_invoice_response_to_dict_all_keys_present(self) -> None:
        resp = InvoiceResponse(
            invoice_id=_INVOICE_ID,
            org_id=_ORG,
            customer_id=_CUSTOMER_ID,
            subscription_id=_SUB_ID,
            amount_paid=9000,
            currency="usd",
            status="paid",
            created_at="2026-01-01T00:00:00Z",
        )
        d = resp.to_dict()
        for key in ("invoice_id", "org_id", "customer_id", "subscription_id", "amount_paid", "currency", "status", "created_at", "schema_version"):
            assert key in d, f"missing key '{key}' in InvoiceResponse.to_dict()"


# ===========================================================================
# Section N — attach_payment_method
# ===========================================================================


class TestAttachPaymentMethod:
    def test_attach_payment_method_returns_payment_method_response(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {
            "id": _PM_ID,
            "type": "card",
            "card": {"brand": "visa", "last4": "4242", "exp_month": 12, "exp_year": 2028},
            "customer": _CUSTOMER_ID,
        }
        result = svc_wired.attach_payment_method(customer_id=_CUSTOMER_ID, payment_method_id=_PM_ID)
        assert isinstance(result, PaymentMethodResponse)
        assert result.payment_method_id == _PM_ID
        assert result.customer_id == _CUSTOMER_ID

    def test_attach_payment_method_stored_in_service(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {
            "id": _PM_ID,
            "type": "card",
            "card": {"brand": "mastercard", "last4": "5555", "exp_month": 6, "exp_year": 2027},
            "customer": _CUSTOMER_ID,
        }
        svc_wired.attach_payment_method(customer_id=_CUSTOMER_ID, payment_method_id=_PM_ID)
        assert _PM_ID in svc_wired._payment_methods

    def test_attach_payment_method_calls_stripe_api(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {
            "id": _PM_ID,
            "type": "card",
            "card": {"brand": "visa", "last4": "4242", "exp_month": 12, "exp_year": 2028},
            "customer": _CUSTOMER_ID,
        }
        svc_wired.attach_payment_method(customer_id=_CUSTOMER_ID, payment_method_id=_PM_ID)
        mock_client.post.assert_called_once()
        call_path = mock_client.post.call_args[0][0]
        assert _PM_ID in call_path or "attach" in call_path


# ===========================================================================
# Section O — detach_payment_method
# ===========================================================================


class TestDetachPaymentMethod:
    def test_detach_payment_method_removes_from_store(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": _PM_ID, "customer": None}
        svc_wired._payment_methods[_PM_ID] = _build_payment_method_record()
        svc_wired.detach_payment_method(payment_method_id=_PM_ID)
        assert _PM_ID not in svc_wired._payment_methods

    def test_detach_payment_method_calls_stripe_api(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.post.return_value = {"id": _PM_ID, "customer": None}
        svc_wired._payment_methods[_PM_ID] = _build_payment_method_record()
        svc_wired.detach_payment_method(payment_method_id=_PM_ID)
        mock_client.post.assert_called_once()

    def test_detach_missing_payment_method_raises_not_found(self, svc: StripeService) -> None:
        with pytest.raises(StripePaymentMethodNotFoundError):
            svc.detach_payment_method(payment_method_id="pm_does_not_exist")

    def test_detach_payment_method_not_found_error_is_service_error(self, svc: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc.detach_payment_method(payment_method_id="pm_does_not_exist")


# ===========================================================================
# Section P — list_payment_methods
# ===========================================================================


class TestListPaymentMethods:
    def _configure_stripe_methods(self, mock_client: MagicMock, customer_id: str = _CUSTOMER_ID, count: int = 3) -> list[str]:
        ids = [f"pm_svctest_list_{i:03d}" for i in range(count)]
        mock_client.get.side_effect = [
            {"invoice_settings": {"default_payment_method": ids[0] if ids else None}},
            {
                "data": [
                    {
                        "id": method_id,
                        "type": "card",
                        "customer": customer_id,
                        "created": 1767225600 + index,
                        "card": {
                            "brand": "visa",
                            "last4": str(1000 + index),
                            "exp_month": 12,
                            "exp_year": 2028,
                        },
                    }
                    for index, method_id in enumerate(ids)
                ]
            },
        ]
        return ids

    def test_list_payment_methods_returns_list(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        self._configure_stripe_methods(mock_client)
        result = svc_wired.list_payment_methods(customer_id=_CUSTOMER_ID)
        assert isinstance(result, list)

    def test_list_payment_methods_returns_correct_count(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        self._configure_stripe_methods(mock_client, count=3)
        result = svc_wired.list_payment_methods(customer_id=_CUSTOMER_ID)
        assert len(result) == 3

    def test_list_payment_methods_empty_for_unknown_customer(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.get.side_effect = [
            {"invoice_settings": {}},
            {"data": []},
        ]
        result = svc_wired.list_payment_methods(customer_id="cus_unknown_xyz")
        assert result == []

    def test_list_payment_methods_returns_payment_method_responses(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        self._configure_stripe_methods(mock_client, count=2)
        result = svc_wired.list_payment_methods(customer_id=_CUSTOMER_ID)
        for item in result:
            assert isinstance(item, PaymentMethodResponse)

    def test_list_payment_methods_isolated_per_customer(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.get.side_effect = [
            {"invoice_settings": {}},
            {"data": [{"id": "pm_cust_a_001", "type": "card", "customer": "cus_a", "card": {"brand": "visa"}}]},
            {"invoice_settings": {}},
            {"data": [{"id": "pm_cust_b_001", "type": "card", "customer": "cus_b", "card": {"brand": "mastercard"}}]},
        ]
        assert len(svc_wired.list_payment_methods("cus_a")) == 1
        assert len(svc_wired.list_payment_methods("cus_b")) == 1
        assert svc_wired._payment_methods["pm_cust_a_001"].customer_id == "cus_a"
        assert svc_wired._payment_methods["pm_cust_b_001"].customer_id == "cus_b"


# ===========================================================================
# Section Q — set_default_payment_method
# ===========================================================================


class TestSetDefaultPaymentMethod:
    def _seed_two_pms(self, svc: StripeService) -> tuple[str, str]:
        pm1 = "pm_default_001"
        pm2 = "pm_default_002"
        svc._payment_methods[pm1] = _PaymentMethodRecord(
            payment_method_id=pm1,
            customer_id=_CUSTOMER_ID,
            type="card",
            brand="visa",
            last4="0001",
            exp_month=1,
            exp_year=2029,
            is_default=True,
            created_at="2026-01-01T00:00:00Z",
        )
        svc._payment_methods[pm2] = _PaymentMethodRecord(
            payment_method_id=pm2,
            customer_id=_CUSTOMER_ID,
            type="card",
            brand="mastercard",
            last4="0002",
            exp_month=2,
            exp_year=2030,
            is_default=False,
            created_at="2026-01-01T00:00:00Z",
        )
        return pm1, pm2

    def test_set_default_marks_correct_pm_as_default(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        pm1, pm2 = self._seed_two_pms(svc_wired)
        svc_wired.set_default_payment_method(customer_id=_CUSTOMER_ID, payment_method_id=pm2)
        assert svc_wired._payment_methods[pm2].is_default is True
        mock_client.post.assert_called_once_with(
            f"/customers/{_CUSTOMER_ID}",
            {"invoice_settings[default_payment_method]": pm2},
        )

    def test_set_default_unsets_previous_default(self, svc_wired: StripeService) -> None:
        pm1, pm2 = self._seed_two_pms(svc_wired)
        svc_wired.set_default_payment_method(customer_id=_CUSTOMER_ID, payment_method_id=pm2)
        assert svc_wired._payment_methods[pm1].is_default is False

    def test_set_default_missing_pm_raises_not_found(self, svc_wired: StripeService) -> None:
        with pytest.raises(StripePaymentMethodNotFoundError):
            svc_wired.set_default_payment_method(customer_id=_CUSTOMER_ID, payment_method_id="pm_ghost_999")

    def test_set_default_not_found_is_service_error(self, svc_wired: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc_wired.set_default_payment_method(customer_id=_CUSTOMER_ID, payment_method_id="pm_ghost_999")

    def test_set_default_only_one_default_per_customer(self, svc_wired: StripeService) -> None:
        pm1, pm2 = self._seed_two_pms(svc_wired)
        svc_wired.set_default_payment_method(customer_id=_CUSTOMER_ID, payment_method_id=pm2)
        defaults = [pm for pm in svc_wired._payment_methods.values() if pm.customer_id == _CUSTOMER_ID and pm.is_default]
        assert len(defaults) == 1
        assert defaults[0].payment_method_id == pm2


# ===========================================================================
# Section R — get_invoices_for_org and invalidate_invoice_cache
# ===========================================================================


class TestInvoicesForOrg:
    def _seed_invoice_cache(self, svc: StripeService, count: int = 2) -> None:
        svc._invoice_cache[_ORG] = [
            {
                "id": f"in_seed_{i:03d}",
                "customer": _CUSTOMER_ID,
                "subscription": _SUB_ID,
                "amount_paid": 9000,
                "currency": "usd",
                "status": "paid",
                "created": 1700000000 + i,
            }
            for i in range(count)
        ]

    def test_get_invoices_for_org_returns_list(self, svc: StripeService) -> None:
        self._seed_invoice_cache(svc)
        result = svc.get_invoices_for_org(org_id=_ORG)
        assert isinstance(result, list)

    def test_get_invoices_for_org_returns_correct_count(self, svc: StripeService) -> None:
        self._seed_invoice_cache(svc, count=3)
        result = svc.get_invoices_for_org(org_id=_ORG)
        assert len(result) == 3

    def test_get_invoices_for_org_returns_invoice_responses(self, svc: StripeService) -> None:
        self._seed_invoice_cache(svc, count=2)
        svc.register_customer_mapping(_ORG, _CUSTOMER_ID)
        result = svc.get_invoices_for_org(org_id=_ORG)
        for item in result:
            assert isinstance(item, InvoiceResponse)

    def test_get_invoices_for_org_empty_org_returns_empty(self, svc: StripeService) -> None:
        result = svc.get_invoices_for_org(org_id="org-no-invoices-xyz")
        assert result == []

    def test_invalidate_invoice_cache_clears_org_cache(self, svc: StripeService) -> None:
        self._seed_invoice_cache(svc, count=2)
        svc.invalidate_invoice_cache(org_id=_ORG)
        assert _ORG not in svc._invoice_cache

    def test_invalidate_invoice_cache_does_not_affect_other_orgs(self, svc: StripeService) -> None:
        svc._invoice_cache[_ORG] = [{"id": "in_org_a"}]
        svc._invoice_cache["org-other"] = [{"id": "in_org_b"}]
        svc.invalidate_invoice_cache(org_id=_ORG)
        assert "org-other" in svc._invoice_cache
        assert svc._invoice_cache["org-other"] == [{"id": "in_org_b"}]

    def test_invalidate_invoice_cache_noop_for_missing_org(self, svc: StripeService) -> None:
        svc.invalidate_invoice_cache(org_id="org-ghost-no-cache")


# ===========================================================================
# Section S — list_subscriptions_for_org
# ===========================================================================


class TestListSubscriptionsForOrg:
    def test_list_subscriptions_for_org_returns_list(self, svc_with_sub: StripeService) -> None:
        result = svc_with_sub.list_subscriptions_for_org(org_id=_ORG)
        assert isinstance(result, list)

    def test_list_subscriptions_for_org_returns_correct_count(self, svc_with_sub: StripeService) -> None:
        svc_with_sub.upsert_subscription(
            subscription_id="sub_second_001",
            org_id=_ORG,
            customer_id=_CUSTOMER_ID,
            price_id="price_second_001",
            status=StripeSubscriptionStatus.CANCELED,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2025-01-01T00:00:00Z",
            current_period_end="2025-02-01T00:00:00Z",
        )
        result = svc_with_sub.list_subscriptions_for_org(org_id=_ORG)
        assert len(result) >= 2

    def test_list_subscriptions_for_org_returns_subscription_responses(self, svc_with_sub: StripeService) -> None:
        result = svc_with_sub.list_subscriptions_for_org(org_id=_ORG)
        for item in result:
            assert isinstance(item, SubscriptionResponse)

    def test_list_subscriptions_for_org_empty_org_returns_empty(self, svc: StripeService) -> None:
        result = svc.list_subscriptions_for_org(org_id="org-no-subs-xyz")
        assert result == []

    def test_list_subscriptions_for_org_isolated_per_org(self, svc_with_sub: StripeService) -> None:
        svc_with_sub.upsert_subscription(
            subscription_id="sub_other_org_001",
            org_id="org-other-999",
            customer_id="cus_other_999",
            price_id="price_other_001",
            status=StripeSubscriptionStatus.ACTIVE,
            billing_interval=StripeBillingInterval.MONTHLY,
            current_period_start="2026-01-01T00:00:00Z",
            current_period_end="2026-02-01T00:00:00Z",
        )
        result_main = svc_with_sub.list_subscriptions_for_org(org_id=_ORG)
        result_other = svc_with_sub.list_subscriptions_for_org(org_id="org-other-999")
        assert all(r.org_id == _ORG for r in result_main)
        assert all(r.org_id == "org-other-999" for r in result_other)


# ===========================================================================
# Payment method setup checkout
# ===========================================================================


class TestPaymentMethodSetupSession:
    def test_setup_session_has_no_line_items_or_payment_intent(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        mock_client.post.return_value = {
            "id": "cs_setup_test_001",
            "url": "https://checkout.stripe.com/c/setup_test_001",
        }

        result = svc_wired.create_payment_method_setup_session(
            org_id=_ORG,
            customer_id=_CUSTOMER_ID,
            success_url="https://example.com/dashboard?card_setup=success",
            cancel_url="https://example.com/dashboard?card_setup=cancel",
        )

        assert result == {
            "session_id": "cs_setup_test_001",
            "checkout_url": "https://checkout.stripe.com/c/setup_test_001",
            "org_id": _ORG,
            "mode": "setup",
        }
        params = mock_client.post.call_args.args[1]
        assert params["mode"] == "setup"
        assert params["customer"] == _CUSTOMER_ID
        assert params["payment_method_types[0]"] == "card"
        assert not any(key.startswith("line_items[") for key in params)
        assert not any(key.startswith("payment_intent_data[") for key in params)

    def test_setup_session_webhook_does_not_credit_wallet(self, svc: StripeService) -> None:
        result = svc.handle_webhook_event(
            {
                "id": "evt_setup_test_001",
                "type": StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED.value,
                "data": {
                    "object": {
                        "id": "cs_setup_test_001",
                        "mode": "setup",
                        "customer": _CUSTOMER_ID,
                        "payment_status": "no_payment_required",
                        "metadata": {"flow": "saved_payment_method_setup"},
                    }
                },
            }
        )

        assert result["action"] == "processed"
        assert result["detail"]["payment_method_setup"] == "completed"
        assert svc.get_unit_balance(_ORG).balance == 0


# ===========================================================================
# Section T — complete_checkout_session
# ===========================================================================


class TestCheckoutSessionCreation:
    @pytest.mark.parametrize("save_card", [False, True])
    def test_checkout_saves_card_only_with_explicit_consent(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        save_card: bool,
    ) -> None:
        mock_client.post.return_value = {
            "id": "cs_save_card_consent_001",
            "url": "https://checkout.stripe.com/test",
            "customer": _CUSTOMER_ID,
            "payment_intent": "pi_save_card_consent_001",
        }
        persisted: dict[str, Any] = {}
        monkeypatch.setattr(
            svc_wired,
            "_record_checkout_fulfillment",
            lambda **record: persisted.update(record) or record,
        )

        svc_wired.create_checkout_session(
            org_id=_ORG,
            price_id="price_save_card_001",
            unit_credits=5_000,
            success_url="https://example.com/ok",
            cancel_url="https://example.com/cancel",
            customer_id=_CUSTOMER_ID,
            owner_key="buyer@ironclaw.test",
            metadata={"package_id": "pkg_5000"},
            save_card=save_card,
        )

        stripe_params = mock_client.post.call_args.args[1]
        assert stripe_params.get("payment_intent_data[setup_future_usage]") == ("off_session" if save_card else None)
        assert stripe_params["metadata[save_card]"] == str(save_card).lower()
        assert persisted["session_id"] == "cs_save_card_consent_001"
        assert persisted["owner_key"] == "buyer@ironclaw.test"
        assert persisted["package_id"] == "pkg_5000"
        assert persisted["units"] == 5_000
        assert persisted["payment_intent"] == "pi_save_card_consent_001"
        assert persisted["save_card"] is save_card

    def test_checkout_preflight_failure_skips_stripe_session_creation(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            svc_wired,
            "_verify_checkout_fulfillment_storage",
            MagicMock(
                side_effect=StripePersistenceError(
                    "durable fulfillment storage is unavailable",
                    error_code="checkout_fulfillment_storage_unavailable",
                ),
            ),
        )

        with pytest.raises(StripePersistenceError) as exc_info:
            svc_wired.create_checkout_session(
                org_id=_ORG,
                price_id="price_preflight_001",
                unit_credits=5_000,
                success_url="https://example.com/ok",
                cancel_url="https://example.com/cancel",
                customer_id=_CUSTOMER_ID,
                owner_key="buyer@ironclaw.test",
                metadata={"package_id": "pkg_5000"},
            )

        assert exc_info.value.error_code == "checkout_fulfillment_storage_unavailable"
        mock_client.post.assert_not_called()


class TestCompleteCheckoutSession:
    def _seed_session(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
        unit_credits: int = 500,
        owner_key: str | None = None,
    ) -> str:
        session_id = "cs_complete_test_001"
        mock_client.post.return_value = {
            "id": session_id,
            "url": "https://checkout.stripe.com/test",
            "customer": _CUSTOMER_ID,
            "payment_intent": "pi_complete_test_001",
            "expires_at": int(time.time()) + 1800,
        }
        checkout_owner = owner_key or svc_wired._canonical_org_owner_key(_ORG)  # noqa: SLF001
        svc_wired.create_checkout_session(
            org_id=_ORG,
            price_id="price_complete_001",
            unit_credits=unit_credits,
            success_url="https://example.com/ok",
            cancel_url="https://example.com/cancel",
            customer_id=_CUSTOMER_ID,
            owner_key=checkout_owner,
            metadata={"package_id": "pkg_5000"},
        )
        record = svc_wired.get_checkout_session(session_id)
        assert record is not None
        mock_client.get.return_value = {
            "id": session_id,
            "mode": "payment",
            "payment_status": "paid",
            "payment_intent": "pi_complete_test_001",
            "customer": _CUSTOMER_ID,
            "metadata": record["metadata"],
        }
        return session_id

    def test_complete_checkout_session_credits_units(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        session_id = self._seed_session(svc_wired, mock_client, unit_credits=1000)
        svc_wired.complete_checkout_session(session_id=session_id, org_id=_ORG)
        assert svc_wired.get_unit_balance(_ORG).balance == 1000

    def test_complete_checkout_session_credits_authenticated_owner_wallet(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        owner_key = "buyer@ironclaw.test"
        session_id = self._seed_session(
            svc_wired,
            mock_client,
            unit_credits=1000,
            owner_key=owner_key,
        )

        svc_wired.complete_checkout_session(session_id=session_id, org_id=_ORG)

        owner_wallet = svc_wired._wallet_registry.get_wallet(owner_key)  # noqa: SLF001
        assert owner_wallet is not None
        assert owner_wallet.balance_units == 1000
        assert svc_wired.get_unit_balance(_ORG).balance == 0

    def test_complete_checkout_session_marks_session_complete(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        session_id = self._seed_session(svc_wired, mock_client, unit_credits=100)
        svc_wired.complete_checkout_session(session_id=session_id, org_id=_ORG)
        record = svc_wired.get_checkout_session(session_id)
        assert record is not None
        assert record["status"] == "complete"

    def test_complete_checkout_session_missing_session_raises(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        mock_client.get.side_effect = StripeAPIError("not found", http_status=404)
        with pytest.raises(StripeSessionNotFoundError):
            svc_wired.complete_checkout_session(session_id="cs_ghost_999", org_id=_ORG)

    def test_complete_checkout_session_ledger_reason_checkout_complete(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        session_id = self._seed_session(svc_wired, mock_client, unit_credits=250)
        svc_wired.complete_checkout_session(session_id=session_id, org_id=_ORG)
        resp = svc_wired.get_unit_balance(_ORG)
        assert any(e["reason"] == StripeUnitEventReason.CHECKOUT_COMPLETE.value for e in resp.ledger_entries)


# ===========================================================================
# Section T2 — reconcile_checkout_session / reconcile_owner_checkout_sessions
# ===========================================================================


class TestReconcileCheckoutSession:
    def test_reconcile_checkout_session_credits_units(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.get.return_value = _build_checkout_completed_event(unit_credits=5000, session_id="cs_reconcile_001")["data"]["object"]

        result = svc_wired.reconcile_checkout_session("cs_reconcile_001")

        mock_client.get.assert_called_once_with("/checkout/sessions/cs_reconcile_001")
        assert result["payment_confirmed"] is True
        assert svc_wired.get_unit_balance(_ORG).balance == 5000

    def test_reconcile_checkout_session_is_idempotent(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        mock_client.get.return_value = _build_checkout_completed_event(unit_credits=5000, session_id="cs_reconcile_002")["data"]["object"]

        svc_wired.reconcile_checkout_session("cs_reconcile_002")
        svc_wired.reconcile_checkout_session("cs_reconcile_002")

        assert svc_wired.get_unit_balance(_ORG).balance == 5000

    def test_reconcile_checkout_session_unpaid_does_not_credit(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        session = _build_checkout_completed_event(unit_credits=5000, session_id="cs_reconcile_003")["data"]["object"]
        session["payment_status"] = "unpaid"
        mock_client.get.return_value = session

        result = svc_wired.reconcile_checkout_session("cs_reconcile_003")

        assert result["payment_confirmed"] is False
        assert svc_wired.get_unit_balance(_ORG).balance == 0

    def test_reconcile_checkout_session_rejects_invalid_id(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        with pytest.raises(StripeSessionNotFoundError):
            svc_wired.reconcile_checkout_session("not-a-session")
        mock_client.get.assert_not_called()

    def test_reconcile_owner_checkout_sessions_credits_only_matching_owner(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        owner = "buyer@ironclaw.test"
        mine = _build_checkout_completed_event(unit_credits=5000, session_id="cs_owner_001", owner_key=owner)["data"]["object"]
        other = _build_checkout_completed_event(unit_credits=2500, session_id="cs_owner_002", owner_key="other@ironclaw.test")["data"]["object"]
        mock_client.get.return_value = {"object": "list", "data": [mine, other]}

        reconciliation = svc_wired.reconcile_owner_checkout_sessions("Buyer@Ironclaw.test")

        assert reconciliation["status"] == "complete"
        assert reconciliation["sessions_reconciled"] == 1
        assert reconciliation["units_credited"] == 5000
        assert [r["session_id"] for r in reconciliation["sessions"]] == ["cs_owner_001"]
        owner_wallet = svc_wired._wallet_registry.get_wallet(owner)  # noqa: SLF001
        assert owner_wallet is not None
        assert owner_wallet.balance_units == 5000
        assert svc_wired.get_unit_balance(_ORG).balance == 0

    def test_reconcile_owner_checkout_sessions_paginates(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        owner = "buyer@ironclaw.test"
        first = _build_checkout_completed_event(
            unit_credits=5000,
            session_id="cs_owner_page_001",
            owner_key=owner,
        )[
            "data"
        ]["object"]
        second = _build_checkout_completed_event(
            unit_credits=2500,
            session_id="cs_owner_page_002",
            owner_key=owner,
        )[
            "data"
        ]["object"]
        mock_client.get.side_effect = [
            {"object": "list", "data": [first], "has_more": True},
            {"object": "list", "data": [second], "has_more": False},
        ]

        reconciliation = svc_wired.reconcile_owner_checkout_sessions(owner)

        assert reconciliation["status"] == "complete"
        assert reconciliation["pages_scanned"] == 2
        assert reconciliation["sessions_scanned"] == 2
        assert reconciliation["sessions_reconciled"] == 2
        assert reconciliation["units_credited"] == 7500
        assert mock_client.get.call_args_list[0].kwargs["params"] == {
            "limit": 100,
            "status": "complete",
        }
        assert mock_client.get.call_args_list[1].kwargs["params"] == {
            "limit": 100,
            "status": "complete",
            "starting_after": "cs_owner_page_001",
        }

    def test_reconcile_owner_checkout_sessions_retry_reports_existing_ledger_credit(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        owner = "buyer@ironclaw.test"
        session = _build_checkout_completed_event(
            unit_credits=5000,
            session_id="cs_owner_retry_001",
            owner_key=owner,
        )[
            "data"
        ]["object"]
        mock_client.get.return_value = {"object": "list", "data": [session], "has_more": False}

        first = svc_wired.reconcile_owner_checkout_sessions(owner)
        retry = svc_wired.reconcile_owner_checkout_sessions(owner)

        assert first["units_credited"] == retry["units_credited"] == 5000
        assert retry["sessions_reconciled"] == 1
        owner_wallet = svc_wired._wallet_registry.get_wallet(owner)  # noqa: SLF001
        assert owner_wallet is not None
        assert owner_wallet.balance_units == 5000

    def test_owner_reconciliation_does_not_fulfill_refunded_checkout(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = "buyer@ironclaw.test"
        session = _build_checkout_completed_event(
            unit_credits=5_000,
            session_id="cs_owner_refunded_001",
            owner_key=owner,
        )[
            "data"
        ]["object"]
        mock_client.get.return_value = {
            "object": "list",
            "data": [session],
            "has_more": False,
        }
        monkeypatch.setattr(svc_wired, "_is_payment_intent_refunded", lambda _: True)

        reconciliation = svc_wired.reconcile_owner_checkout_sessions(owner)

        assert reconciliation["status"] == "partial"
        assert reconciliation["sessions_reconciled"] == 0
        assert reconciliation["units_credited"] == 0
        assert reconciliation["sessions"][0]["status"] == "refunded"
        assert reconciliation["sessions"][0]["action"] == "contact_support"
        assert "refunded" in reconciliation["sessions"][0]["error"]
        assert svc_wired._wallet_registry.get_wallet(owner) is None  # noqa: SLF001

    def test_reconcile_owner_checkout_sessions_reports_page_limit(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        mock_client.get.side_effect = [
            {
                "object": "list",
                "data": [{"id": f"cs_unmatched_page_{index}"}],
                "has_more": True,
            }
            for index in range(5)
        ]

        reconciliation = svc_wired.reconcile_owner_checkout_sessions("buyer@ironclaw.test")

        assert reconciliation["status"] == "partial"
        assert reconciliation["pages_scanned"] == 5
        assert reconciliation["sessions_scanned"] == 5
        assert reconciliation["sessions_matched"] == 0
        assert reconciliation["truncated"] is True
        assert mock_client.get.call_count == 5

    def test_reconcile_owner_checkout_sessions_reports_failure_without_blocking_others(
        self,
        svc_wired: StripeService,
        mock_client: MagicMock,
    ) -> None:
        owner = "buyer@ironclaw.test"
        failing = _build_checkout_completed_event(
            unit_credits=5000,
            session_id="cs_owner_003",
            owner_key=owner,
        )[
            "data"
        ]["object"]
        successful = _build_checkout_completed_event(
            unit_credits=2500,
            session_id="cs_owner_004",
            owner_key=owner,
        )[
            "data"
        ]["object"]
        mock_client.get.return_value = {
            "object": "list",
            "data": [failing, successful],
            "has_more": False,
        }
        original_handler = svc_wired._handle_checkout_completed  # noqa: SLF001

        def _handle_checkout_completed(row: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
            if row.get("id") == "cs_owner_003":
                raise RuntimeError("wallet unavailable")
            return original_handler(row, event)

        with patch.object(svc_wired, "_handle_checkout_completed", side_effect=_handle_checkout_completed):
            reconciliation = svc_wired.reconcile_owner_checkout_sessions(owner)

        assert reconciliation["status"] == "partial"
        assert reconciliation["sessions_reconciled"] == 1
        assert reconciliation["units_credited"] == 2500
        assert reconciliation["sessions"][0]["status"] == "failed"
        assert reconciliation["sessions"][1]["status"] == "fulfilled"


# ===========================================================================
# Section U — dispatch_webhook_event full event dispatch
# ===========================================================================


class TestDispatchWebhookEvent:
    def test_dispatch_checkout_session_completed_credits_units(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=2500)
        result = svc.dispatch_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 2500
        assert result["action"] == "processed"

    def test_dispatch_invoice_paid_renewal_credits_org(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=750)
        result = svc_with_sub.dispatch_webhook_event(event)
        assert svc_with_sub.get_unit_balance(_ORG).balance == 750
        assert result["action"] == "processed"

    def test_dispatch_invoice_paid_renewal_credit_path_reason(self, svc_with_sub: StripeService) -> None:
        event = _build_invoice_paid_event(unit_credits=100)
        svc_with_sub.dispatch_webhook_event(event)
        resp = svc_with_sub.get_unit_balance(_ORG)
        assert any(e["reason"] == StripeUnitEventReason.SUBSCRIPTION_RENEWED.value for e in resp.ledger_entries)

    def test_dispatch_charge_refunded_returns_processed(self, svc_with_sub: StripeService) -> None:
        event = _build_charge_refunded_event(customer_id=_CUSTOMER_ID, amount_refunded=2000)
        result = svc_with_sub.dispatch_webhook_event(event)
        assert result is not None
        assert "action" in result

    def test_dispatch_customer_updated_returns_processed(self, svc: StripeService) -> None:
        svc.register_customer_mapping(_ORG, _CUSTOMER_ID)
        event = _build_customer_updated_event(customer_id=_CUSTOMER_ID, org_id=_ORG)
        result = svc.dispatch_webhook_event(event)
        assert result is not None
        assert "action" in result

    def test_dispatch_unknown_event_type_returns_ignored(self, svc: StripeService) -> None:
        event = {"id": "evt_unknown_001", "type": "payment_intent.created", "data": {"object": {}}}
        result = svc.dispatch_webhook_event(event)
        assert result["action"] in ("ignored", "skipped", "noop")

    def test_dispatch_duplicate_event_id_returns_duplicate_action(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=500)
        svc.dispatch_webhook_event(event)
        result = svc.dispatch_webhook_event(event)
        assert result["action"] == "duplicate"

    def test_dispatch_duplicate_event_does_not_double_credit(self, svc: StripeService) -> None:
        event = _build_checkout_completed_event(unit_credits=500)
        svc.dispatch_webhook_event(event)
        svc.dispatch_webhook_event(event)
        assert svc.get_unit_balance(_ORG).balance == 500

    def test_dispatch_checkout_session_expired_marks_session_expired(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        session_id = "cs_exp_dispatch_001"
        mock_client.post.return_value = {
            "id": session_id,
            "url": "https://checkout.stripe.com/exp",
            "customer": _CUSTOMER_ID,
            "expires_at": int(time.time()) + 100,
        }
        svc_wired.create_checkout_session(
            org_id=_ORG,
            price_id="price_exp_001",
            success_url="https://example.com/ok",
            cancel_url="https://example.com/cancel",
        )
        expire_event = {
            "id": "evt_exp_dispatch_001",
            "type": StripeWebhookEventType.CHECKOUT_SESSION_EXPIRED.value,
            "data": {"object": {"id": session_id}},
        }
        svc_wired.dispatch_webhook_event(expire_event)
        record = svc_wired.get_checkout_session(session_id)
        assert record is not None
        assert record["status"] == "expired"

    def test_dispatch_subscription_deleted_marks_canceled(self, svc_with_sub: StripeService) -> None:
        event = {
            "id": "evt_sub_del_001",
            "type": StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_DELETED.value,
            "data": {
                "object": {
                    "id": _SUB_ID,
                    "customer": _CUSTOMER_ID,
                    "status": "canceled",
                    "items": {"data": [{"price": {"id": "price_svctest_001", "recurring": {"interval": "month"}}}]},
                    "current_period_start": 1700000000,
                    "current_period_end": 1702678400,
                    "cancel_at_period_end": True,
                    "metadata": {},
                }
            },
        }
        svc_with_sub.dispatch_webhook_event(event)
        sub = svc_with_sub.get_subscription(_SUB_ID)
        assert sub is not None
        assert sub.status == StripeSubscriptionStatus.CANCELED.value


# ===========================================================================
# Section V — StripePaymentMethodNotFoundError exception
# ===========================================================================


class TestStripePaymentMethodNotFoundError:
    def test_is_subclass_of_service_error(self) -> None:
        err = StripePaymentMethodNotFoundError("pm_test_001")
        assert isinstance(err, StripeServiceError)

    def test_message_contains_payment_method_id(self) -> None:
        err = StripePaymentMethodNotFoundError("pm_ghost_xyz")
        assert "pm_ghost_xyz" in str(err)

    def test_raised_on_detach_of_unknown_pm(self, svc: StripeService) -> None:
        with pytest.raises(StripePaymentMethodNotFoundError):
            svc.detach_payment_method(payment_method_id="pm_unknown_001")

    def test_raised_on_set_default_of_unknown_pm(self, svc: StripeService) -> None:
        with pytest.raises(StripePaymentMethodNotFoundError):
            svc.set_default_payment_method(customer_id=_CUSTOMER_ID, payment_method_id="pm_unknown_002")


# ===========================================================================
# Section W — StripeIdempotencyError exception
# ===========================================================================


class TestStripeIdempotencyError:
    def test_is_subclass_of_service_error(self) -> None:
        err = StripeIdempotencyError("idem-key-001")
        assert isinstance(err, StripeServiceError)

    def test_message_contains_idempotency_key(self) -> None:
        err = StripeIdempotencyError("idem-key-abc-123")
        assert "idem-key-abc-123" in str(err)

    def test_raised_on_duplicate_idempotency_key(self, svc_wired: StripeService, mock_client: MagicMock) -> None:
        if not hasattr(svc_wired, "_idempotency_keys"):
            pytest.skip("Service does not expose _idempotency_keys — implementation-specific gate")
        mock_client.post.return_value = {"id": "mbur_idem_001"}
        key = "idem-key-dedup-test-001"
        svc_wired.report_metered_usage(_ORG, "si_idem_001", quantity=10, idempotency_key=key)
        with pytest.raises(StripeIdempotencyError):
            svc_wired.report_metered_usage(_ORG, "si_idem_001", quantity=10, idempotency_key=key)


# ===========================================================================
# Section X — get_subscription_strict raises StripeSubscriptionNotFoundError
# ===========================================================================


class TestGetSubscriptionStrict:
    def test_get_subscription_strict_returns_subscription_response_when_found(self, svc_with_sub: StripeService) -> None:
        result = svc_with_sub.get_subscription_strict(_SUB_ID)
        assert isinstance(result, SubscriptionResponse)
        assert result.subscription_id == _SUB_ID

    def test_get_subscription_strict_raises_when_not_found(self, svc: StripeService) -> None:
        with pytest.raises(StripeSubscriptionNotFoundError):
            svc.get_subscription_strict("sub_does_not_exist")

    def test_get_subscription_strict_error_is_subclass_of_service_error(self, svc: StripeService) -> None:
        with pytest.raises(StripeServiceError):
            svc.get_subscription_strict("sub_ghost_999")

    def test_get_subscription_strict_error_carries_subscription_id(self, svc: StripeService) -> None:
        missing_id = "sub_strict_missing_001"
        with pytest.raises(StripeSubscriptionNotFoundError) as exc_info:
            svc.get_subscription_strict(missing_id)
        assert exc_info.value.subscription_id == missing_id

    def test_get_subscription_strict_message_contains_subscription_id(self, svc: StripeService) -> None:
        missing_id = "sub_strict_msg_001"
        with pytest.raises(StripeSubscriptionNotFoundError) as exc_info:
            svc.get_subscription_strict(missing_id)
        assert missing_id in str(exc_info.value)

    def test_get_subscription_non_strict_returns_none_when_not_found(self, svc: StripeService) -> None:
        result = svc.get_subscription("sub_does_not_exist", strict=False)
        assert result is None

    def test_get_subscription_non_strict_does_not_raise(self, svc: StripeService) -> None:
        result = svc.get_subscription("sub_does_not_exist_no_raise", strict=False)
        assert result is None
