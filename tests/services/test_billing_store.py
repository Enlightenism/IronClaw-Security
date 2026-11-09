from __future__ import annotations

from collections.abc import Iterator
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

import pytest

import app.api.routes.billing as billing_routes
from app.services.billing_store import (
    StripeCheckoutFulfillmentStore,
    SubscriptionMeterStore,
    get_billing_store,
    get_subscription_meter_store,
    reset_billing_store,
    reset_subscription_meter_store,
)


@pytest.fixture()
def durable_purchase_fixture() -> Iterator[None]:
    billing_routes._PURCHASES.clear()
    yield
    billing_routes._PURCHASES.clear()


def _make_pending_purchase(
    *,
    owner_key: str,
    purchase_id: str,
    checkout_session_id: str,
    package_id: str = "pkg_5000",
) -> billing_routes.BillingPackagePurchaseView:
    pkg = billing_routes.PACKAGE_CATALOG[package_id]
    return billing_routes.BillingPackagePurchaseView(
        purchase_id=purchase_id,
        package_id=package_id,
        package_name=str(pkg["name"]),
        buyer_name="Durable Buyer",
        buyer_email=owner_key,
        owner_key=owner_key,
        price_usd=float(pkg["price_usd"]),
        granted_units=0,
        token_coverage=int(pkg["included_units"]) * billing_routes.TOKEN_CHUNK_SIZE,
        tokens_per_unit=billing_routes.TOKEN_CHUNK_SIZE,
        created_at=billing_routes._utc_now_iso(),
        payment_id=None,
        payment_status="pending",
        entitlement_status="not_active",
        metadata={
            "owner_key": owner_key,
            "buyer_email": owner_key,
            "package_id": package_id,
            "payment_required": True,
            "payment_status": "pending",
            "fulfillment_status": "pending",
            "install_keys_provisioned": False,
            "units_credited": False,
            "checkout_session_id": checkout_session_id,
        },
    )


@pytest.fixture()
def store() -> SubscriptionMeterStore:
    return SubscriptionMeterStore()


def test_stripe_checkout_fulfillment_store_persists_trusted_session_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.rpc.return_value.execute.return_value = SimpleNamespace(
        data=[
            {
                "session_id": "cs_store_001",
                "owner_key": "buyer@ironclaw.test",
                "org_id": "org_store_001",
                "package_id": "pkg_5000",
                "units": 5_000,
                "payment_intent": "pi_store_001",
            }
        ],
    )
    monkeypatch.setattr(
        "app.services.billing_store.get_supabase_service_client",
        lambda: client,
    )

    record = StripeCheckoutFulfillmentStore().record_checkout(
        session_id="cs_store_001",
        owner_key=" Buyer@Ironclaw.test ",
        org_id=" Org_Store_001 ",
        package_id="pkg_5000",
        units=5_000,
        payment_intent="pi_store_001",
        customer_id="cus_store_001",
        save_card=True,
        metadata={"source": "stripe.checkout"},
    )

    assert record["session_id"] == "cs_store_001"
    assert record["owner_key"] == "buyer@ironclaw.test"
    assert record["org_id"] == "org_store_001"
    assert record["units"] == 5_000
    client.rpc.assert_called_once_with(
        "register_stripe_checkout_fulfillment",
        {
            "p_session_id": "cs_store_001",
            "p_owner_key": "buyer@ironclaw.test",
            "p_org_id": "org_store_001",
            "p_package_id": "pkg_5000",
            "p_units": 5_000,
            "p_payment_intent": "pi_store_001",
            "p_customer_id": "cus_store_001",
            "p_save_card": True,
            "p_metadata": {"source": "stripe.checkout"},
        },
    )


# ---------------------------------------------------------------------------
# create_subscription
# ---------------------------------------------------------------------------


def test_create_subscription_stores_correct_fields(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-alpha", plan_name="team", customer_id="cus_123")
    assert record.org_id == "org-alpha"
    assert record.plan_name == "team"
    assert record.customer_id == "cus_123"
    assert record.payment_status == "paid"
    assert record.entitlements_status == "active"
    assert record.purchase_complete is False


def test_create_subscription_normalizes_org_id_case_and_whitespace(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="  Org-Beta  ", plan_name="starter", customer_id="cus_1")
    assert record.org_id == "org-beta"


def test_create_subscription_generates_prefixed_id_when_not_given(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-gen", plan_name="starter", customer_id="cus_2")
    assert record.subscription_id.startswith("sub_")


def test_create_subscription_uses_provided_subscription_id(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-explicit", plan_name="enterprise", customer_id="cus_3", subscription_id="sub_explicit")
    assert record.subscription_id == "sub_explicit"


def test_create_subscription_is_idempotent_per_org(store: SubscriptionMeterStore) -> None:
    first = store.create_subscription(org_id="org-dupe", plan_name="starter", customer_id="cus_4")
    second = store.create_subscription(org_id="org-dupe", plan_name="team", customer_id="cus_5")
    assert first.subscription_id == second.subscription_id
    assert second.plan_name == "starter"  # original record returned unchanged


def test_create_subscription_starts_with_zero_units(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-units", plan_name="starter", customer_id="cus_6")
    assert record.unit_balance == 0
    assert record.units_purchased == 0
    assert record.units_consumed == 0


def test_create_subscription_preserves_owner_metadata_and_runtime_lifecycle(store: SubscriptionMeterStore) -> None:
    owner_key = "ic_org_acme"
    record = store.create_subscription(
        org_id="org-owner-lifecycle",
        plan_name="team",
        customer_id="cus_owner",
        owner_key=owner_key,
    )
    assert record.owner_key == owner_key
    assert record.metadata["owner_key"] == owner_key
    assert record.metadata["org_id"] == "org-owner-lifecycle"
    assert record.metadata["entitlements_status"] == "active"
    assert record.metadata["payment_status"] == "paid"
    assert record.metadata["install_key_status"] is None
    assert store.get_subscription_by_owner(owner_key) is not None
    assert store.list_subscriptions(owner_key=owner_key)[0].subscription_id == record.subscription_id


# ---------------------------------------------------------------------------
# get_subscription / get_subscription_by_org
# ---------------------------------------------------------------------------


def test_get_subscription_returns_correct_record(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-fetch", plan_name="starter", customer_id="cus_7")
    fetched = store.get_subscription(record.subscription_id)
    assert fetched is not None
    assert fetched.subscription_id == record.subscription_id


def test_get_subscription_returns_none_for_unknown_id(store: SubscriptionMeterStore) -> None:
    assert store.get_subscription("sub_does_not_exist") is None


def test_get_subscription_by_org_returns_correct_record(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-by-org", plan_name="starter", customer_id="cus_8")
    fetched = store.get_subscription_by_org("org-by-org")
    assert fetched is not None
    assert fetched.subscription_id == record.subscription_id


def test_get_subscription_by_org_is_case_insensitive(store: SubscriptionMeterStore) -> None:
    store.create_subscription(org_id="org-Mixed-Case", plan_name="starter", customer_id="cus_9")
    fetched = store.get_subscription_by_org("ORG-mixed-case")
    assert fetched is not None


def test_get_subscription_by_org_returns_none_for_unknown_org(store: SubscriptionMeterStore) -> None:
    assert store.get_subscription_by_org("org-nope") is None


# ---------------------------------------------------------------------------
# mark_purchase_complete
# ---------------------------------------------------------------------------


def test_mark_purchase_complete_updates_status_fields(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-purchase", plan_name="team", customer_id="cus_10")
    updated = store.mark_purchase_complete(record.subscription_id, payment_id="pay_1")
    assert updated.purchase_complete is True
    assert updated.payment_id == "pay_1"
    assert updated.payment_status == "paid"
    assert updated.entitlements_status == "active"


def test_mark_purchase_complete_accepts_custom_statuses(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-purchase-2", plan_name="team", customer_id="cus_11")
    updated = store.mark_purchase_complete(record.subscription_id, payment_id="pay_2", payment_status="succeeded", entitlements_status="granted")
    assert updated.payment_status == "succeeded"
    assert updated.entitlements_status == "granted"


def test_mark_purchase_complete_raises_for_unknown_subscription(store: SubscriptionMeterStore) -> None:
    with pytest.raises(ValueError):
        store.mark_purchase_complete("sub_missing", payment_id="pay_x")


# ---------------------------------------------------------------------------
# link_install_key
# ---------------------------------------------------------------------------


def test_link_install_key_updates_record(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-link", plan_name="starter", customer_id="cus_12")
    store.mark_purchase_complete(record.subscription_id, payment_id="pay_1")
    updated = store.link_install_key(record.subscription_id, install_key_id="ik_1")
    assert updated.install_key_id == "ik_1"
    assert updated.install_key_status == "active"


def test_link_install_key_raises_when_checkout_is_not_successful(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-link-pending", plan_name="starter", customer_id="cus_12b")
    store.sync_checkout_result(
        record.subscription_id,
        payment_id="pay_pending",
        payment_status="pending",
        entitlements_status="not_active",
        purchase_complete=False,
    )
    with pytest.raises(ValueError):
        store.link_install_key(record.subscription_id, install_key_id="ik_x")


def test_link_install_key_raises_for_unknown_subscription(store: SubscriptionMeterStore) -> None:
    with pytest.raises(ValueError):
        store.link_install_key("sub_missing", install_key_id="ik_x")


# ---------------------------------------------------------------------------
# credit_units / debit_units
# ---------------------------------------------------------------------------


def test_credit_units_increments_balance_and_purchased(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-credit", plan_name="starter", customer_id="cus_13")
    updated = store.credit_units(record.subscription_id, 500)
    assert updated.unit_balance == 500
    assert updated.units_purchased == 500


def test_credit_units_negative_input_is_clamped_to_zero(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-credit-neg", plan_name="starter", customer_id="cus_14")
    updated = store.credit_units(record.subscription_id, -100)
    assert updated.unit_balance == 0


def test_debit_units_decrements_balance_and_increments_consumed(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-debit", plan_name="starter", customer_id="cus_15")
    store.credit_units(record.subscription_id, 200)
    updated, event = store.debit_units(record.subscription_id, 50, action_type="scan")
    assert updated.unit_balance == 150
    assert updated.units_consumed == 50
    assert event.units == 50
    assert event.action_type == "scan"
    assert event.event_id.startswith("evt_")


def test_debit_units_raises_when_exceeding_balance(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-debit-over", plan_name="starter", customer_id="cus_16")
    store.credit_units(record.subscription_id, 10)
    with pytest.raises(ValueError):
        store.debit_units(record.subscription_id, 11)


def test_debit_units_raises_for_unknown_subscription(store: SubscriptionMeterStore) -> None:
    with pytest.raises(ValueError):
        store.debit_units("sub_missing", 1)


def test_debit_units_records_metadata_on_event(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-debit-meta", plan_name="starter", customer_id="cus_17")
    store.credit_units(record.subscription_id, 100)
    _, event = store.debit_units(record.subscription_id, 10, metadata={"run_id": "abc"})
    assert event.metadata["run_id"] == "abc"


def test_revoke_units_floors_at_balance_without_counting_consumption(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-revoke", plan_name="starter", customer_id="cus_18")
    store.credit_units(record.subscription_id, 40)
    result = store.revoke_units(record.subscription_id, 100, metadata={"event_id": "refund_revoke:cs_store_001"})
    assert result is not None
    updated, event = result
    assert updated.unit_balance == 0
    assert updated.units_consumed == 0
    assert event.action_type == "refund_revoke"
    assert event.units == 40


def test_revoke_units_is_idempotent_per_event_id(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-revoke-dup", plan_name="starter", customer_id="cus_19")
    store.credit_units(record.subscription_id, 100)
    metadata = {"event_id": "refund_revoke:cs_store_002"}
    assert store.revoke_units(record.subscription_id, 40, metadata=metadata) is not None
    assert store.revoke_units(record.subscription_id, 40, metadata=metadata) is None
    updated = store.get_subscription(record.subscription_id)
    assert updated is not None
    assert updated.unit_balance == 60


def test_revoke_units_returns_none_for_unknown_subscription(store: SubscriptionMeterStore) -> None:
    assert store.revoke_units("sub_missing_revoke", 5) is None


# ---------------------------------------------------------------------------
# provision_install_key_on_purchase
# ---------------------------------------------------------------------------


def test_provision_install_key_on_purchase_requires_successful_checkout(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-provision", plan_name="team", customer_id="cus_18")
    store.sync_checkout_result(
        record.subscription_id,
        payment_id="pay_pending",
        payment_status="pending",
        entitlements_status="not_active",
        purchase_complete=False,
    )
    with pytest.raises(ValueError):
        store.provision_install_key_on_purchase(record.subscription_id, "openclaw", owner_key="owner-1")


def test_provision_install_key_on_purchase_raises_for_unknown_subscription(store: SubscriptionMeterStore) -> None:
    with pytest.raises(ValueError):
        store.provision_install_key_on_purchase("sub_missing", "openclaw", owner_key="owner-1")


def test_provision_install_key_on_purchase_records_status_without_issuing_key(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-provision-2", plan_name="team", customer_id="cus_19")
    store.mark_purchase_complete(record.subscription_id, payment_id="pay_9")
    store.credit_units(record.subscription_id, 1_000)
    updated, payload = store.provision_install_key_on_purchase(
        record.subscription_id,
        "openclaw",
        owner_key="owner-2",
        install_key_id="ik_issued_001",
        install_key_status="active",
    )
    assert updated.purchase_complete is True
    assert updated.install_key_id == "ik_issued_001"
    assert updated.install_key_status == "active"
    assert payload["owner_key"] == "owner-2"
    assert payload["program"] == "openclaw"
    assert payload["purchase_complete"] is True


def test_provision_install_key_on_purchase_records_all_supported_platforms_for_purchase(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-provision-all", plan_name="team", customer_id="cus_19b")
    store.mark_purchase_complete(record.subscription_id, payment_id="pay_multi")
    store.credit_units(record.subscription_id, 1_000)

    updated, payload = store.provision_install_key_on_purchase(
        record.subscription_id,
        None,
        owner_key="owner-3",
        install_key_id="ik_multi_001",
        install_key_status="active",
    )

    assert updated.purchase_complete is True
    assert isinstance(payload, dict)
    assert "openclaw" in payload
    assert "claude_code" in payload
    assert "cursor" in payload
    assert "goose" in payload
    assert "gemini_cli" in payload
    assert "copilot" in payload
    assert "security_guardian" not in payload

    for program, item in payload.items():
        assert item["program"] == program
        assert item["owner_key"] == "owner-3"
        assert item["active"] is True
        assert item["payment_status"] == "paid"
        assert item["entitlements_status"] == "active"


# ---------------------------------------------------------------------------
# list_events
# ---------------------------------------------------------------------------


def test_list_events_returns_empty_when_none_recorded(store: SubscriptionMeterStore) -> None:
    assert store.list_events() == []


def test_list_events_filters_by_subscription_id(store: SubscriptionMeterStore) -> None:
    record_a = store.create_subscription(org_id="org-events-a", plan_name="starter", customer_id="cus_20")
    record_b = store.create_subscription(org_id="org-events-b", plan_name="starter", customer_id="cus_21")
    store.credit_units(record_a.subscription_id, 10)
    store.credit_units(record_b.subscription_id, 10)
    store.debit_units(record_a.subscription_id, 5)
    store.debit_units(record_b.subscription_id, 5)

    events_a = store.list_events(subscription_id=record_a.subscription_id)
    assert len(events_a) == 1
    assert events_a[0].subscription_id == record_a.subscription_id


def test_list_events_respects_limit(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-events-limit", plan_name="starter", customer_id="cus_22")
    store.credit_units(record.subscription_id, 100)
    for _ in range(5):
        store.debit_units(record.subscription_id, 1)
    events = store.list_events(subscription_id=record.subscription_id, limit=2)
    assert len(events) == 2


# ---------------------------------------------------------------------------
# as_dict()
# ---------------------------------------------------------------------------


def test_subscription_record_as_dict_contains_expected_keys(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-asdict", plan_name="starter", customer_id="cus_23")
    d = record.as_dict()
    assert d["org_id"] == "org-asdict"
    assert d["subscription_id"] == record.subscription_id
    assert isinstance(d["created_at"], str)


def test_meter_event_record_as_dict_contains_expected_keys(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(org_id="org-event-dict", plan_name="starter", customer_id="cus_24")
    store.credit_units(record.subscription_id, 10)
    _, event = store.debit_units(record.subscription_id, 5)
    d = event.as_dict()
    assert d["event_id"] == event.event_id
    assert d["subscription_id"] == record.subscription_id
    assert isinstance(d["recorded_at"], str)


def test_durable_purchase_record_is_pending_and_lookupable_by_identity_fields(durable_purchase_fixture) -> None:
    owner_key = "pending-lookup@ironclaw.test"
    purchase_id = "purch_lookup_001"
    session_id = "cs_lookup_001"
    purchase = _make_pending_purchase(owner_key=owner_key, purchase_id=purchase_id, checkout_session_id=session_id)
    billing_routes._append_purchase(purchase)

    by_purchase_id = billing_routes._find_matching_purchase(purchase_id=purchase_id)
    by_session_id = billing_routes._find_matching_purchase(session_id=session_id)
    by_owner = billing_routes._find_matching_purchase(owner_key=owner_key)

    assert by_purchase_id is not None
    assert by_session_id is not None
    assert by_owner is not None
    assert by_purchase_id.purchase_id == purchase_id
    assert by_session_id.purchase_id == purchase_id
    assert by_owner.owner_key == owner_key
    assert by_purchase_id.metadata["payment_status"] == "pending"
    assert by_purchase_id.metadata["fulfillment_status"] == "pending"


def test_durable_legacy_purchase_is_not_fulfilled_without_trusted_checkout_metadata(
    durable_purchase_fixture,
) -> None:
    owner_key = "fulfilled-lookup@ironclaw.test"
    purchase_id = "purch_fulfill_001"
    session_id = "cs_fulfill_001"
    purchase = _make_pending_purchase(owner_key=owner_key, purchase_id=purchase_id, checkout_session_id=session_id)
    billing_routes._append_purchase(purchase)

    response = billing_routes.handle_checkout_session_completed_webhook(
        {
            "id": "evt_fulfill_001",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": session_id,
                    "customer": "cus_fulfill_001",
                    "payment_status": "paid",
                    "amount_total": 2000,
                    "currency": "usd",
                    "mode": "payment",
                    "customer_details": {"email": owner_key},
                    "metadata": {
                        "owner_key": owner_key,
                        "purchase_id": purchase_id,
                        "buyer_email": owner_key,
                        "package_id": "pkg_5000",
                        "checkout_session_id": session_id,
                    },
                }
            },
        }
    )

    assert response["status"] == "unfulfilled"
    assert response["reason"] == "legacy_checkout_requires_review"
    stored = billing_routes._find_matching_purchase(purchase_id=purchase_id)
    assert stored is not None
    assert stored.metadata["payment_status"] == "pending"
    assert stored.metadata["fulfillment_status"] == "pending"
    assert stored.metadata["checkout_session_id"] == session_id
    assert stored.granted_units == 0
    assert stored.metadata["units_credited"] is False


def test_durable_legacy_purchase_does_not_attempt_wallet_credit(
    durable_purchase_fixture,
    monkeypatch,
) -> None:
    owner_key = "rollback-owner@ironclaw.test"
    purchase_id = "purch_rollback_001"
    session_id = "cs_rollback_001"
    purchase = _make_pending_purchase(owner_key=owner_key, purchase_id=purchase_id, checkout_session_id=session_id)
    billing_routes._append_purchase(purchase)

    registry = billing_routes.get_unit_wallet_registry()

    credit_units = MagicMock(wraps=registry.credit_units)
    monkeypatch.setattr(registry, "credit_units", credit_units)

    response = billing_routes.handle_checkout_session_completed_webhook(
        {
            "id": "evt_rollback_001",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": session_id,
                    "customer": "cus_rollback_001",
                    "payment_status": "paid",
                    "amount_total": 2000,
                    "currency": "usd",
                    "mode": "payment",
                    "customer_details": {"email": owner_key},
                    "metadata": {
                        "owner_key": owner_key,
                        "purchase_id": purchase_id,
                        "buyer_email": owner_key,
                        "package_id": "pkg_5000",
                        "checkout_session_id": session_id,
                    },
                }
            },
        }
    )

    assert response["status"] == "unfulfilled"
    assert response["reason"] == "legacy_checkout_requires_review"
    credit_units.assert_not_called()
    stored = billing_routes._find_matching_purchase(purchase_id=purchase_id)
    assert stored is not None
    assert stored.metadata["payment_status"] == "pending"
    assert stored.metadata["fulfillment_status"] == "pending"
    assert stored.metadata.get("checkout_session_id") == session_id
    assert stored.metadata.get("units_credited") is False


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------


def test_get_subscription_meter_store_returns_singleton() -> None:
    reset_subscription_meter_store()
    assert get_subscription_meter_store() is get_subscription_meter_store()


def test_get_billing_store_is_alias_for_get_subscription_meter_store() -> None:
    reset_subscription_meter_store()
    assert get_billing_store() is get_subscription_meter_store()


def test_reset_subscription_meter_store_produces_new_instance() -> None:
    first = get_subscription_meter_store()
    reset_subscription_meter_store()
    second = get_subscription_meter_store()
    assert first is not second


def test_reset_billing_store_is_alias_for_reset_subscription_meter_store() -> None:
    first = get_subscription_meter_store()
    reset_billing_store()
    second = get_subscription_meter_store()
    assert first is not second
