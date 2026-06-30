from __future__ import annotations

import calendar
from datetime import datetime
import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

import pytest

from app.services.billing_store import (
    BillingStore,
    SubscriptionMeterStore,
    get_billing_store,
    get_subscription_meter_store,
    reset_billing_store,
    reset_subscription_meter_store,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _last_day_of_month(dt: datetime) -> int:
    return calendar.monthrange(dt.year, dt.month)[1]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store() -> SubscriptionMeterStore:
    s = SubscriptionMeterStore()
    s.seed_defaults()
    return s


@pytest.fixture()
def empty_store() -> SubscriptionMeterStore:
    return SubscriptionMeterStore()


# ---------------------------------------------------------------------------
# seed_defaults() — count and idempotency
# ---------------------------------------------------------------------------


def test_seed_defaults_seeds_exactly_2_subscriptions(store: SubscriptionMeterStore) -> None:
    assert len(store.list_subscriptions()) == 2


def test_seed_defaults_seeds_exactly_3_meter_events(store: SubscriptionMeterStore) -> None:
    assert len(store.list_meter_events()) == 3


def test_seed_defaults_is_idempotent_subscriptions(store: SubscriptionMeterStore) -> None:
    store.seed_defaults()
    store.seed_defaults()
    assert len(store.list_subscriptions()) == 2


def test_seed_defaults_is_idempotent_meter_events(store: SubscriptionMeterStore) -> None:
    store.seed_defaults()
    store.seed_defaults()
    assert len(store.list_meter_events()) == 3


def test_seed_defaults_on_empty_store_populates(empty_store: SubscriptionMeterStore) -> None:
    assert len(empty_store.list_subscriptions()) == 0
    empty_store.seed_defaults()
    assert len(empty_store.list_subscriptions()) == 2
    assert len(empty_store.list_meter_events()) == 3


# ---------------------------------------------------------------------------
# seed_defaults() — record contents
# ---------------------------------------------------------------------------


def test_seeded_org_seed_001_has_correct_fields(store: SubscriptionMeterStore) -> None:
    subs = store.list_subscriptions(org_id="org-seed-001")
    assert len(subs) == 1
    sub = subs[0]
    assert sub.org_id == "org-seed-001"
    assert sub.plan_name == "enterprise"
    assert sub.status == "active"
    assert sub.included_units == 60_000


def test_seeded_org_seed_002_has_correct_fields(store: SubscriptionMeterStore) -> None:
    subs = store.list_subscriptions(org_id="org-seed-002")
    assert len(subs) == 1
    sub = subs[0]
    assert sub.org_id == "org-seed-002"
    assert sub.plan_name == "pro"
    assert sub.status == "trialing"
    assert sub.included_units == 25_000


def test_seeded_subscriptions_have_subscription_id_prefix(store: SubscriptionMeterStore) -> None:
    for sub in store.list_subscriptions():
        assert sub.subscription_id.startswith("sub-")


def test_seeded_meter_events_have_event_id_prefix(store: SubscriptionMeterStore) -> None:
    for event in store.list_meter_events():
        assert event.event_id.startswith("mtr-")


def test_seeded_subscriptions_have_overage_rate_usd_zero(store: SubscriptionMeterStore) -> None:
    for sub in store.list_subscriptions():
        assert sub.overage_rate_usd == 0


# ---------------------------------------------------------------------------
# period_start / period_end — correct calendar boundaries
# ---------------------------------------------------------------------------


def test_seeded_period_start_is_first_of_month(store: SubscriptionMeterStore) -> None:
    for sub in store.list_subscriptions():
        assert sub.period_start.day == 1
        assert sub.period_start.hour == 0
        assert sub.period_start.minute == 0
        assert sub.period_start.second == 0


def test_seeded_period_end_is_last_real_day_of_month(store: SubscriptionMeterStore) -> None:
    for sub in store.list_subscriptions():
        expected_last_day = _last_day_of_month(sub.period_end)
        assert sub.period_end.day == expected_last_day
        assert sub.period_end.hour == 23
        assert sub.period_end.minute == 59
        assert sub.period_end.second == 59


def test_created_subscription_period_end_is_last_real_day_of_month(
    empty_store: SubscriptionMeterStore,
) -> None:
    record = empty_store.create_subscription(
        org_id="org-period-check",
        plan_name="pro",
        status="active",
        billing_email="period@test.dev",
        included_units=25_000,
        price_usd_monthly=299,
    )
    expected_last_day = _last_day_of_month(record.period_end)
    assert record.period_end.day == expected_last_day
    assert record.period_end.hour == 23
    assert record.period_end.minute == 59
    assert record.period_end.second == 59


def test_created_subscription_period_start_is_first_of_month(
    empty_store: SubscriptionMeterStore,
) -> None:
    record = empty_store.create_subscription(
        org_id="org-period-start-check",
        plan_name="free",
        status="trialing",
        billing_email="start@test.dev",
        included_units=5_000,
        price_usd_monthly=0,
    )
    assert record.period_start.day == 1
    assert record.period_start.hour == 0
    assert record.period_start.minute == 0
    assert record.period_start.second == 0


def test_period_start_before_period_end(store: SubscriptionMeterStore) -> None:
    for sub in store.list_subscriptions():
        assert sub.period_start < sub.period_end


# ---------------------------------------------------------------------------
# list_subscriptions — filtering
# ---------------------------------------------------------------------------


def test_list_subscriptions_no_filter_returns_all(store: SubscriptionMeterStore) -> None:
    all_subs = store.list_subscriptions()
    assert len(all_subs) == 2


def test_list_subscriptions_org_filter_returns_only_matching_org(store: SubscriptionMeterStore) -> None:
    subs = store.list_subscriptions(org_id="org-seed-001")
    assert len(subs) == 1
    assert subs[0].org_id == "org-seed-001"


def test_list_subscriptions_org_filter_excludes_other_orgs(store: SubscriptionMeterStore) -> None:
    subs = store.list_subscriptions(org_id="org-seed-002")
    for sub in subs:
        assert sub.org_id == "org-seed-002"


def test_list_subscriptions_unknown_org_returns_empty(store: SubscriptionMeterStore) -> None:
    subs = store.list_subscriptions(org_id="org-does-not-exist")
    assert subs == []


# ---------------------------------------------------------------------------
# get_subscription
# ---------------------------------------------------------------------------


def test_get_subscription_returns_correct_record(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    fetched = store.get_subscription(sub.subscription_id)
    assert fetched is not None
    assert fetched.subscription_id == sub.subscription_id
    assert fetched.org_id == "org-seed-001"


def test_get_subscription_returns_none_for_unknown_id(store: SubscriptionMeterStore) -> None:
    result = store.get_subscription("sub-does-not-exist-xyz")
    assert result is None


# ---------------------------------------------------------------------------
# create_subscription
# ---------------------------------------------------------------------------


def test_create_subscription_appends_new_record(store: SubscriptionMeterStore) -> None:
    before = len(store.list_subscriptions())
    store.create_subscription(
        org_id="org-new-test",
        plan_name="free",
        status="trialing",
        billing_email="new@test.dev",
        included_units=5_000,
        price_usd_monthly=0,
    )
    assert len(store.list_subscriptions()) == before + 1


def test_create_subscription_starts_with_zero_used_and_overage(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(
        org_id="org-fresh",
        plan_name="pro",
        status="active",
        billing_email="fresh@test.dev",
        included_units=25_000,
        price_usd_monthly=299,
    )
    assert record.used_units == 0
    assert record.overage_units == 0


def test_create_subscription_stores_correct_field_values(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(
        org_id="org-verify",
        plan_name="enterprise",
        status="active",
        billing_email="verify@test.dev",
        included_units=60_000,
        price_usd_monthly=2499,
        metadata={"source": "test"},
    )
    assert record.org_id == "org-verify"
    assert record.plan_name == "enterprise"
    assert record.status == "active"
    assert record.billing_email == "verify@test.dev"
    assert record.included_units == 60_000
    assert record.price_usd_monthly == 2499
    assert record.metadata["source"] == "test"
    assert record.subscription_id.startswith("sub-")


def test_create_subscription_is_retrievable_by_get(store: SubscriptionMeterStore) -> None:
    record = store.create_subscription(
        org_id="org-retrieve",
        plan_name="pro",
        status="trialing",
        billing_email="retrieve@test.dev",
        included_units=25_000,
        price_usd_monthly=299,
    )
    fetched = store.get_subscription(record.subscription_id)
    assert fetched is not None
    assert fetched.subscription_id == record.subscription_id


def test_create_subscription_overage_rate_usd_defaults_to_zero(empty_store: SubscriptionMeterStore) -> None:
    record = empty_store.create_subscription(
        org_id="org-rate-default",
        plan_name="free",
        status="trialing",
        billing_email="rate@test.dev",
        included_units=5_000,
        price_usd_monthly=0,
    )
    assert record.overage_rate_usd == 0


def test_create_subscription_overage_rate_usd_is_stored(empty_store: SubscriptionMeterStore) -> None:
    record = empty_store.create_subscription(
        org_id="org-rate-set",
        plan_name="enterprise",
        status="active",
        billing_email="rateset@test.dev",
        included_units=60_000,
        price_usd_monthly=2499,
        overage_rate_usd=5,
    )
    assert record.overage_rate_usd == 5


def test_create_subscription_whitespace_stripped_from_org_id(empty_store: SubscriptionMeterStore) -> None:
    record = empty_store.create_subscription(
        org_id="  org-strip-test  ",
        plan_name="free",
        status="trialing",
        billing_email="strip@test.dev",
        included_units=1_000,
        price_usd_monthly=0,
    )
    assert record.org_id == "org-strip-test"


def test_create_subscription_whitespace_stripped_from_email(empty_store: SubscriptionMeterStore) -> None:
    record = empty_store.create_subscription(
        org_id="org-email-strip",
        plan_name="free",
        status="trialing",
        billing_email="  email@test.dev  ",
        included_units=1_000,
        price_usd_monthly=0,
    )
    assert record.billing_email == "email@test.dev"


# ---------------------------------------------------------------------------
# update_subscription
# ---------------------------------------------------------------------------


def test_update_subscription_mutates_status(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-002")[0]
    updated = store.update_subscription(sub.subscription_id, status="active")
    assert updated is not None
    assert updated.status == "active"


def test_update_subscription_mutates_plan_name(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-002")[0]
    updated = store.update_subscription(sub.subscription_id, status=sub.status, plan_name="enterprise")
    assert updated is not None
    assert updated.plan_name == "enterprise"


def test_update_subscription_mutates_billing_email(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    updated = store.update_subscription(sub.subscription_id, status=sub.status, billing_email="updated@test.dev")
    assert updated is not None
    assert updated.billing_email == "updated@test.dev"


def test_update_subscription_mutates_included_units(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    updated = store.update_subscription(sub.subscription_id, status=sub.status, included_units=100_000)
    assert updated is not None
    assert updated.included_units == 100_000


def test_update_subscription_mutates_price_usd_monthly(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    updated = store.update_subscription(sub.subscription_id, status=sub.status, price_usd_monthly=3999)
    assert updated is not None
    assert updated.price_usd_monthly == 3999


def test_update_subscription_mutates_overage_rate_usd(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    updated = store.update_subscription(sub.subscription_id, status=sub.status, overage_rate_usd=10)
    assert updated is not None
    assert updated.overage_rate_usd == 10


def test_update_subscription_overage_rate_usd_to_zero(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    # set to non-zero first
    store.update_subscription(sub.subscription_id, status=sub.status, overage_rate_usd=7)
    updated = store.update_subscription(sub.subscription_id, status=sub.status, overage_rate_usd=0)
    assert updated is not None
    assert updated.overage_rate_usd == 0


def test_update_subscription_merges_metadata(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    updated = store.update_subscription(
        sub.subscription_id,
        status=sub.status,
        metadata={"extra_key": "extra_value"},
    )
    assert updated is not None
    assert updated.metadata["seeded"] is True
    assert updated.metadata["extra_key"] == "extra_value"


def test_update_subscription_returns_none_for_unknown_id(store: SubscriptionMeterStore) -> None:
    result = store.update_subscription("sub-nonexistent-xyz", status="canceled")
    assert result is None


def test_update_subscription_persists_in_list(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-002")[0]
    store.update_subscription(sub.subscription_id, status="past_due")
    reloaded = store.get_subscription(sub.subscription_id)
    assert reloaded is not None
    assert reloaded.status == "past_due"


def test_update_subscription_preserves_used_and_overage_units(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    used_before = sub.used_units
    overage_before = sub.overage_units
    updated = store.update_subscription(sub.subscription_id, status="active")
    assert updated is not None
    assert updated.used_units == used_before
    assert updated.overage_units == overage_before


def test_update_subscription_billing_email_stripped(store: SubscriptionMeterStore) -> None:
    sub = store.list_subscriptions(org_id="org-seed-001")[0]
    updated = store.update_subscription(
        sub.subscription_id,
        status=sub.status,
        billing_email="  stripped@test.dev  ",
    )
    assert updated is not None
    assert updated.billing_email == "stripped@test.dev"


# ---------------------------------------------------------------------------
# record_meter_event — appends and increments used_units
# ---------------------------------------------------------------------------


def test_record_meter_event_appends_event(store: SubscriptionMeterStore) -> None:
    before = len(store.list_meter_events())
    store.record_meter_event(
        org_id="org-seed-001",
        event_type="scan",
        quantity=100,
    )
    assert len(store.list_meter_events()) == before + 1


def test_record_meter_event_increments_used_units_on_matching_subscription(
    store: SubscriptionMeterStore,
) -> None:
    sub_before = store.list_subscriptions(org_id="org-seed-001")[0]
    used_before = sub_before.used_units

    store.record_meter_event(
        org_id="org-seed-001",
        event_type="guard_request",
        quantity=500,
    )

    sub_after = store.list_subscriptions(org_id="org-seed-001")[0]
    assert sub_after.used_units == used_before + 500


def test_record_meter_event_stores_correct_event_fields(store: SubscriptionMeterStore) -> None:
    event = store.record_meter_event(
        org_id="org-seed-002",
        event_type="execution",
        quantity=77,
        metadata={"run_id": "abc123"},
    )
    assert event.org_id == "org-seed-002"
    assert event.event_type == "execution"
    assert event.quantity == 77
    assert event.metadata["run_id"] == "abc123"
    assert event.event_id.startswith("mtr-")


def test_record_meter_event_does_not_affect_other_orgs(store: SubscriptionMeterStore) -> None:
    sub_002_before = store.list_subscriptions(org_id="org-seed-002")[0]

    store.record_meter_event(
        org_id="org-seed-001",
        event_type="incident",
        quantity=1_000,
    )

    sub_002_after = store.list_subscriptions(org_id="org-seed-002")[0]
    assert sub_002_after.used_units == sub_002_before.used_units


def test_record_meter_event_computes_overage_when_usage_exceeds_included_units(
    empty_store: SubscriptionMeterStore,
) -> None:
    sub = empty_store.create_subscription(
        org_id="org-overage-test",
        plan_name="pro",
        status="active",
        billing_email="overage@test.dev",
        included_units=100,
        price_usd_monthly=299,
    )
    empty_store.record_meter_event(
        org_id="org-overage-test",
        event_type="scan",
        quantity=150,
    )
    updated = empty_store.get_subscription(sub.subscription_id)
    assert updated is not None
    assert updated.used_units == 150
    assert updated.overage_units == 50


def test_record_meter_event_overage_is_zero_when_within_included_units(
    empty_store: SubscriptionMeterStore,
) -> None:
    sub = empty_store.create_subscription(
        org_id="org-no-overage",
        plan_name="pro",
        status="active",
        billing_email="noop@test.dev",
        included_units=1_000,
        price_usd_monthly=299,
    )
    empty_store.record_meter_event(
        org_id="org-no-overage",
        event_type="scan",
        quantity=500,
    )
    updated = empty_store.get_subscription(sub.subscription_id)
    assert updated is not None
    assert updated.overage_units == 0


def test_record_meter_event_exact_boundary_no_overage(empty_store: SubscriptionMeterStore) -> None:
    sub = empty_store.create_subscription(
        org_id="org-exact-boundary",
        plan_name="free",
        status="active",
        billing_email="boundary@test.dev",
        included_units=200,
        price_usd_monthly=0,
    )
    empty_store.record_meter_event(
        org_id="org-exact-boundary",
        event_type="scan",
        quantity=200,
    )
    updated = empty_store.get_subscription(sub.subscription_id)
    assert updated is not None
    assert updated.used_units == 200
    assert updated.overage_units == 0


def test_record_meter_event_zero_quantity_no_change(store: SubscriptionMeterStore) -> None:
    sub_before = store.list_subscriptions(org_id="org-seed-001")[0]
    used_before = sub_before.used_units
    before_events = len(store.list_meter_events())
    store.record_meter_event(
        org_id="org-seed-001",
        event_type="scan",
        quantity=0,
    )
    sub_after = store.list_subscriptions(org_id="org-seed-001")[0]
    assert sub_after.used_units == used_before
    assert len(store.list_meter_events()) == before_events + 1


# ---------------------------------------------------------------------------
# list_meter_events — filtering
# ---------------------------------------------------------------------------


def test_list_meter_events_no_filter_returns_all(store: SubscriptionMeterStore) -> None:
    events = store.list_meter_events()
    assert len(events) == 3


def test_list_meter_events_org_filter_returns_only_matching_org(store: SubscriptionMeterStore) -> None:
    events = store.list_meter_events(org_id="org-seed-001")
    assert len(events) == 2
    for e in events:
        assert e.org_id == "org-seed-001"


def test_list_meter_events_org_filter_excludes_other_orgs(store: SubscriptionMeterStore) -> None:
    events = store.list_meter_events(org_id="org-seed-002")
    for e in events:
        assert e.org_id == "org-seed-002"


def test_list_meter_events_event_type_filter(store: SubscriptionMeterStore) -> None:
    events = store.list_meter_events(event_type="scan")
    for e in events:
        assert e.event_type == "scan"


def test_list_meter_events_org_and_event_type_combined_filter(store: SubscriptionMeterStore) -> None:
    events = store.list_meter_events(org_id="org-seed-001", event_type="guard_request")
    assert len(events) == 1
    assert events[0].org_id == "org-seed-001"
    assert events[0].event_type == "guard_request"


def test_list_meter_events_unknown_org_returns_empty(store: SubscriptionMeterStore) -> None:
    events = store.list_meter_events(org_id="org-nonexistent")
    assert events == []


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------


def test_reset_clears_all_subscriptions(store: SubscriptionMeterStore) -> None:
    store.reset()
    assert store.list_subscriptions() == []


def test_reset_clears_all_meter_events(store: SubscriptionMeterStore) -> None:
    store.reset()
    assert store.list_meter_events() == []


def test_reset_allows_re_seed(store: SubscriptionMeterStore) -> None:
    store.reset()
    assert len(store.list_subscriptions()) == 0
    store.seed_defaults()
    assert len(store.list_subscriptions()) == 2
    assert len(store.list_meter_events()) == 3


# ---------------------------------------------------------------------------
# reset_and_reseed()
# ---------------------------------------------------------------------------


def test_reset_and_reseed_clears_then_repopulates(store: SubscriptionMeterStore) -> None:
    store.create_subscription(
        org_id="org-extra",
        plan_name="free",
        status="trialing",
        billing_email="extra@test.dev",
        included_units=1_000,
        price_usd_monthly=0,
    )
    assert len(store.list_subscriptions()) == 3
    store.reset_and_reseed()
    assert len(store.list_subscriptions()) == 2
    assert len(store.list_meter_events()) == 3


def test_reset_and_reseed_produces_clean_seeded_state(store: SubscriptionMeterStore) -> None:
    store.reset_and_reseed()
    subs = store.list_subscriptions()
    assert len(subs) == 2
    org_ids = {s.org_id for s in subs}
    assert "org-seed-001" in org_ids
    assert "org-seed-002" in org_ids


def test_reset_and_reseed_called_on_empty_store_seeds_correctly(
    empty_store: SubscriptionMeterStore,
) -> None:
    empty_store.reset_and_reseed()
    assert len(empty_store.list_subscriptions()) == 2
    assert len(empty_store.list_meter_events()) == 3


# ---------------------------------------------------------------------------
# as_dict()
# ---------------------------------------------------------------------------


def test_as_dict_returns_correct_counts_after_seed(store: SubscriptionMeterStore) -> None:
    d = store.as_dict()
    assert d["subscriptions"] == 2
    assert d["meter_events"] == 3
    assert d["ready"] is True


def test_as_dict_reflects_mutations(store: SubscriptionMeterStore) -> None:
    store.create_subscription(
        org_id="org-asdict-test",
        plan_name="free",
        status="trialing",
        billing_email="asdict@test.dev",
        included_units=5_000,
        price_usd_monthly=0,
    )
    store.record_meter_event(
        org_id="org-asdict-test",
        event_type="scan",
        quantity=10,
    )
    d = store.as_dict()
    assert d["subscriptions"] == 3
    assert d["meter_events"] == 4


def test_as_dict_after_reset_returns_zeros(store: SubscriptionMeterStore) -> None:
    store.reset()
    d = store.as_dict()
    assert d["subscriptions"] == 0
    assert d["meter_events"] == 0


def test_as_dict_after_reset_and_reseed_returns_seed_counts(store: SubscriptionMeterStore) -> None:
    store.reset_and_reseed()
    d = store.as_dict()
    assert d["subscriptions"] == 2
    assert d["meter_events"] == 3
    assert d["ready"] is True


# ---------------------------------------------------------------------------
# is_ready()
# ---------------------------------------------------------------------------


def test_is_ready_always_returns_true(store: SubscriptionMeterStore) -> None:
    assert store.is_ready() is True


def test_is_ready_returns_true_on_empty_store(empty_store: SubscriptionMeterStore) -> None:
    assert empty_store.is_ready() is True


# ---------------------------------------------------------------------------
# BillingStore shim and singleton accessors
# ---------------------------------------------------------------------------


def test_billing_store_shim_resolves_to_subscription_meter_store() -> None:
    assert BillingStore is SubscriptionMeterStore


def test_get_billing_store_and_get_subscription_meter_store_return_same_singleton() -> None:
    assert get_billing_store() is get_subscription_meter_store()


def test_singleton_is_subscription_meter_store_instance() -> None:
    assert isinstance(get_subscription_meter_store(), SubscriptionMeterStore)


def test_singleton_is_already_seeded() -> None:
    store_inst = get_subscription_meter_store()
    assert len(store_inst.list_subscriptions()) >= 2


def test_reset_billing_store_and_reset_subscription_meter_store_are_equivalent() -> None:
    s1 = get_billing_store()
    reset_billing_store()
    s2 = get_subscription_meter_store()
    assert s1 is s2
    assert len(s1.list_subscriptions()) >= 2


def test_module_level_reset_reseeds_singleton(store: SubscriptionMeterStore) -> None:
    reset_subscription_meter_store()
    singleton = get_subscription_meter_store()
    assert len(singleton.list_subscriptions()) >= 2
