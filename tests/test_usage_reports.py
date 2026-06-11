from __future__ import annotations

from decimal import Decimal

import pytest

# ---------------------------------------------------------------------------
# Imports from the IronClaw usage layer
# ---------------------------------------------------------------------------
from app.actionusage import ActionUsage, build_action_usage
from app.actionusagedetail import ActionUsageDetail, build_action_usage_detail
from app.actionusagesnapshot import ActionUsageSnapshot, build_action_usage_snapshot
from app.services.billing_store import (
    MeterEventRecord,
    SubscriptionMeterStore,
    SubscriptionRecord,
    get_subscription_meter_store,
    reset_subscription_meter_store,
)

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture()
def fresh_store() -> SubscriptionMeterStore:
    """Return a SubscriptionMeterStore that is fully reset (no seed data)."""
    store = SubscriptionMeterStore()
    return store


@pytest.fixture()
def seeded_store() -> SubscriptionMeterStore:
    """Return a SubscriptionMeterStore pre-populated with seed defaults."""
    store = SubscriptionMeterStore()
    store.seed_defaults()
    return store


# ===========================================================================
# ActionUsage — core usage record
# ===========================================================================


class TestActionUsageDataclass:
    def test_default_construction_all_none(self) -> None:
        record = ActionUsage()
        assert record.ownerid is None
        assert record.action is None
        assert record.units is None
        assert record.unitcost is None
        assert record.totalcost is None
        assert record.status is None
        assert record.quota is None
        assert record.remaining is None
        assert record.usageid is None
        assert record.generatedat is None
        assert record.events is None
        assert record.metadata is None

    def test_as_dict_has_all_keys(self) -> None:
        record = ActionUsage()
        d = record.as_dict()
        expected_keys = {
            "ownerid",
            "action",
            "units",
            "unitcost",
            "totalcost",
            "status",
            "quota",
            "remaining",
            "usageid",
            "generatedat",
            "events",
            "metadata",
        }
        assert expected_keys == set(d.keys())

    def test_as_dict_decimal_serialised_to_str(self) -> None:
        record = ActionUsage(
            units=Decimal("10"),
            unitcost=Decimal("0.5"),
            totalcost=Decimal("5.0"),
            quota=Decimal("100"),
            remaining=Decimal("90"),
        )
        d = record.as_dict()
        assert d["units"] == "10"
        assert d["unitcost"] == "0.5"
        assert d["totalcost"] == "5.0"
        assert d["quota"] == "100"
        assert d["remaining"] == "90"

    def test_as_dict_none_decimal_stays_none(self) -> None:
        record = ActionUsage()
        d = record.as_dict()
        for key in ("units", "unitcost", "totalcost", "quota", "remaining"):
            assert d[key] is None


class TestBuildActionUsage:
    def test_minimal_call_no_args(self) -> None:
        result = build_action_usage()
        assert isinstance(result, ActionUsage)
        assert result.usageid is not None
        assert result.generatedat is not None

    def test_full_call_produces_correct_values(self) -> None:
        result = build_action_usage(
            owner_id="org-report-01",
            action="scan",
            units=50,
            unit_cost="0.02",
            quota=200,
        )
        assert result.ownerid == "org-report-01"
        assert result.action == "scan"
        assert result.units == Decimal("50")
        assert result.unitcost == Decimal("0.02")
        assert result.totalcost == Decimal("1.00")
        assert result.quota == Decimal("200")
        assert result.remaining == Decimal("150")
        assert result.status == "ok"

    def test_total_cost_computed_from_units_and_unit_cost(self) -> None:
        result = build_action_usage(
            owner_id="org-x",
            action="guard",
            units=10,
            unit_cost="1.5",
        )
        assert result.totalcost == Decimal("15.0")

    def test_remaining_equals_quota_minus_units(self) -> None:
        result = build_action_usage(
            owner_id="org-x",
            action="execute",
            units=20,
            quota=100,
        )
        assert result.remaining == Decimal("80")

    def test_units_equal_quota_leaves_zero_remaining(self) -> None:
        result = build_action_usage(
            owner_id="org-x",
            action="scan",
            units=100,
            quota=100,
        )
        assert result.remaining == Decimal("0")

    def test_units_exceed_quota_raises(self) -> None:
        with pytest.raises(ValueError, match="quota"):
            build_action_usage(
                owner_id="org-x",
                action="scan",
                units=200,
                quota=100,
            )

    def test_negative_units_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage(
                owner_id="org-x",
                action="scan",
                units=-1,
            )

    def test_negative_unit_cost_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage(
                owner_id="org-x",
                action="scan",
                units=10,
                unit_cost=-0.5,
            )

    def test_negative_quota_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage(
                owner_id="org-x",
                action="scan",
                quota=-50,
            )

    def test_blank_owner_id_raises(self) -> None:
        with pytest.raises(ValueError, match="owner_id"):
            build_action_usage(owner_id="   ", action="scan")

    def test_owner_without_action_raises(self) -> None:
        with pytest.raises(ValueError, match="action"):
            build_action_usage(owner_id="org-x")

    def test_action_without_owner_raises(self) -> None:
        with pytest.raises(ValueError, match="owner_id"):
            build_action_usage(action="scan")

    def test_usage_id_prefix(self) -> None:
        result = build_action_usage(owner_id="org-x", action="guard")
        assert result.usageid.startswith("usage-")

    def test_as_dict_keys_stable_across_two_builds(self) -> None:
        r1 = build_action_usage(owner_id="org-a", action="scan", units=5)
        r2 = build_action_usage(owner_id="org-b", action="exec", units=10)
        assert set(r1.as_dict().keys()) == set(r2.as_dict().keys())


# ===========================================================================
# ActionUsageDetail
# ===========================================================================


class TestActionUsageDetailDataclass:
    def test_default_construction(self) -> None:
        detail = ActionUsageDetail()
        assert detail.usageid is None
        assert detail.ownerid is None
        assert detail.action is None
        assert detail.metadata == {}

    def test_as_dict_returns_dict(self) -> None:
        detail = ActionUsageDetail(
            usageid="u-001",
            ownerid="org-01",
            action="scan",
            units=Decimal("5"),
            unitcost=Decimal("1"),
            totalcost=Decimal("5"),
            status="ok",
        )
        d = detail.as_dict()
        assert isinstance(d, dict)
        assert d["usageid"] == "u-001"
        assert d["units"] == "5"

    def test_decimal_fields_serialised_to_str(self) -> None:
        detail = ActionUsageDetail(
            units=Decimal("3.14"),
            unitcost=Decimal("0.01"),
            totalcost=Decimal("0.0314"),
        )
        d = detail.as_dict()
        assert d["units"] == "3.14"
        assert d["unitcost"] == "0.01"
        assert d["totalcost"] == "0.0314"


class TestBuildActionUsageDetail:
    def test_no_args_call_succeeds(self) -> None:
        detail = build_action_usage_detail()
        assert isinstance(detail, ActionUsageDetail)
        assert detail.usageid is not None
        assert detail.ownerid is not None

    def test_total_cost_derived_from_units_and_unit_cost(self) -> None:
        detail = build_action_usage_detail(units=4, unit_cost=2.5)
        assert detail.totalcost == Decimal("10.0")

    def test_negative_units_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage_detail(units=-1)

    def test_negative_unit_cost_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage_detail(unit_cost=-0.1)

    def test_metadata_coerced_to_dict(self) -> None:
        detail = build_action_usage_detail(metadata={"source": "report"})
        assert detail.metadata == {"source": "report"}

    def test_metadata_none_produces_empty_dict(self) -> None:
        detail = build_action_usage_detail(metadata=None)
        assert detail.metadata == {}

    def test_all_fields_json_safe(self) -> None:
        detail = build_action_usage_detail(
            usage_id="u-test",
            owner_id="org-test",
            action="execute",
            units=7,
            unit_cost="0.10",
            status="ok",
            request_id="req-001",
            metadata={"env": "test"},
        )
        d = detail.as_dict()
        for key, value in d.items():
            if key == "metadata":
                assert isinstance(value, dict)
            else:
                assert value is None or isinstance(value, (str, int, float, bool, list, dict))

    def test_as_dict_key_set_is_stable(self) -> None:
        d1 = build_action_usage_detail(units=1, unit_cost=1).as_dict()
        d2 = build_action_usage_detail().as_dict()
        assert set(d1.keys()) == set(d2.keys())


# ===========================================================================
# ActionUsageSnapshot
# ===========================================================================


class TestActionUsageSnapshotDataclass:
    def test_default_construction_all_none(self) -> None:
        snap = ActionUsageSnapshot()
        assert snap.snapshotid is None
        assert snap.ownerid is None
        assert snap.totalunits is None
        assert snap.totalcost is None
        assert snap.remaining is None
        assert snap.quota is None

    def test_as_dict_has_all_keys(self) -> None:
        snap = ActionUsageSnapshot()
        d = snap.as_dict()
        expected = {
            "snapshotid",
            "ownerid",
            "periodstart",
            "periodend",
            "totalunits",
            "totalcost",
            "remaining",
            "quota",
            "events",
            "summary",
            "generatedat",
        }
        assert expected == set(d.keys())

    def test_decimal_fields_serialised_to_str(self) -> None:
        snap = ActionUsageSnapshot(
            totalunits=Decimal("100"),
            totalcost=Decimal("10.00"),
            remaining=Decimal("50"),
            quota=Decimal("150"),
        )
        d = snap.as_dict()
        assert d["totalunits"] == "100"
        assert d["totalcost"] == "10.00"
        assert d["remaining"] == "50"
        assert d["quota"] == "150"


class TestBuildActionUsageSnapshot:
    def test_minimal_call_no_args(self) -> None:
        snap = build_action_usage_snapshot()
        assert isinstance(snap, ActionUsageSnapshot)
        assert snap.snapshotid is not None
        assert snap.generatedat is not None

    def test_full_call_produces_correct_values(self) -> None:
        snap = build_action_usage_snapshot(
            owner_id="org-snap-01",
            period_start="2026-01-01T00:00:00Z",
            period_end="2026-01-31T23:59:59Z",
            total_units=200,
            total_cost="4.00",
            quota=500,
        )
        assert snap.ownerid == "org-snap-01"
        assert snap.periodstart == "2026-01-01T00:00:00Z"
        assert snap.periodend == "2026-01-31T23:59:59Z"
        assert snap.totalunits == Decimal("200")
        assert snap.totalcost == Decimal("4.00")
        assert snap.quota == Decimal("500")
        assert snap.remaining == Decimal("300")

    def test_remaining_equals_quota_minus_total_units(self) -> None:
        snap = build_action_usage_snapshot(
            owner_id="org-x",
            total_units=40,
            quota=100,
        )
        assert snap.remaining == Decimal("60")

    def test_total_units_equal_quota_leaves_zero_remaining(self) -> None:
        snap = build_action_usage_snapshot(
            owner_id="org-x",
            total_units=100,
            quota=100,
        )
        assert snap.remaining == Decimal("0")

    def test_total_units_exceeding_quota_raises(self) -> None:
        with pytest.raises(ValueError, match="remaining"):
            build_action_usage_snapshot(
                owner_id="org-x",
                total_units=150,
                quota=100,
            )

    def test_negative_total_units_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage_snapshot(owner_id="org-x", total_units=-1)

    def test_negative_total_cost_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage_snapshot(owner_id="org-x", total_cost=-0.01)

    def test_negative_quota_raises(self) -> None:
        with pytest.raises(ValueError):
            build_action_usage_snapshot(owner_id="org-x", quota=-10)

    def test_zero_units_nonzero_cost_raises(self) -> None:
        with pytest.raises(ValueError, match="total_cost"):
            build_action_usage_snapshot(
                owner_id="org-x",
                total_units=0,
                total_cost="5.00",
            )

    def test_zero_units_zero_cost_ok(self) -> None:
        snap = build_action_usage_snapshot(
            owner_id="org-x",
            total_units=0,
            total_cost="0",
        )
        assert snap.totalunits == Decimal("0")
        assert snap.totalcost == Decimal("0")

    def test_blank_owner_raises(self) -> None:
        with pytest.raises(ValueError, match="owner_id"):
            build_action_usage_snapshot(owner_id="   ")

    def test_snapshot_id_prefix(self) -> None:
        snap = build_action_usage_snapshot(owner_id="org-x")
        assert snap.snapshotid.startswith("snapshot-")

    def test_as_dict_key_set_stable_across_builds(self) -> None:
        s1 = build_action_usage_snapshot(owner_id="org-a", total_units=10, quota=50).as_dict()
        s2 = build_action_usage_snapshot().as_dict()
        assert set(s1.keys()) == set(s2.keys())

    def test_quota_only_no_units_sets_remaining_to_quota(self) -> None:
        snap = build_action_usage_snapshot(owner_id="org-x", quota=200)
        assert snap.remaining == Decimal("200")


# ===========================================================================
# SubscriptionMeterStore  (usage reports — metering / subscription layer)
# ===========================================================================


class TestSubscriptionMeterStoreInit:
    def test_fresh_store_empty(self, fresh_store: SubscriptionMeterStore) -> None:
        assert fresh_store.list_subscriptions() == []
        assert fresh_store.list_meter_events() == []

    def test_seed_defaults_populates_records(self, seeded_store: SubscriptionMeterStore) -> None:
        subs = seeded_store.list_subscriptions()
        events = seeded_store.list_meter_events()
        assert len(subs) >= 2
        assert len(events) >= 3

    def test_seed_defaults_idempotent(self, seeded_store: SubscriptionMeterStore) -> None:
        before_subs = len(seeded_store.list_subscriptions())
        seeded_store.seed_defaults()  # second call — should not double up
        assert len(seeded_store.list_subscriptions()) == before_subs

    def test_is_ready_returns_true(self, fresh_store: SubscriptionMeterStore) -> None:
        assert fresh_store.is_ready() is True


class TestSubscriptionCRUD:
    def test_create_subscription_returns_record(self, fresh_store: SubscriptionMeterStore) -> None:
        record = fresh_store.create_subscription(
            org_id="org-report-01",
            plan_name="pro",
            status="active",
            billing_email="ops@ironclaw.dev",
            included_units=25_000,
            price_usd_monthly=299,
        )
        assert isinstance(record, SubscriptionRecord)
        assert record.org_id == "org-report-01"
        assert record.plan_name == "pro"
        assert record.status == "active"
        assert record.included_units == 25_000
        assert record.used_units == 0
        assert record.overage_units == 0

    def test_create_subscription_id_has_prefix(self, fresh_store: SubscriptionMeterStore) -> None:
        record = fresh_store.create_subscription(
            org_id="org-x",
            plan_name="free",
            status="active",
            billing_email="x@x.com",
            included_units=5_000,
            price_usd_monthly=0,
        )
        assert record.subscription_id.startswith("sub-")

    def test_get_subscription_by_id(self, fresh_store: SubscriptionMeterStore) -> None:
        created = fresh_store.create_subscription(
            org_id="org-get",
            plan_name="enterprise",
            status="active",
            billing_email="billing@get.dev",
            included_units=60_000,
            price_usd_monthly=2499,
        )
        fetched = fresh_store.get_subscription(created.subscription_id)
        assert fetched is not None
        assert fetched.subscription_id == created.subscription_id

    def test_get_subscription_missing_returns_none(self, fresh_store: SubscriptionMeterStore) -> None:
        assert fresh_store.get_subscription("sub-does-not-exist") is None

    def test_list_subscriptions_filter_by_org_id(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-alpha",
            plan_name="pro",
            status="active",
            billing_email="a@a.com",
            included_units=25_000,
            price_usd_monthly=299,
        )
        fresh_store.create_subscription(
            org_id="org-beta",
            plan_name="free",
            status="active",
            billing_email="b@b.com",
            included_units=5_000,
            price_usd_monthly=0,
        )
        results = fresh_store.list_subscriptions(org_id="org-alpha")
        assert len(results) == 1
        assert results[0].org_id == "org-alpha"

    def test_list_subscriptions_no_filter_returns_all(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-1",
            plan_name="pro",
            status="active",
            billing_email="c@c.com",
            included_units=25_000,
            price_usd_monthly=299,
        )
        fresh_store.create_subscription(
            org_id="org-2",
            plan_name="enterprise",
            status="active",
            billing_email="d@d.com",
            included_units=60_000,
            price_usd_monthly=2499,
        )
        assert len(fresh_store.list_subscriptions()) == 2

    def test_update_subscription_changes_status(self, fresh_store: SubscriptionMeterStore) -> None:
        created = fresh_store.create_subscription(
            org_id="org-upd",
            plan_name="pro",
            status="trialing",
            billing_email="upd@ironclaw.dev",
            included_units=25_000,
            price_usd_monthly=299,
        )
        updated = fresh_store.update_subscription(
            created.subscription_id,
            status="active",
        )
        assert updated is not None
        assert updated.status == "active"
        assert updated.plan_name == "pro"

    def test_update_subscription_missing_id_returns_none(self, fresh_store: SubscriptionMeterStore) -> None:
        result = fresh_store.update_subscription("sub-ghost", status="canceled")
        assert result is None

    def test_update_subscription_changes_plan_name(self, fresh_store: SubscriptionMeterStore) -> None:
        created = fresh_store.create_subscription(
            org_id="org-plan",
            plan_name="free",
            status="active",
            billing_email="plan@ironclaw.dev",
            included_units=5_000,
            price_usd_monthly=0,
        )
        updated = fresh_store.update_subscription(
            created.subscription_id,
            status="active",
            plan_name="enterprise",
        )
        assert updated is not None
        assert updated.plan_name == "enterprise"


# ===========================================================================
# MeterEvent CRUD
# ===========================================================================


class TestMeterEventCRUD:
    def test_record_meter_event_returns_record(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-meter",
            plan_name="pro",
            status="active",
            billing_email="meter@ironclaw.dev",
            included_units=25_000,
            price_usd_monthly=299,
        )
        event = fresh_store.record_meter_event(
            org_id="org-meter",
            event_type="scan",
            quantity=100,
        )
        assert isinstance(event, MeterEventRecord)
        assert event.org_id == "org-meter"
        assert event.event_type == "scan"
        assert event.quantity == 100
        assert event.event_id.startswith("mtr-")

    def test_record_meter_event_increments_used_units(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-inc",
            plan_name="pro",
            status="active",
            billing_email="inc@ironclaw.dev",
            included_units=25_000,
            price_usd_monthly=299,
        )
        fresh_store.record_meter_event(org_id="org-inc", event_type="scan", quantity=500)
        subs = fresh_store.list_subscriptions(org_id="org-inc")
        assert subs[0].used_units == 500

    def test_record_meter_event_computes_overage(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-ov",
            plan_name="free",
            status="active",
            billing_email="ov@ironclaw.dev",
            included_units=5_000,
            price_usd_monthly=0,
        )
        fresh_store.record_meter_event(org_id="org-ov", event_type="scan", quantity=6_000)
        subs = fresh_store.list_subscriptions(org_id="org-ov")
        assert subs[0].overage_units == 1_000

    def test_list_meter_events_filter_by_org_id(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-ev-a",
            plan_name="pro",
            status="active",
            billing_email="eva@ironclaw.dev",
            included_units=25_000,
            price_usd_monthly=299,
        )
        fresh_store.create_subscription(
            org_id="org-ev-b",
            plan_name="free",
            status="active",
            billing_email="evb@ironclaw.dev",
            included_units=5_000,
            price_usd_monthly=0,
        )
        fresh_store.record_meter_event(org_id="org-ev-a", event_type="scan", quantity=10)
        fresh_store.record_meter_event(org_id="org-ev-b", event_type="scan", quantity=20)
        results = fresh_store.list_meter_events(org_id="org-ev-a")
        assert len(results) == 1
        assert results[0].org_id == "org-ev-a"

    def test_list_meter_events_filter_by_event_type(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-type",
            plan_name="enterprise",
            status="active",
            billing_email="type@ironclaw.dev",
            included_units=60_000,
            price_usd_monthly=2499,
        )
        fresh_store.record_meter_event(org_id="org-type", event_type="scan", quantity=5)
        fresh_store.record_meter_event(org_id="org-type", event_type="guard_request", quantity=3)
        scans = fresh_store.list_meter_events(event_type="scan")
        assert all(e.event_type == "scan" for e in scans)

    def test_meter_event_to_dict_isoformat_z(self, fresh_store: SubscriptionMeterStore) -> None:
        fresh_store.create_subscription(
            org_id="org-iso",
            plan_name="pro",
            status="active",
            billing_email="iso@ironclaw.dev",
            included_units=25_000,
            price_usd_monthly=299,
        )
        event = fresh_store.record_meter_event(org_id="org-iso", event_type="execution", quantity=1)
        d = event.to_dict()
        assert d["occurred_at"].endswith("Z")


# ===========================================================================
# Store lifecycle
# ===========================================================================


class TestStoreLifecycle:
    def test_reset_clears_all_records(self, seeded_store: SubscriptionMeterStore) -> None:
        seeded_store.reset()
        assert seeded_store.list_subscriptions() == []
        assert seeded_store.list_meter_events() == []

    def test_as_dict_reports_counts(self, seeded_store: SubscriptionMeterStore) -> None:
        d = seeded_store.as_dict()
        assert d["subscriptions"] >= 2
        assert d["meter_events"] >= 3
        assert d["ready"] is True

    def test_module_singleton_get_and_reset(self) -> None:
        store = get_subscription_meter_store()
        assert store.is_ready() is True
        reset_subscription_meter_store()
        store2 = get_subscription_meter_store()
        assert store2 is store
        assert store2.is_ready() is True
