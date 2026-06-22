from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.core.billing import (
    PLAN_DEFINITIONS,
    TOKENS_PER_UNIT,
    UNIT_PACKAGE_CATALOG,
    BillingCustomer,
    BillingRegistry,
    BillingSubscription,
    BillingUsageError,
    _reset_billing_registry_for_testing,
    get_billing_registry,
    resolve_billing_owner,
    units_required_for_tokens,
)
from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_fake_store() -> MagicMock:
    store = MagicMock()
    store.select.return_value = []
    store.insert.return_value = []
    store.update.return_value = []
    store.delete.return_value = []
    return store


def _make_registry() -> BillingRegistry:
    return BillingRegistry(store=_make_fake_store())


def _create_customer(
    registry: BillingRegistry,
    *,
    email: str = "user@example.com",
    display_name: str = "Test User",
    plan: str = "starter-5k",
) -> BillingCustomer:
    return registry.create_customer(
        email=email,
        display_name=display_name,
        plan=plan,
    )


def _create_active_subscription(
    registry: BillingRegistry,
    customer_id: str,
    *,
    plan: str = "starter-5k",
) -> BillingSubscription:
    future = datetime.now(UTC) + timedelta(days=30)
    return registry.create_subscription(
        customer_id=customer_id,
        plan=plan,
        status="active",
        period_end=future,
    )


# ---------------------------------------------------------------------------
# UNIT_PACKAGE_CATALOG integrity
# ---------------------------------------------------------------------------


class TestUnitPackageCatalog:
    def test_catalog_has_three_entries(self) -> None:
        assert len(UNIT_PACKAGE_CATALOG) == 3

    def test_catalog_codes_match_plan_definitions(self) -> None:
        catalog_codes = {e["code"] for e in UNIT_PACKAGE_CATALOG}
        assert catalog_codes == set(PLAN_DEFINITIONS.keys())

    def test_catalog_units_match_plan_definitions(self) -> None:
        for entry in UNIT_PACKAGE_CATALOG:
            plan = PLAN_DEFINITIONS[entry["code"]]
            assert entry["units"] == plan["unit_limit"], f"units mismatch for {entry['code']!r}"

    def test_catalog_price_usd_match_plan_definitions(self) -> None:
        for entry in UNIT_PACKAGE_CATALOG:
            plan = PLAN_DEFINITIONS[entry["code"]]
            assert entry["price_usd"] == plan["price_usd"], f"price_usd mismatch for {entry['code']!r}"

    def test_catalog_tokens_per_unit_all_equal_constant(self) -> None:
        for entry in UNIT_PACKAGE_CATALOG:
            assert entry["tokens_per_unit"] == TOKENS_PER_UNIT

    def test_starter_tier_values(self) -> None:
        starter = next(e for e in UNIT_PACKAGE_CATALOG if e["code"] == "starter-5k")
        assert starter["units"] == BILLING_TIER_5K_UNITS
        assert starter["price_usd"] == BILLING_TIER_5K_PRICE_USD

    def test_team_tier_values(self) -> None:
        team = next(e for e in UNIT_PACKAGE_CATALOG if e["code"] == "team-25k")
        assert team["units"] == BILLING_TIER_25K_UNITS
        assert team["price_usd"] == BILLING_TIER_25K_PRICE_USD

    def test_enterprise_tier_values(self) -> None:
        ent = next(e for e in UNIT_PACKAGE_CATALOG if e["code"] == "enterprise-60k")
        assert ent["units"] == BILLING_TIER_60K_UNITS
        assert ent["price_usd"] == BILLING_TIER_60K_PRICE_USD


# ---------------------------------------------------------------------------
# units_required_for_tokens
# ---------------------------------------------------------------------------


class TestUnitsRequiredForTokens:
    def test_zero_tokens_returns_zero(self) -> None:
        assert units_required_for_tokens(0) == 0

    def test_negative_tokens_returns_zero(self) -> None:
        assert units_required_for_tokens(-1) == 0

    def test_exact_one_unit(self) -> None:
        assert units_required_for_tokens(TOKENS_PER_UNIT) == 1

    def test_one_over_unit_boundary_rounds_up(self) -> None:
        assert units_required_for_tokens(TOKENS_PER_UNIT + 1) == 2

    def test_half_unit_rounds_up_to_one(self) -> None:
        assert units_required_for_tokens(TOKENS_PER_UNIT // 2) == 1

    def test_large_value(self) -> None:
        assert units_required_for_tokens(TOKENS_PER_UNIT * 100) == 100


# ---------------------------------------------------------------------------
# resolve_billing_owner
# ---------------------------------------------------------------------------


class TestResolveBillingOwner:
    def _ctx(self, key_type: str | None = None, org_id: str | None = None) -> Any:
        ctx = MagicMock()
        ctx.key_type = key_type
        ctx.org_id = org_id
        return ctx

    def test_org_key_type_returns_ic_org_prefix(self) -> None:
        ctx = self._ctx(key_type="org", org_id="abc123")
        result = resolve_billing_owner(ctx, "user@example.com")
        assert result == "ic_org_abc123"

    def test_org_key_type_without_org_id_falls_back_to_email(self) -> None:
        ctx = self._ctx(key_type="org", org_id=None)
        result = resolve_billing_owner(ctx, "User@Example.COM")
        assert result == "user@example.com"

    def test_personal_key_type_returns_normalised_email(self) -> None:
        ctx = self._ctx(key_type="personal", org_id=None)
        result = resolve_billing_owner(ctx, "  UPPER@Domain.COM  ")
        assert result == "upper@domain.com"

    def test_none_key_type_falls_back_to_email(self) -> None:
        ctx = self._ctx(key_type=None, org_id="x")
        result = resolve_billing_owner(ctx, "a@b.com")
        assert result == "a@b.com"

    def test_object_without_attrs_uses_email(self) -> None:
        result = resolve_billing_owner(object(), "bare@test.com")
        assert result == "bare@test.com"


# ---------------------------------------------------------------------------
# BillingCustomer validation
# ---------------------------------------------------------------------------


class TestBillingCustomerValidation:
    def test_invalid_email_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid email"):
            BillingCustomer(
                customer_id="c1",
                email="notanemail",
                display_name="x",
                plan="starter-5k",
            )

    def test_unknown_plan_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown plan code"):
            BillingCustomer(
                customer_id="c1",
                email="u@example.com",
                display_name="x",
                plan="nonexistent",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# BillingRegistry — create_customer / get_customer / list_customers
# ---------------------------------------------------------------------------


class TestBillingRegistryCRUDCustomer:
    def test_create_customer_returns_billing_customer(self) -> None:
        reg = _make_registry()
        customer = _create_customer(reg)
        assert isinstance(customer, BillingCustomer)
        assert customer.customer_id.startswith("cus_")

    def test_create_customer_normalises_email(self) -> None:
        reg = _make_registry()
        customer = reg.create_customer(
            email="  TEST@Example.COM  ",
            display_name="T",
            plan="starter-5k",
        )
        assert customer.email == "test@example.com"

    def test_create_customer_sets_active_true(self) -> None:
        reg = _make_registry()
        customer = _create_customer(reg)
        assert customer.active is True

    def test_get_customer_returns_created_customer(self) -> None:
        reg = _make_registry()
        created = _create_customer(reg)
        fetched = reg.get_customer(created.customer_id)
        assert fetched is created

    def test_get_customer_unknown_id_returns_none(self) -> None:
        reg = _make_registry()
        assert reg.get_customer("nonexistent") is None

    def test_list_customers_empty_initially(self) -> None:
        reg = _make_registry()
        assert reg.list_customers() == []

    def test_list_customers_reflects_created(self) -> None:
        reg = _make_registry()
        c1 = _create_customer(reg, email="a@a.com")
        c2 = _create_customer(reg, email="b@b.com")
        customers = reg.list_customers()
        assert len(customers) == 2
        ids = {c.customer_id for c in customers}
        assert c1.customer_id in ids
        assert c2.customer_id in ids

    def test_create_customer_invalid_plan_raises(self) -> None:
        reg = _make_registry()
        with pytest.raises(ValueError, match="Unknown plan code"):
            reg.create_customer(
                email="u@example.com",
                display_name="x",
                plan="bogus-plan",
            )

    def test_create_customer_persists_to_store(self) -> None:
        store = _make_fake_store()
        reg = BillingRegistry(store=store)
        _create_customer(reg)
        store.insert.assert_called_once()
        call_args = store.insert.call_args
        assert call_args[0][0] == "billing_customers"


# ---------------------------------------------------------------------------
# BillingRegistry — create_subscription / list_subscriptions / get_active
# ---------------------------------------------------------------------------


class TestBillingRegistryCRUDSubscription:
    def test_create_subscription_returns_billing_subscription(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        assert isinstance(sub, BillingSubscription)
        assert sub.subscription_id.startswith("sub_")

    def test_create_subscription_unknown_customer_raises(self) -> None:
        reg = _make_registry()
        with pytest.raises(KeyError, match="Unknown customer_id"):
            reg.create_subscription(
                customer_id="ghost",
                plan="starter-5k",
            )

    def test_list_subscriptions_empty_initially(self) -> None:
        reg = _make_registry()
        assert reg.list_subscriptions() == []

    def test_list_subscriptions_reflects_created(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        subs = reg.list_subscriptions()
        assert len(subs) == 1
        assert subs[0].subscription_id == sub.subscription_id

    def test_get_active_subscription_returns_active(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        result = reg.get_active_subscription_for_customer(c.customer_id)
        assert result is sub

    def test_get_active_subscription_no_subscription_returns_none(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        result = reg.get_active_subscription_for_customer(c.customer_id)
        assert result is None

    def test_get_active_subscription_cancelled_returns_none(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        reg.cancel_subscription(sub.subscription_id)
        result = reg.get_active_subscription_for_customer(c.customer_id)
        assert result is None

    def test_subscription_persists_to_store(self) -> None:
        store = _make_fake_store()
        reg = BillingRegistry(store=store)
        c = reg.create_customer(email="u@u.com", display_name="U", plan="starter-5k")
        reg.create_subscription(customer_id=c.customer_id, plan="starter-5k")
        assert store.insert.call_count == 2


# ---------------------------------------------------------------------------
# record_usage
# ---------------------------------------------------------------------------


class TestRecordUsage:
    def test_record_usage_increments_units_consumed(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        reg.record_usage(customer_id=c.customer_id, units=10)
        assert sub.units_consumed == 10

    def test_record_usage_at_exact_limit_succeeds(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        limit = sub.unit_limit
        reg.record_usage(customer_id=c.customer_id, units=limit)
        assert sub.units_consumed == limit

    def test_record_usage_over_limit_raises_billing_usage_error(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        limit = sub.unit_limit
        with pytest.raises(BillingUsageError) as exc_info:
            reg.record_usage(customer_id=c.customer_id, units=limit + 1)
        err = exc_info.value
        assert err.customer_id == c.customer_id
        assert err.subscription_id == sub.subscription_id
        assert err.units_requested == limit + 1
        assert err.units_consumed == 0
        assert err.unit_limit == limit

    def test_record_usage_zero_units_raises_value_error(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        _create_active_subscription(reg, c.customer_id)
        with pytest.raises(ValueError, match="units must be positive"):
            reg.record_usage(customer_id=c.customer_id, units=0)

    def test_record_usage_negative_units_raises_value_error(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        _create_active_subscription(reg, c.customer_id)
        with pytest.raises(ValueError, match="units must be positive"):
            reg.record_usage(customer_id=c.customer_id, units=-5)

    def test_record_usage_no_active_subscription_raises_key_error(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        with pytest.raises(KeyError, match="No active subscription"):
            reg.record_usage(customer_id=c.customer_id, units=1)

    def test_record_usage_cumulative_enforcement(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        limit = sub.unit_limit
        reg.record_usage(customer_id=c.customer_id, units=limit - 1)
        with pytest.raises(BillingUsageError):
            reg.record_usage(customer_id=c.customer_id, units=2)

    def test_record_usage_error_attributes_reflect_consumed_state(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        limit = sub.unit_limit
        reg.record_usage(customer_id=c.customer_id, units=limit - 5)
        with pytest.raises(BillingUsageError) as exc_info:
            reg.record_usage(customer_id=c.customer_id, units=10)
        err = exc_info.value
        assert err.units_consumed == limit - 5
        assert err.units_requested == 10

    def test_record_usage_persists_update_to_store(self) -> None:
        store = _make_fake_store()
        reg = BillingRegistry(store=store)
        c = reg.create_customer(email="u@u.com", display_name="U", plan="starter-5k")
        future = datetime.now(UTC) + timedelta(days=30)
        reg.create_subscription(customer_id=c.customer_id, plan="starter-5k", period_end=future)
        store.update.reset_mock()
        reg.record_usage(customer_id=c.customer_id, units=1)
        store.update.assert_called_once()


# ---------------------------------------------------------------------------
# upgrade_plan
# ---------------------------------------------------------------------------


class TestUpgradePlan:
    def test_upgrade_plan_returns_customer_and_new_subscription(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg, plan="starter-5k")
        _create_active_subscription(reg, c.customer_id, plan="starter-5k")
        new_customer, new_sub = reg.upgrade_plan(customer_id=c.customer_id, new_plan="team-25k")
        assert new_customer.customer_id == c.customer_id
        assert new_sub.plan == "team-25k"
        assert new_sub.status == "active"

    def test_upgrade_plan_sets_old_subscription_to_upgraded(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg, plan="starter-5k")
        old_sub = _create_active_subscription(reg, c.customer_id, plan="starter-5k")
        reg.upgrade_plan(customer_id=c.customer_id, new_plan="team-25k")
        assert old_sub.status == "upgraded"

    def test_upgrade_plan_updates_customer_plan_code(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg, plan="starter-5k")
        _create_active_subscription(reg, c.customer_id, plan="starter-5k")
        reg.upgrade_plan(customer_id=c.customer_id, new_plan="enterprise-60k")
        assert c.plan == "enterprise-60k"

    def test_upgrade_plan_new_subscription_is_active(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg, plan="starter-5k")
        _create_active_subscription(reg, c.customer_id)
        _, new_sub = reg.upgrade_plan(customer_id=c.customer_id, new_plan="team-25k")
        fetched = reg.get_active_subscription_for_customer(c.customer_id)
        assert fetched is new_sub

    def test_upgrade_plan_unknown_customer_raises(self) -> None:
        reg = _make_registry()
        with pytest.raises(KeyError, match="Unknown customer_id"):
            reg.upgrade_plan(customer_id="ghost", new_plan="team-25k")

    def test_upgrade_plan_invalid_plan_raises(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg, plan="starter-5k")
        with pytest.raises(ValueError, match="Unknown plan code"):
            reg.upgrade_plan(customer_id=c.customer_id, new_plan="invalid-plan")


# ---------------------------------------------------------------------------
# reset_period
# ---------------------------------------------------------------------------


class TestResetPeriod:
    def test_reset_period_zeroes_units_consumed(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        reg.record_usage(customer_id=c.customer_id, units=50)
        assert sub.units_consumed == 50
        new_end = datetime.now(UTC) + timedelta(days=30)
        reg.reset_period(subscription_id=sub.subscription_id, new_period_end=new_end)
        assert sub.units_consumed == 0

    def test_reset_period_updates_period_end(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        new_end = datetime.now(UTC) + timedelta(days=60)
        reg.reset_period(subscription_id=sub.subscription_id, new_period_end=new_end)
        assert sub.current_period_end == new_end

    def test_reset_period_updates_period_start_to_now(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        before = datetime.now(UTC)
        new_end = before + timedelta(days=30)
        reg.reset_period(subscription_id=sub.subscription_id, new_period_end=new_end)
        after = datetime.now(UTC)
        assert before <= sub.current_period_start <= after

    def test_reset_period_unknown_subscription_raises(self) -> None:
        reg = _make_registry()
        with pytest.raises(KeyError, match="Unknown subscription_id"):
            reg.reset_period(
                subscription_id="ghost",
                new_period_end=datetime.now(UTC) + timedelta(days=30),
            )

    def test_reset_period_persists_to_store(self) -> None:
        store = _make_fake_store()
        reg = BillingRegistry(store=store)
        c = reg.create_customer(email="u@u.com", display_name="U", plan="starter-5k")
        future = datetime.now(UTC) + timedelta(days=30)
        sub = reg.create_subscription(customer_id=c.customer_id, plan="starter-5k", period_end=future)
        store.update.reset_mock()
        reg.reset_period(
            subscription_id=sub.subscription_id,
            new_period_end=datetime.now(UTC) + timedelta(days=30),
        )
        store.update.assert_called_once()


# ---------------------------------------------------------------------------
# can_consume
# ---------------------------------------------------------------------------


class TestCanConsume:
    def test_can_consume_within_limit_returns_true(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        assert reg.can_consume(customer_id=c.customer_id, units=sub.unit_limit)

    def test_can_consume_over_limit_returns_false(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        assert not reg.can_consume(customer_id=c.customer_id, units=sub.unit_limit + 1)

    def test_can_consume_zero_units_returns_false(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        _create_active_subscription(reg, c.customer_id)
        assert not reg.can_consume(customer_id=c.customer_id, units=0)

    def test_can_consume_no_active_subscription_returns_false(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        assert not reg.can_consume(customer_id=c.customer_id, units=1)

    def test_can_consume_after_partial_usage(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        limit = sub.unit_limit
        reg.record_usage(customer_id=c.customer_id, units=limit - 1)
        assert reg.can_consume(customer_id=c.customer_id, units=1)
        assert not reg.can_consume(customer_id=c.customer_id, units=2)

    def test_can_consume_at_exhausted_limit_returns_false(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        reg.record_usage(customer_id=c.customer_id, units=sub.unit_limit)
        assert not reg.can_consume(customer_id=c.customer_id, units=1)


# ---------------------------------------------------------------------------
# can_consume_tokens
# ---------------------------------------------------------------------------


class TestCanConsumeTokens:
    def test_can_consume_tokens_within_coverage_returns_true(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        safe_tokens = sub.token_coverage_limit
        assert reg.can_consume_tokens(customer_id=c.customer_id, token_count=safe_tokens)

    def test_can_consume_tokens_over_coverage_returns_false(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        over = sub.token_coverage_limit + 1
        assert not reg.can_consume_tokens(customer_id=c.customer_id, token_count=over)

    def test_can_consume_tokens_zero_returns_false(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        _create_active_subscription(reg, c.customer_id)
        assert not reg.can_consume_tokens(customer_id=c.customer_id, token_count=0)

    def test_can_consume_tokens_no_subscription_returns_false(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        assert not reg.can_consume_tokens(customer_id=c.customer_id, token_count=100)

    def test_can_consume_tokens_delegates_via_units_required(self) -> None:
        reg = _make_registry()
        c = _create_customer(reg)
        sub = _create_active_subscription(reg, c.customer_id)
        assert reg.can_consume_tokens(customer_id=c.customer_id, token_count=TOKENS_PER_UNIT)
        assert reg.can_consume_tokens(customer_id=c.customer_id, token_count=TOKENS_PER_UNIT + 1)
        reg.record_usage(customer_id=c.customer_id, units=sub.unit_limit - 1)
        assert reg.can_consume_tokens(customer_id=c.customer_id, token_count=1)
        assert not reg.can_consume_tokens(customer_id=c.customer_id, token_count=TOKENS_PER_UNIT + 1)


# ---------------------------------------------------------------------------
# BillingSubscription computed properties
# ---------------------------------------------------------------------------


class TestBillingSubscriptionProperties:
    def _make_sub(
        self,
        *,
        plan: str = "starter-5k",
        units_consumed: int = 0,
        status: str = "active",
        period_days: int = 30,
    ) -> BillingSubscription:
        now = datetime.now(UTC)
        return BillingSubscription(
            subscription_id="sub_test",
            customer_id="cus_test",
            plan=plan,  # type: ignore[arg-type]
            status=status,
            created_at=now,
            current_period_start=now,
            current_period_end=now + timedelta(days=period_days),
            units_consumed=units_consumed,
        )

    def test_remaining_units_full(self) -> None:
        sub = self._make_sub(plan="starter-5k", units_consumed=0)
        assert sub.remaining_units == BILLING_TIER_5K_UNITS

    def test_remaining_units_after_consumption(self) -> None:
        sub = self._make_sub(plan="starter-5k", units_consumed=100)
        assert sub.remaining_units == BILLING_TIER_5K_UNITS - 100

    def test_remaining_units_floored_at_zero(self) -> None:
        sub = self._make_sub(plan="starter-5k", units_consumed=BILLING_TIER_5K_UNITS)
        assert sub.remaining_units == 0

    def test_token_coverage_limit(self) -> None:
        sub = self._make_sub(plan="starter-5k")
        assert sub.token_coverage_limit == BILLING_TIER_5K_UNITS * TOKENS_PER_UNIT

    def test_remaining_token_coverage(self) -> None:
        sub = self._make_sub(plan="starter-5k", units_consumed=1)
        expected = (BILLING_TIER_5K_UNITS - 1) * TOKENS_PER_UNIT
        assert sub.remaining_token_coverage == expected

    def test_is_active_true_when_active_and_units_remain_and_in_period(self) -> None:
        sub = self._make_sub(status="active", units_consumed=0)
        assert sub.is_active is True

    def test_is_active_false_when_cancelled(self) -> None:
        sub = self._make_sub(status="cancelled")
        assert sub.is_active is False

    def test_is_active_false_when_units_exhausted(self) -> None:
        sub = self._make_sub(status="active", units_consumed=BILLING_TIER_5K_UNITS)
        assert sub.is_active is False

    def test_is_active_false_when_period_expired(self) -> None:
        """
        Units do not expire in IronClaw. is_active is gated on status and
        remaining units only. A subscription with status=active and remaining
        units is active regardless of period_end. is_period_active reflects
        the date window; is_active reflects consumption eligibility.
        """
        now = datetime.now(UTC)
        sub = BillingSubscription(
            subscription_id="s",
            customer_id="c",
            plan="starter-5k",
            status="active",
            created_at=now - timedelta(days=40),
            current_period_start=now - timedelta(days=40),
            current_period_end=now - timedelta(days=1),
            units_consumed=0,
        )
        assert sub.is_period_active is False
        assert sub.is_active is True

    def test_negative_units_consumed_raises(self) -> None:
        with pytest.raises(ValueError, match="units_consumed cannot be negative"):
            BillingSubscription(
                subscription_id="s",
                customer_id="c",
                plan="starter-5k",
                status="active",
                created_at=datetime.now(UTC),
                current_period_start=datetime.now(UTC),
                current_period_end=datetime.now(UTC) + timedelta(days=1),
                units_consumed=-1,
            )


# ---------------------------------------------------------------------------
# _reset_billing_registry_for_testing — singleton reset
# ---------------------------------------------------------------------------


class TestResetBillingRegistryForTesting:
    def test_reset_produces_new_instance(self) -> None:
        first = get_billing_registry()
        _reset_billing_registry_for_testing()
        second = get_billing_registry()
        assert first is not second

    def test_reset_clears_state(self) -> None:
        _reset_billing_registry_for_testing()
        reg = get_billing_registry()
        assert reg.list_customers() == []

    def test_double_reset_is_safe(self) -> None:
        _reset_billing_registry_for_testing()
        _reset_billing_registry_for_testing()
        reg = get_billing_registry()
        assert reg is not None

    def teardown_method(self) -> None:
        _reset_billing_registry_for_testing()
