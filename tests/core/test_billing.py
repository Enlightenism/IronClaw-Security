from __future__ import annotations

import os

import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from datetime import UTC, datetime, timedelta

from app.core.billing import (
    PLAN_DEFINITIONS,
    TOKENS_PER_UNIT,
    BillingCustomer,
    BillingRegistry,
    BillingSubscription,
    BillingUsageError,
    units_required_for_tokens,
)
from app.persistencebootstrap import InMemoryPersistenceStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store() -> InMemoryPersistenceStore:
    return InMemoryPersistenceStore()


def _make_registry() -> BillingRegistry:
    return BillingRegistry(store=_make_store())


def _future(days: int = 30) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


def _past(days: int = 1) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


# ---------------------------------------------------------------------------
# Per-test fixture: isolated registry with fresh in-memory store
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> BillingRegistry:
    return _make_registry()


@pytest.fixture()
def customer(registry: BillingRegistry) -> BillingCustomer:
    return registry.create_customer(
        email="alice@ironclaw.test",
        display_name="Alice",
        plan="starter-5k",
    )


@pytest.fixture()
def active_sub(registry: BillingRegistry, customer: BillingCustomer) -> BillingSubscription:
    return registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )


# ---------------------------------------------------------------------------
# units_required_for_tokens
# ---------------------------------------------------------------------------


def test_units_required_one_token_costs_one_unit() -> None:
    assert units_required_for_tokens(1) == 1


def test_units_required_exact_chunk_boundary_costs_one_unit() -> None:
    assert units_required_for_tokens(TOKENS_PER_UNIT) == 1


def test_units_required_one_over_boundary_costs_two_units() -> None:
    assert units_required_for_tokens(TOKENS_PER_UNIT + 1) == 2


def test_units_required_two_full_chunks_costs_two_units() -> None:
    assert units_required_for_tokens(TOKENS_PER_UNIT * 2) == 2


def test_units_required_two_chunks_plus_one_costs_three_units() -> None:
    assert units_required_for_tokens(TOKENS_PER_UNIT * 2 + 1) == 3


def test_units_required_zero_returns_zero() -> None:
    assert units_required_for_tokens(0) == 0


def test_units_required_negative_returns_zero() -> None:
    assert units_required_for_tokens(-1) == 0


# ---------------------------------------------------------------------------
# BillingCustomer.__post_init__ validation
# ---------------------------------------------------------------------------


def test_billing_customer_rejects_empty_email() -> None:
    with pytest.raises(ValueError, match="Invalid email"):
        BillingCustomer(
            customer_id="cus_test",
            email="",
            display_name="Test",
            plan="starter-5k",
        )


def test_billing_customer_rejects_email_without_at_sign() -> None:
    with pytest.raises(ValueError, match="Invalid email"):
        BillingCustomer(
            customer_id="cus_test",
            email="notanemail",
            display_name="Test",
            plan="starter-5k",
        )


def test_billing_customer_rejects_unknown_plan() -> None:
    with pytest.raises(ValueError, match="Unknown plan code"):
        BillingCustomer(
            customer_id="cus_test",
            email="test@ironclaw.test",
            display_name="Test",
            plan="nonexistent-plan",  # type: ignore[arg-type]
        )


def test_billing_customer_accepts_valid_email_and_plan() -> None:
    c = BillingCustomer(
        customer_id="cus_test",
        email="valid@ironclaw.test",
        display_name="Valid",
        plan="starter-5k",
    )
    assert c.email == "valid@ironclaw.test"
    assert c.plan == "starter-5k"


def test_billing_customer_all_three_plan_codes_are_valid() -> None:
    for plan_code in PLAN_DEFINITIONS:
        c = BillingCustomer(
            customer_id=f"cus_{plan_code}",
            email="test@ironclaw.test",
            display_name="Test",
            plan=plan_code,
        )
        assert c.plan == plan_code


# ---------------------------------------------------------------------------
# BillingSubscription.__post_init__ and is_active / is_period_active
# ---------------------------------------------------------------------------


def test_billing_subscription_rejects_unknown_plan() -> None:
    with pytest.raises(ValueError, match="Unknown plan code"):
        BillingSubscription(
            subscription_id="sub_test",
            customer_id="cus_test",
            plan="bad-plan",  # type: ignore[arg-type]
            status="active",
        )


def test_billing_subscription_rejects_negative_units_consumed() -> None:
    with pytest.raises(ValueError, match="units_consumed cannot be negative"):
        BillingSubscription(
            subscription_id="sub_test",
            customer_id="cus_test",
            plan="starter-5k",
            status="active",
            units_consumed=-1,
        )


def test_billing_subscription_is_active_true_when_period_is_future_and_status_active() -> None:
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="starter-5k",
        status="active",
        current_period_start=datetime.now(UTC) - timedelta(hours=1),
        current_period_end=_future(30),
        units_consumed=0,
    )
    assert sub.is_active is True
    assert sub.is_period_active is True


def test_billing_subscription_is_active_false_when_period_expired() -> None:
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="starter-5k",
        status="active",
        current_period_start=_past(60),
        current_period_end=_past(1),
        units_consumed=0,
    )
    assert sub.is_period_active is False
    assert sub.is_active is False


def test_billing_subscription_is_active_false_when_status_cancelled() -> None:
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="starter-5k",
        status="cancelled",
        current_period_start=datetime.now(UTC) - timedelta(hours=1),
        current_period_end=_future(30),
        units_consumed=0,
    )
    assert sub.is_active is False


def test_billing_subscription_is_active_false_when_units_exhausted() -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="starter-5k",
        status="active",
        current_period_start=datetime.now(UTC) - timedelta(hours=1),
        current_period_end=_future(30),
        units_consumed=plan_def["unit_limit"],
    )
    assert sub.remaining_units == 0
    assert sub.is_active is False


def test_billing_subscription_remaining_units_never_goes_negative() -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="starter-5k",
        status="active",
        units_consumed=plan_def["unit_limit"] + 100,
    )
    assert sub.remaining_units == 0


def test_billing_subscription_token_coverage_limit_equals_units_times_tokens_per_unit() -> None:
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="starter-5k",
        status="active",
    )
    assert sub.token_coverage_limit == sub.unit_limit * TOKENS_PER_UNIT


# ---------------------------------------------------------------------------
# BillingRegistry.create_customer
# ---------------------------------------------------------------------------


def test_create_customer_returns_customer_with_correct_fields(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="bob@ironclaw.test",
        display_name="Bob",
        plan="team-25k",
    )
    assert c.customer_id.startswith("cus_")
    assert c.email == "bob@ironclaw.test"
    assert c.display_name == "Bob"
    assert c.plan == "team-25k"
    assert c.active is True


def test_create_customer_normalizes_email_to_lowercase(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="BOB@IRONCLAW.TEST",
        display_name="Bob",
        plan="starter-5k",
    )
    assert c.email == "bob@ironclaw.test"


def test_create_customer_is_retrievable_by_id(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="carol@ironclaw.test",
        display_name="Carol",
        plan="starter-5k",
    )
    fetched = registry.get_customer(c.customer_id)
    assert fetched is not None
    assert fetched.customer_id == c.customer_id


def test_create_customer_rejects_invalid_plan(registry: BillingRegistry) -> None:
    with pytest.raises(ValueError, match="Unknown plan code"):
        registry.create_customer(
            email="test@ironclaw.test",
            display_name="Test",
            plan="bad-plan",
        )


def test_create_customer_appears_in_list_customers(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="dan@ironclaw.test",
        display_name="Dan",
        plan="starter-5k",
    )
    ids = [x.customer_id for x in registry.list_customers()]
    assert c.customer_id in ids


# ---------------------------------------------------------------------------
# create_subscription with period_end
# ---------------------------------------------------------------------------


def test_create_subscription_sets_period_end_correctly(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    end = _future(30)
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
        period_end=end,
    )
    assert sub.subscription_id.startswith("sub_")
    assert sub.current_period_end == end
    assert sub.status == "active"
    assert sub.plan == "starter-5k"
    assert sub.units_consumed == 0


def test_create_subscription_raises_for_unknown_customer(registry: BillingRegistry) -> None:
    with pytest.raises(KeyError, match="Unknown customer_id"):
        registry.create_subscription(
            customer_id="cus_does_not_exist",
            plan="starter-5k",
            period_end=_future(30),
        )


def test_create_subscription_is_active_when_period_is_future(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    assert sub.is_active is True


def test_create_subscription_not_active_when_period_already_expired(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_past(1),
    )
    assert sub.is_active is False


def test_create_subscription_appears_in_list_subscriptions(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        period_end=_future(30),
    )
    ids = [s.subscription_id for s in registry.list_subscriptions()]
    assert sub.subscription_id in ids


# ---------------------------------------------------------------------------
# record_usage raising BillingUsageError with structured fields
# ---------------------------------------------------------------------------


def test_record_usage_increments_units_consumed(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    sub = registry.record_usage(customer_id=customer.customer_id, units=10)
    assert sub.units_consumed == 10


def test_record_usage_raises_billing_usage_error_when_limit_exceeded(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    with pytest.raises(BillingUsageError):
        registry.record_usage(
            customer_id=customer.customer_id,
            units=plan_def["unit_limit"] + 1,
        )


def test_record_usage_error_customer_id_is_correct(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    with pytest.raises(BillingUsageError) as exc_info:
        registry.record_usage(
            customer_id=customer.customer_id,
            units=plan_def["unit_limit"] + 1,
        )
    assert exc_info.value.customer_id == customer.customer_id


def test_record_usage_error_subscription_id_is_correct(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    with pytest.raises(BillingUsageError) as exc_info:
        registry.record_usage(
            customer_id=customer.customer_id,
            units=plan_def["unit_limit"] + 1,
        )
    assert exc_info.value.subscription_id == active_sub.subscription_id


def test_record_usage_error_units_requested_is_correct(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    over_limit = plan_def["unit_limit"] + 1
    with pytest.raises(BillingUsageError) as exc_info:
        registry.record_usage(customer_id=customer.customer_id, units=over_limit)
    assert exc_info.value.units_requested == over_limit


def test_record_usage_error_units_consumed_is_current_balance(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.record_usage(customer_id=customer.customer_id, units=100)
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    with pytest.raises(BillingUsageError) as exc_info:
        registry.record_usage(
            customer_id=customer.customer_id,
            units=plan_def["unit_limit"],
        )
    assert exc_info.value.units_consumed == 100


def test_record_usage_error_unit_limit_is_plan_limit(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    with pytest.raises(BillingUsageError) as exc_info:
        registry.record_usage(
            customer_id=customer.customer_id,
            units=plan_def["unit_limit"] + 1,
        )
    assert exc_info.value.unit_limit == plan_def["unit_limit"]


def test_record_usage_raises_key_error_when_no_active_subscription(
    registry: BillingRegistry,
) -> None:
    c = registry.create_customer(
        email="nosubscriber@ironclaw.test",
        display_name="No Sub",
        plan="starter-5k",
    )
    with pytest.raises(KeyError, match="No active subscription"):
        registry.record_usage(customer_id=c.customer_id, units=1)


def test_record_usage_raises_value_error_for_zero_units(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    with pytest.raises(ValueError, match="units must be positive"):
        registry.record_usage(customer_id=customer.customer_id, units=0)


def test_record_usage_raises_value_error_for_negative_units(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    with pytest.raises(ValueError, match="units must be positive"):
        registry.record_usage(customer_id=customer.customer_id, units=-5)


# ---------------------------------------------------------------------------
# record_token_usage
# ---------------------------------------------------------------------------


def test_record_token_usage_returns_subscription_and_required_units(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    sub, used = registry.record_token_usage(
        customer_id=customer.customer_id,
        token_count=TOKENS_PER_UNIT,
    )
    assert used == 1
    assert sub.units_consumed == 1


def test_record_token_usage_ceiling_division_at_boundary_plus_one(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    sub, used = registry.record_token_usage(
        customer_id=customer.customer_id,
        token_count=TOKENS_PER_UNIT + 1,
    )
    assert used == 2
    assert sub.units_consumed == 2


def test_record_token_usage_zero_tokens_raises_value_error(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    with pytest.raises(ValueError, match="units must be positive"):
        registry.record_token_usage(customer_id=customer.customer_id, token_count=0)


# ---------------------------------------------------------------------------
# can_consume
# ---------------------------------------------------------------------------


def test_can_consume_true_when_units_available(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    assert registry.can_consume(customer_id=customer.customer_id, units=1) is True


def test_can_consume_false_when_units_would_exceed_limit(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    assert (
        registry.can_consume(
            customer_id=customer.customer_id,
            units=plan_def["unit_limit"] + 1,
        )
        is False
    )


def test_can_consume_false_when_no_active_subscription(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="nosub@ironclaw.test",
        display_name="No Sub",
        plan="starter-5k",
    )
    assert registry.can_consume(customer_id=c.customer_id, units=1) is False


def test_can_consume_false_for_zero_units(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    assert registry.can_consume(customer_id=customer.customer_id, units=0) is False


def test_can_consume_false_for_negative_units(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    assert registry.can_consume(customer_id=customer.customer_id, units=-1) is False


def test_can_consume_exact_remaining_units_returns_true(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    assert (
        registry.can_consume(
            customer_id=customer.customer_id,
            units=plan_def["unit_limit"],
        )
        is True
    )


# ---------------------------------------------------------------------------
# can_consume_tokens
# ---------------------------------------------------------------------------


def test_can_consume_tokens_true_when_tokens_fit_within_limit(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    assert (
        registry.can_consume_tokens(
            customer_id=customer.customer_id,
            token_count=TOKENS_PER_UNIT,
        )
        is True
    )


def test_can_consume_tokens_false_when_tokens_would_exceed_limit(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    over_tokens = (plan_def["unit_limit"] + 1) * TOKENS_PER_UNIT
    assert (
        registry.can_consume_tokens(
            customer_id=customer.customer_id,
            token_count=over_tokens,
        )
        is False
    )


def test_can_consume_tokens_false_when_no_active_subscription(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="nosub2@ironclaw.test",
        display_name="No Sub 2",
        plan="starter-5k",
    )
    assert registry.can_consume_tokens(customer_id=c.customer_id, token_count=TOKENS_PER_UNIT) is False


def test_can_consume_tokens_false_for_zero_tokens(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    assert registry.can_consume_tokens(customer_id=customer.customer_id, token_count=0) is False


# ---------------------------------------------------------------------------
# upgrade_plan full flow
# ---------------------------------------------------------------------------


def test_upgrade_plan_returns_customer_and_new_subscription(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    upgraded_customer, new_sub = registry.upgrade_plan(
        customer_id=customer.customer_id,
        new_plan="team-25k",
    )
    assert upgraded_customer.plan == "team-25k"
    assert new_sub.plan == "team-25k"
    assert new_sub.subscription_id != active_sub.subscription_id


def test_upgrade_plan_old_subscription_status_is_upgraded(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.upgrade_plan(
        customer_id=customer.customer_id,
        new_plan="team-25k",
    )
    old = registry._subscriptions.get(active_sub.subscription_id)
    assert old is not None
    assert old.status == "upgraded"


def test_upgrade_plan_new_subscription_is_active(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    _, new_sub = registry.upgrade_plan(
        customer_id=customer.customer_id,
        new_plan="team-25k",
    )
    # Retrieve via the registry method — must find the new active sub
    fetched = registry.get_active_subscription_for_customer(customer.customer_id)
    assert fetched is not None
    assert fetched.subscription_id == new_sub.subscription_id


def test_upgrade_plan_new_subscription_has_fresh_period(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    _, new_sub = registry.upgrade_plan(
        customer_id=customer.customer_id,
        new_plan="team-25k",
    )
    assert new_sub.is_period_active is True
    assert new_sub.units_consumed == 0


def test_upgrade_plan_raises_for_unknown_customer(registry: BillingRegistry) -> None:
    with pytest.raises(KeyError, match="Unknown customer_id"):
        registry.upgrade_plan(
            customer_id="cus_does_not_exist",
            new_plan="team-25k",
        )


def test_upgrade_plan_raises_for_unknown_plan(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    with pytest.raises(ValueError, match="Unknown plan code"):
        registry.upgrade_plan(
            customer_id=customer.customer_id,
            new_plan="bad-plan",
        )


def test_upgrade_plan_customer_plan_field_updated(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.upgrade_plan(
        customer_id=customer.customer_id,
        new_plan="enterprise-60k",
    )
    fetched = registry.get_customer(customer.customer_id)
    assert fetched is not None
    assert fetched.plan == "enterprise-60k"


# ---------------------------------------------------------------------------
# reset_period
# ---------------------------------------------------------------------------


def test_reset_period_zeros_units_consumed_and_updates_period_end(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.record_usage(customer_id=customer.customer_id, units=50)
    new_end = _future(60)
    sub = registry.reset_period(
        subscription_id=active_sub.subscription_id,
        new_period_end=new_end,
    )
    assert sub.units_consumed == 0
    assert sub.current_period_end == new_end
    assert sub.is_period_active is True


def test_reset_period_raises_for_unknown_subscription(registry: BillingRegistry) -> None:
    with pytest.raises(KeyError, match="Unknown subscription_id"):
        registry.reset_period(
            subscription_id="sub_does_not_exist",
            new_period_end=_future(30),
        )


def test_reset_period_updates_current_period_start_to_now(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    before = datetime.now(UTC)
    sub = registry.reset_period(
        subscription_id=active_sub.subscription_id,
        new_period_end=_future(30),
    )
    after = datetime.now(UTC)
    assert before <= sub.current_period_start <= after


# ---------------------------------------------------------------------------
# deactivate_customer cancelling all active subs
# ---------------------------------------------------------------------------


def test_deactivate_customer_sets_active_false(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.deactivate_customer(customer.customer_id)
    fetched = registry.get_customer(customer.customer_id)
    assert fetched is not None
    assert fetched.active is False


def test_deactivate_customer_cancels_active_subscription(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.deactivate_customer(customer.customer_id)
    sub = registry._subscriptions.get(active_sub.subscription_id)
    assert sub is not None
    assert sub.status == "cancelled"


def test_deactivate_customer_no_active_subscription_after_deactivation(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.deactivate_customer(customer.customer_id)
    result = registry.get_active_subscription_for_customer(customer.customer_id)
    assert result is None


def test_deactivate_customer_cancels_all_multiple_active_subs(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    sub1 = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    sub2 = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="team-25k",
        status="active",
        period_end=_future(30),
    )
    registry.deactivate_customer(customer.customer_id)
    assert registry._subscriptions[sub1.subscription_id].status == "cancelled"
    assert registry._subscriptions[sub2.subscription_id].status == "cancelled"


def test_deactivate_customer_raises_for_unknown_customer_id(
    registry: BillingRegistry,
) -> None:
    with pytest.raises(KeyError, match="Unknown customer_id"):
        registry.deactivate_customer("cus_does_not_exist")


# ---------------------------------------------------------------------------
# get_billing_registry lazy-init singleton isolation
# ---------------------------------------------------------------------------


def test_get_billing_registry_returns_same_instance_on_repeated_calls() -> None:
    import app.core.billing as _billing_module

    _billing_module._billing_registry = None
    from app.core.billing import get_billing_registry

    r1 = get_billing_registry()
    r2 = get_billing_registry()
    assert r1 is r2
    _billing_module._billing_registry = None


def test_get_billing_registry_returns_billing_registry_instance() -> None:
    import app.core.billing as _billing_module

    _billing_module._billing_registry = None
    from app.core.billing import get_billing_registry

    r = get_billing_registry()
    assert isinstance(r, BillingRegistry)
    _billing_module._billing_registry = None


def test_get_billing_registry_isolation_after_reset() -> None:
    import app.core.billing as _billing_module

    _billing_module._billing_registry = None
    from app.core.billing import get_billing_registry

    r1 = get_billing_registry()
    _billing_module._billing_registry = None
    r2 = get_billing_registry()
    assert r1 is not r2
    _billing_module._billing_registry = None


# ---------------------------------------------------------------------------
# _customer_sub_index O(1) lookup correctness
# ---------------------------------------------------------------------------


def test_customer_sub_index_populated_on_create_subscription(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        period_end=_future(30),
    )
    assert sub.subscription_id in registry._customer_sub_index[customer.customer_id]


def test_customer_sub_index_contains_all_subscriptions_for_customer(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    sub1 = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        period_end=_future(10),
    )
    sub2 = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="team-25k",
        period_end=_future(20),
    )
    index = registry._customer_sub_index[customer.customer_id]
    assert sub1.subscription_id in index
    assert sub2.subscription_id in index


def test_customer_sub_index_does_not_mix_customers(
    registry: BillingRegistry,
) -> None:
    c1 = registry.create_customer(
        email="x1@ironclaw.test",
        display_name="X1",
        plan="starter-5k",
    )
    c2 = registry.create_customer(
        email="x2@ironclaw.test",
        display_name="X2",
        plan="starter-5k",
    )
    s1 = registry.create_subscription(
        customer_id=c1.customer_id,
        plan="starter-5k",
        period_end=_future(30),
    )
    s2 = registry.create_subscription(
        customer_id=c2.customer_id,
        plan="starter-5k",
        period_end=_future(30),
    )
    assert s1.subscription_id not in registry._customer_sub_index.get(c2.customer_id, [])
    assert s2.subscription_id not in registry._customer_sub_index.get(c1.customer_id, [])


def test_customer_sub_index_unknown_customer_returns_empty(
    registry: BillingRegistry,
) -> None:
    assert registry._customer_sub_index.get("cus_unknown", []) == []
