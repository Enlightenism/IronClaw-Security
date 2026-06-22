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
from types import SimpleNamespace

from app.core.billing import (
    PLAN_DEFINITIONS,
    TOKENS_PER_UNIT,
    UNIT_PACKAGE_CATALOG,
    BillingCustomer,
    BillingRegistry,
    BillingSubscription,
    BillingUsageError,
    resolve_billing_owner,
    units_required_for_tokens,
)
from app.persistencebootstrap import InMemoryPersistenceStore


def _make_store() -> InMemoryPersistenceStore:
    return InMemoryPersistenceStore()


def _make_registry() -> BillingRegistry:
    return BillingRegistry(store=_make_store())


def _future(days: int = 30) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


def _past(days: int = 1) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


# ---------------------------------------------------------------------------
# Fixtures
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
# UNIT_PACKAGE_CATALOG
# ---------------------------------------------------------------------------


def test_unit_package_catalog_has_three_entries() -> None:
    assert len(UNIT_PACKAGE_CATALOG) == 3


def test_unit_package_catalog_codes_match_plan_definitions() -> None:
    catalog_codes = {entry["code"] for entry in UNIT_PACKAGE_CATALOG}
    plan_codes = set(PLAN_DEFINITIONS.keys())
    assert catalog_codes == plan_codes


def test_unit_package_catalog_units_match_plan_definitions() -> None:
    for entry in UNIT_PACKAGE_CATALOG:
        plan = PLAN_DEFINITIONS[entry["code"]]
        assert entry["units"] == plan["unit_limit"], f"UNIT_PACKAGE_CATALOG units mismatch for {entry['code']!r}"


def test_unit_package_catalog_price_usd_matches_plan_definitions() -> None:
    for entry in UNIT_PACKAGE_CATALOG:
        plan = PLAN_DEFINITIONS[entry["code"]]
        assert entry["price_usd"] == plan["price_usd"], f"UNIT_PACKAGE_CATALOG price_usd mismatch for {entry['code']!r}"


def test_unit_package_catalog_tokens_per_unit_matches_constant() -> None:
    for entry in UNIT_PACKAGE_CATALOG:
        assert entry["tokens_per_unit"] == TOKENS_PER_UNIT


def test_unit_package_catalog_required_keys_present() -> None:
    required = {"code", "name", "units", "price_usd", "tokens_per_unit"}
    for entry in UNIT_PACKAGE_CATALOG:
        assert required.issubset(entry.keys()), f"Missing keys in catalog entry {entry}"


def test_unit_package_catalog_starter_is_first_entry() -> None:
    assert UNIT_PACKAGE_CATALOG[0]["code"] == "starter-5k"


def test_unit_package_catalog_enterprise_is_last_entry() -> None:
    assert UNIT_PACKAGE_CATALOG[-1]["code"] == "enterprise-60k"


def test_unit_package_catalog_units_are_positive() -> None:
    for entry in UNIT_PACKAGE_CATALOG:
        assert entry["units"] > 0, f"units must be positive for {entry['code']!r}"


def test_unit_package_catalog_price_usd_are_positive() -> None:
    for entry in UNIT_PACKAGE_CATALOG:
        assert entry["price_usd"] > 0, f"price_usd must be positive for {entry['code']!r}"


# ---------------------------------------------------------------------------
# resolve_billing_owner
# ---------------------------------------------------------------------------


def test_resolve_billing_owner_returns_email_for_personal_key() -> None:
    ctx = SimpleNamespace(key_type="personal", org_id=None)
    result = resolve_billing_owner(ctx, "User@IronClaw.TEST")
    assert result == "user@ironclaw.test"


def test_resolve_billing_owner_returns_org_key_for_org_key_type() -> None:
    ctx = SimpleNamespace(key_type="org", org_id="acme")
    result = resolve_billing_owner(ctx, "user@ironclaw.test")
    assert result == "ic_org_acme"


def test_resolve_billing_owner_org_key_format_is_ic_org_prefix() -> None:
    ctx = SimpleNamespace(key_type="org", org_id="xyz123")
    result = resolve_billing_owner(ctx, "user@ironclaw.test")
    assert result.startswith("ic_org_")


def test_resolve_billing_owner_falls_back_to_email_when_org_id_is_none() -> None:
    ctx = SimpleNamespace(key_type="org", org_id=None)
    result = resolve_billing_owner(ctx, "user@ironclaw.test")
    assert result == "user@ironclaw.test"


def test_resolve_billing_owner_falls_back_to_email_when_org_id_is_empty_string() -> None:
    ctx = SimpleNamespace(key_type="org", org_id="")
    result = resolve_billing_owner(ctx, "user@ironclaw.test")
    assert result == "user@ironclaw.test"


def test_resolve_billing_owner_session_auth_returns_email() -> None:
    ctx = SimpleNamespace(key_type="session", org_id=None)
    result = resolve_billing_owner(ctx, "User@IronClaw.TEST")
    assert result == "user@ironclaw.test"


def test_resolve_billing_owner_no_key_type_attr_returns_email() -> None:
    ctx = SimpleNamespace()
    result = resolve_billing_owner(ctx, "User@IronClaw.TEST")
    assert result == "user@ironclaw.test"


def test_resolve_billing_owner_strips_and_lowercases_email() -> None:
    ctx = SimpleNamespace(key_type="personal", org_id=None)
    result = resolve_billing_owner(ctx, "  ADMIN@IRONCLAW.TEST  ")
    assert result == "admin@ironclaw.test"


def test_resolve_billing_owner_different_org_ids_produce_different_keys() -> None:
    ctx_a = SimpleNamespace(key_type="org", org_id="org_a")
    ctx_b = SimpleNamespace(key_type="org", org_id="org_b")
    assert resolve_billing_owner(ctx_a, "xx.com") != resolve_billing_owner(ctx_b, "xx.com")


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
# BillingUsageError
# ---------------------------------------------------------------------------


def test_billing_usage_error_message_is_accessible() -> None:
    err = BillingUsageError(
        "limit exceeded",
        customer_id="cus_test",
        subscription_id="sub_test",
        units_requested=100,
        units_consumed=4900,
        unit_limit=5000,
    )
    assert str(err) == "limit exceeded"


def test_billing_usage_error_customer_id_attribute() -> None:
    err = BillingUsageError(
        "limit exceeded",
        customer_id="cus_abc",
        subscription_id="sub_xyz",
        units_requested=10,
        units_consumed=5000,
        unit_limit=5000,
    )
    assert err.customer_id == "cus_abc"


def test_billing_usage_error_subscription_id_attribute() -> None:
    err = BillingUsageError(
        "limit exceeded",
        customer_id="cus_abc",
        subscription_id="sub_xyz",
        units_requested=10,
        units_consumed=5000,
        unit_limit=5000,
    )
    assert err.subscription_id == "sub_xyz"


def test_billing_usage_error_units_requested_attribute() -> None:
    err = BillingUsageError(
        "limit exceeded",
        customer_id="cus_abc",
        subscription_id="sub_xyz",
        units_requested=99,
        units_consumed=4950,
        unit_limit=5000,
    )
    assert err.units_requested == 99


def test_billing_usage_error_units_consumed_attribute() -> None:
    err = BillingUsageError(
        "limit exceeded",
        customer_id="cus_abc",
        subscription_id="sub_xyz",
        units_requested=99,
        units_consumed=4950,
        unit_limit=5000,
    )
    assert err.units_consumed == 4950


def test_billing_usage_error_unit_limit_attribute() -> None:
    err = BillingUsageError(
        "limit exceeded",
        customer_id="cus_abc",
        subscription_id="sub_xyz",
        units_requested=99,
        units_consumed=4950,
        unit_limit=5000,
    )
    assert err.unit_limit == 5000


def test_billing_usage_error_is_exception_subclass() -> None:
    err = BillingUsageError(
        "limit exceeded",
        customer_id="cus_abc",
        subscription_id="sub_xyz",
        units_requested=1,
        units_consumed=5000,
        unit_limit=5000,
    )
    assert isinstance(err, Exception)


# ---------------------------------------------------------------------------
# BillingCustomer validation
# ---------------------------------------------------------------------------


def test_billing_customer_rejects_empty_email() -> None:
    with pytest.raises(ValueError, match="Invalid email"):
        BillingCustomer(customer_id="cus_test", email="", display_name="Test", plan="starter-5k")


def test_billing_customer_rejects_email_without_at_sign() -> None:
    with pytest.raises(ValueError, match="Invalid email"):
        BillingCustomer(customer_id="cus_test", email="notanemail", display_name="Test", plan="starter-5k")


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
# BillingSubscription properties
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
    """
    is_active is NOT gated on period_end — units do not expire in IronClaw.
    A sub with status=active and remaining units is active even if period_end is past.
    is_period_active reflects the date window; is_active reflects consumption eligibility.
    """
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
    assert sub.is_active is True


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


def test_billing_subscription_remaining_units_partial_consumption() -> None:
    plan_def = PLAN_DEFINITIONS["starter-5k"]
    consumed = plan_def["unit_limit"] // 2
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="starter-5k",
        status="active",
        units_consumed=consumed,
    )
    assert sub.remaining_units == plan_def["unit_limit"] - consumed


def test_billing_subscription_token_coverage_limit_team_plan() -> None:
    plan_def = PLAN_DEFINITIONS["team-25k"]
    sub = BillingSubscription(
        subscription_id="sub_test",
        customer_id="cus_test",
        plan="team-25k",
        status="active",
    )
    assert sub.token_coverage_limit == plan_def["unit_limit"] * TOKENS_PER_UNIT


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
# BillingRegistry.create_subscription
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
    """
    Units do not expire — is_active is gated on status and remaining units only.
    A subscription created with an expired period_end is still active if status=active
    and units remain. is_period_active correctly reflects the date window.
    """
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_past(1),
    )
    assert sub.is_period_active is False
    assert sub.is_active is True


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
# BillingRegistry.record_usage
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
# BillingRegistry.record_token_usage
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
