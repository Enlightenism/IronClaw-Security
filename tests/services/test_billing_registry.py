from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.core.billing import (
    BillingRegistry,
    BillingUsageError,
    _reset_billing_registry_for_testing,
    resolve_billing_owner,
)
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.persistencebootstrap import build_store

# ---------------------------------------------------------------------------
# Stub install key registry — isolates BillingRegistry from Supabase
# ---------------------------------------------------------------------------


class _StubInstallKeyRegistry:
    """Minimal stub that matches the paid-entitlement install-key API."""

    def __init__(self) -> None:
        self._keys: dict[str, Any] = {}
        self.calls: list[dict[str, Any]] = []

    def generate_for_paid_customer(
        self,
        owner_key: str,
        subscription_id: str,
        program: str,
        *,
        org_id: str | None = None,
        customer_id: str | None = None,
        payment_status: str | None = "paid",
        entitlements_status: str | None = "active",
        issued_after_payment: bool = True,
        purchase_reference: str | None = None,
        checkout_session_id: str | None = None,
        label: str = "",
        metadata: dict[str, Any] | None = None,
        secure_record_persistor: Any | None = None,
    ) -> Any:
        record = MagicMock()
        record.key_id = f"ik_stub_{program}_{len(self.calls)}"
        record.owner_key = owner_key
        record.subscription_id = subscription_id
        record.program = program
        record.active = True
        self.calls.append(
            {
                "owner_key": owner_key,
                "subscription_id": subscription_id,
                "program": program,
                "label": label,
                "customer_id": customer_id,
                "payment_status": payment_status,
                "entitlements_status": entitlements_status,
                "issued_after_payment": issued_after_payment,
                "purchase_reference": purchase_reference,
                "checkout_session_id": checkout_session_id,
                "metadata": metadata or {},
            }
        )
        return record

    def generate_install_key(
        self,
        owner_key: str,
        subscription_id: str,
        program: str,
        *,
        label: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        return self.generate_for_paid_customer(
            owner_key,
            subscription_id,
            program,
            label=label,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> BillingRegistry:
    """Isolated BillingRegistry with in-memory store and stub install key registry."""
    store = build_store()
    stub_keys = _StubInstallKeyRegistry()
    return BillingRegistry(store=store, install_key_registry=stub_keys)


@pytest.fixture()
def registry_with_active_customer(registry: BillingRegistry) -> tuple[BillingRegistry, str, str]:
    """Registry pre-seeded with one active customer and one active subscription."""
    customer = registry.create_customer(
        email="active@ironclaw.dev",
        display_name="Active User",
        plan="starter-5k",
    )
    subscription = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
    )
    return registry, customer.customer_id, subscription.subscription_id


# ---------------------------------------------------------------------------
# resolve_billing_owner — single source of truth for wallet routing
# ---------------------------------------------------------------------------


def test_resolve_billing_owner_returns_org_key_for_org_key_type() -> None:
    ctx = MagicMock()
    ctx.key_type = "org"
    ctx.org_id = "org-abc123"
    result = resolve_billing_owner(ctx, "user@example.com")
    assert result == "ic_org_org-abc123"


def test_resolve_billing_owner_returns_normalized_email_for_personal_key() -> None:
    ctx = MagicMock()
    ctx.key_type = "personal"
    ctx.org_id = None
    result = resolve_billing_owner(ctx, "User@Example.COM")
    assert result == "user@example.com"


def test_resolve_billing_owner_returns_email_when_key_type_is_missing() -> None:
    ctx = MagicMock(spec=[])  # no attributes
    result = resolve_billing_owner(ctx, "  Stripped@Example.COM  ")
    assert result == "stripped@example.com"


def test_resolve_billing_owner_returns_email_when_org_id_is_empty() -> None:
    ctx = MagicMock()
    ctx.key_type = "org"
    ctx.org_id = ""
    result = resolve_billing_owner(ctx, "user@example.com")
    assert result == "user@example.com"


def test_resolve_billing_owner_strips_and_lowercases_email() -> None:
    ctx = MagicMock()
    ctx.key_type = "session"
    ctx.org_id = None
    result = resolve_billing_owner(ctx, "  ADMIN@IRONCLAW.DEV  ")
    assert result == "admin@ironclaw.dev"


# ---------------------------------------------------------------------------
# has_active_subscription — core gate used by customerkeys billing guard
# ---------------------------------------------------------------------------


def test_has_active_subscription_returns_false_for_unknown_owner(registry: BillingRegistry) -> None:
    assert registry.has_active_subscription("nobody@unknown.dev") is False


def test_has_active_subscription_matches_org_key_from_customer_metadata(registry: BillingRegistry) -> None:
    customer = registry.create_customer(
        email="orguser@ironclaw.dev",
        display_name="Org User",
        plan="team-25k",
    )
    customer.metadata["org_id"] = "org-42"
    registry.create_subscription(
        customer_id=customer.customer_id,
        plan="team-25k",
        status="active",
    )
    assert registry.has_active_subscription("ic_org_org-42") is True
    assert registry.get_active_subscription_for_customer("ic_org_org-42") is not None


def test_has_active_subscription_returns_false_when_subscription_is_cancelled(
    registry: BillingRegistry,
) -> None:
    customer = registry.create_customer(
        email="cancelled@ironclaw.dev",
        display_name="Cancelled User",
        plan="starter-5k",
    )
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
    )
    registry.cancel_subscription(sub.subscription_id)
    assert registry.has_active_subscription("cancelled@ironclaw.dev") is False


def test_has_active_subscription_returns_false_when_units_exhausted(
    registry: BillingRegistry,
) -> None:
    customer = registry.create_customer(
        email="exhausted@ironclaw.dev",
        display_name="Exhausted User",
        plan="starter-5k",
    )
    registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
    )
    from app.core.billing import PLAN_DEFINITIONS

    unit_limit = PLAN_DEFINITIONS["starter-5k"]["unit_limit"]
    registry.record_usage(customer_id=customer.customer_id, units=unit_limit)
    assert registry.has_active_subscription("exhausted@ironclaw.dev") is False


def test_has_active_subscription_returns_true_when_active_with_units_remaining(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, _cid, _sid = registry_with_active_customer
    assert reg.has_active_subscription("active@ironclaw.dev") is True


def test_has_active_subscription_returns_false_when_customer_is_inactive(
    registry: BillingRegistry,
) -> None:
    customer = registry.create_customer(
        email="inactive@ironclaw.dev",
        display_name="Inactive User",
        plan="starter-5k",
    )
    registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
    )
    registry.deactivate_customer(customer.customer_id)
    assert registry.has_active_subscription("inactive@ironclaw.dev") is False


def test_has_active_subscription_is_case_insensitive_on_email(
    registry: BillingRegistry,
) -> None:
    customer = registry.create_customer(
        email="casematch@ironclaw.dev",
        display_name="Case Match User",
        plan="starter-5k",
    )
    registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
    )
    assert registry.has_active_subscription("CASEMATCH@IRONCLAW.DEV") is True


def test_has_active_subscription_ignores_upgraded_subscription(
    registry: BillingRegistry,
) -> None:
    customer = registry.create_customer(
        email="upgraded@ironclaw.dev",
        display_name="Upgraded User",
        plan="starter-5k",
    )
    registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
    )
    registry.upgrade_plan(customer_id=customer.customer_id, new_plan="team-25k")
    assert registry.has_active_subscription("upgraded@ironclaw.dev") is True


# ---------------------------------------------------------------------------
# can_consume
# ---------------------------------------------------------------------------


def test_can_consume_returns_false_when_no_active_subscription(registry: BillingRegistry) -> None:
    customer = registry.create_customer(
        email="noconsume@ironclaw.dev",
        display_name="No Consume",
        plan="starter-5k",
    )
    assert registry.can_consume(customer_id=customer.customer_id, units=1) is False


def test_can_consume_returns_true_within_limit(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, _ = registry_with_active_customer
    assert reg.can_consume(customer_id=cid, units=1) is True


def test_can_consume_returns_false_when_units_exceed_limit(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    from app.core.billing import PLAN_DEFINITIONS

    reg, cid, _ = registry_with_active_customer
    unit_limit = PLAN_DEFINITIONS["starter-5k"]["unit_limit"]
    assert reg.can_consume(customer_id=cid, units=unit_limit + 1) is False


def test_can_consume_returns_false_for_zero_units(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, _ = registry_with_active_customer
    assert reg.can_consume(customer_id=cid, units=0) is False


# ---------------------------------------------------------------------------
# record_usage
# ---------------------------------------------------------------------------


def test_record_usage_raises_billing_usage_error_when_units_exceed_limit(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    from app.core.billing import PLAN_DEFINITIONS

    reg, cid, _ = registry_with_active_customer
    unit_limit = PLAN_DEFINITIONS["starter-5k"]["unit_limit"]
    with pytest.raises(BillingUsageError) as exc_info:
        reg.record_usage(customer_id=cid, units=unit_limit + 1)
    err = exc_info.value
    assert err.customer_id == cid
    assert err.units_requested == unit_limit + 1
    assert err.unit_limit == unit_limit


def test_record_usage_raises_key_error_for_unknown_customer(registry: BillingRegistry) -> None:
    with pytest.raises(KeyError):
        registry.record_usage(customer_id="cus_nonexistent", units=1)


def test_record_usage_increments_units_consumed(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    sub = reg.get_active_subscription_for_customer(cid)
    assert sub is not None
    before = sub.units_consumed
    reg.record_usage(customer_id=cid, units=10)
    updated = reg.get_active_subscription_for_customer(cid)
    assert updated is not None
    assert updated.units_consumed == before + 10


def test_record_usage_raises_value_error_for_non_positive_units(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, _ = registry_with_active_customer
    with pytest.raises(ValueError):
        reg.record_usage(customer_id=cid, units=0)


# ---------------------------------------------------------------------------
# upgrade_plan
# ---------------------------------------------------------------------------


def test_upgrade_plan_cancels_old_subscription(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, old_sid = registry_with_active_customer
    reg.upgrade_plan(customer_id=cid, new_plan="team-25k")
    old_sub = reg._subscriptions.get(old_sid)
    assert old_sub is not None
    assert old_sub.status == "upgraded"


def test_upgrade_plan_creates_new_active_subscription(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, old_sid = registry_with_active_customer
    _, new_sub = reg.upgrade_plan(customer_id=cid, new_plan="team-25k")
    assert new_sub.status == "active"
    assert new_sub.plan == "team-25k"
    assert new_sub.subscription_id != old_sid


def test_upgrade_plan_updates_customer_plan(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, _ = registry_with_active_customer
    customer, _ = reg.upgrade_plan(customer_id=cid, new_plan="enterprise-60k")
    assert customer.plan == "enterprise-60k"


def test_upgrade_plan_raises_key_error_for_unknown_customer(registry: BillingRegistry) -> None:
    with pytest.raises(KeyError):
        registry.upgrade_plan(customer_id="cus_ghost", new_plan="team-25k")


def test_upgrade_plan_raises_value_error_for_invalid_plan(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, _ = registry_with_active_customer
    with pytest.raises(ValueError):
        reg.upgrade_plan(customer_id=cid, new_plan="invalid-plan-code")


# ---------------------------------------------------------------------------
# reset_period
# ---------------------------------------------------------------------------


def test_reset_period_zeroes_units_consumed(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    reg.record_usage(customer_id=cid, units=100)
    sub_before = reg._subscriptions.get(sid)
    assert sub_before is not None
    assert sub_before.units_consumed == 100

    new_end = datetime.now(UTC) + timedelta(days=30)
    updated = reg.reset_period(subscription_id=sid, new_period_end=new_end)
    assert updated.units_consumed == 0


def test_reset_period_updates_current_period_end(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    new_end = datetime.now(UTC) + timedelta(days=90)
    updated = reg.reset_period(subscription_id=sid, new_period_end=new_end)
    assert abs((updated.current_period_end - new_end).total_seconds()) < 1


def test_reset_period_updates_current_period_start(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    before_reset = datetime.now(UTC)
    new_end = before_reset + timedelta(days=30)
    updated = reg.reset_period(subscription_id=sid, new_period_end=new_end)
    assert updated.current_period_start >= before_reset


def test_reset_period_raises_key_error_for_unknown_subscription(
    registry: BillingRegistry,
) -> None:
    with pytest.raises(KeyError):
        registry.reset_period(
            subscription_id="sub_nonexistent",
            new_period_end=datetime.now(UTC) + timedelta(days=30),
        )


# ---------------------------------------------------------------------------
# provision_install_keys_on_purchase
# ---------------------------------------------------------------------------


def test_provision_install_keys_raises_value_error_when_no_active_subscription(
    registry: BillingRegistry,
) -> None:
    with pytest.raises(ValueError, match="no active subscription"):
        registry.provision_install_keys_on_purchase(
            customer_id="cus_none",
            subscription_id="sub_none",
            owner_key="nobody@ironclaw.dev",
        )


def test_has_active_subscription_requires_active_paid_subscription_state(
    registry: BillingRegistry,
) -> None:
    customer = registry.create_customer(
        email="pending@ironclaw.dev",
        display_name="Pending User",
        plan="starter-5k",
    )
    registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="pending",
    )
    assert registry.has_active_subscription("pending@ironclaw.dev") is False


def test_provision_install_keys_calls_each_supported_runtime_program(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    stub: _StubInstallKeyRegistry = reg._install_key_registry  # type: ignore[assignment]

    result = reg.provision_install_keys_on_purchase(
        customer_id=cid,
        subscription_id=sid,
        owner_key="active@ironclaw.dev",
    )

    expected_programs = tuple(InstallKeyFormatRegistry.list_programs())
    assert len(stub.calls) == len(expected_programs)
    assert set(result) == set(expected_programs)
    assert {call["program"] for call in stub.calls} == set(expected_programs)
    for call in stub.calls:
        assert call["owner_key"] == "active@ironclaw.dev"
        assert call["subscription_id"] == sid
        assert call["metadata"]["customer_id"] == cid
        assert call["metadata"]["provisioned_by"] == "billing"


def test_provision_install_keys_raises_before_paid_active_state_is_reached(
    registry: BillingRegistry,
) -> None:
    customer = registry.create_customer(
        email="notpaid@ironclaw.dev",
        display_name="Not Paid User",
        plan="starter-5k",
    )
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
    )
    registry.record_usage(customer_id=customer.customer_id, units=sub.unit_limit)
    stub: _StubInstallKeyRegistry = registry._install_key_registry  # type: ignore[assignment]

    with pytest.raises(ValueError, match="no active subscription"):
        registry.provision_install_keys_on_purchase(
            customer_id=customer.customer_id,
            subscription_id=sub.subscription_id,
            owner_key="notpaid@ironclaw.dev",
        )

    assert stub.calls == []


def test_provision_install_keys_passes_correct_owner_key(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    stub: _StubInstallKeyRegistry = reg._install_key_registry  # type: ignore[assignment]
    reg.provision_install_keys_on_purchase(
        customer_id=cid,
        subscription_id=sid,
        owner_key="active@ironclaw.dev",
    )
    for call in stub.calls:
        assert call["owner_key"] == "active@ironclaw.dev"
        assert call["subscription_id"] == sid


def test_provision_install_keys_passes_auto_provisioned_label(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    stub: _StubInstallKeyRegistry = reg._install_key_registry  # type: ignore[assignment]
    reg.provision_install_keys_on_purchase(
        customer_id=cid,
        subscription_id=sid,
        owner_key="active@ironclaw.dev",
    )
    for call in stub.calls:
        assert call["label"] == "auto-provisioned"


def test_provision_install_keys_embeds_customer_id_in_metadata(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, sid = registry_with_active_customer
    stub: _StubInstallKeyRegistry = reg._install_key_registry  # type: ignore[assignment]
    reg.provision_install_keys_on_purchase(
        customer_id=cid,
        subscription_id=sid,
        owner_key="active@ironclaw.dev",
    )
    for call in stub.calls:
        assert call["metadata"].get("customer_id") == cid
        assert call["metadata"].get("provisioned_by") == "billing"


# ---------------------------------------------------------------------------
# create_customer / get_customer / list_customers
# ---------------------------------------------------------------------------


def test_create_customer_returns_customer_with_correct_fields(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="new@ironclaw.dev",
        display_name="New User",
        plan="team-25k",
    )
    assert c.email == "new@ironclaw.dev"
    assert c.display_name == "New User"
    assert c.plan == "team-25k"
    assert c.active is True
    assert c.customer_id.startswith("cus_")


def test_create_customer_raises_value_error_for_invalid_email(registry: BillingRegistry) -> None:
    with pytest.raises(ValueError):
        registry.create_customer(
            email="not-an-email",
            display_name="Bad Email",
            plan="starter-5k",
        )


def test_create_customer_raises_value_error_for_invalid_plan(registry: BillingRegistry) -> None:
    with pytest.raises(ValueError):
        registry.create_customer(
            email="valid@ironclaw.dev",
            display_name="Bad Plan",
            plan="nonexistent-plan",
        )


def test_get_customer_returns_none_for_unknown_id(registry: BillingRegistry) -> None:
    assert registry.get_customer("cus_doesnotexist") is None


def test_get_customer_returns_correct_record(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="lookup@ironclaw.dev",
        display_name="Lookup User",
        plan="enterprise-60k",
    )
    fetched = registry.get_customer(c.customer_id)
    assert fetched is not None
    assert fetched.customer_id == c.customer_id
    assert fetched.email == "lookup@ironclaw.dev"


def test_list_customers_includes_newly_created(registry: BillingRegistry) -> None:
    registry.create_customer(
        email="listed@ironclaw.dev",
        display_name="Listed",
        plan="starter-5k",
    )
    all_customers = registry.list_customers()
    emails = [c.email for c in all_customers]
    assert "listed@ironclaw.dev" in emails


# ---------------------------------------------------------------------------
# deactivate_customer
# ---------------------------------------------------------------------------


def test_deactivate_customer_sets_active_false(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="deactivate@ironclaw.dev",
        display_name="Deactivate",
        plan="starter-5k",
    )
    registry.deactivate_customer(c.customer_id)
    fetched = registry.get_customer(c.customer_id)
    assert fetched is not None
    assert fetched.active is False


def test_deactivate_customer_cancels_active_subscriptions(registry: BillingRegistry) -> None:
    c = registry.create_customer(
        email="deactivate2@ironclaw.dev",
        display_name="Deactivate2",
        plan="starter-5k",
    )
    sub = registry.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
    )
    registry.deactivate_customer(c.customer_id)
    updated_sub = registry._subscriptions.get(sub.subscription_id)
    assert updated_sub is not None
    assert updated_sub.status == "cancelled"


def test_deactivate_customer_raises_key_error_for_unknown_id(registry: BillingRegistry) -> None:
    with pytest.raises(KeyError):
        registry.deactivate_customer("cus_ghost_id")


# ---------------------------------------------------------------------------
# cancel_subscription
# ---------------------------------------------------------------------------


def test_cancel_subscription_sets_status_cancelled(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, _, sid = registry_with_active_customer
    reg.cancel_subscription(sid)
    sub = reg._subscriptions.get(sid)
    assert sub is not None
    assert sub.status == "cancelled"


def test_cancel_subscription_raises_key_error_for_unknown_id(registry: BillingRegistry) -> None:
    with pytest.raises(KeyError):
        registry.cancel_subscription("sub_nonexistent_xyz")


# ---------------------------------------------------------------------------
# record_token_usage
# ---------------------------------------------------------------------------


def test_record_token_usage_consumes_correct_units(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    from app.core.billing import TOKENS_PER_UNIT

    reg, cid, sid = registry_with_active_customer
    sub_before = reg.get_active_subscription_for_customer(cid)
    assert sub_before is not None
    before = sub_before.units_consumed

    token_count = TOKENS_PER_UNIT * 3
    _, units_charged = reg.record_token_usage(customer_id=cid, token_count=token_count)
    assert units_charged == 3
    sub_after = reg.get_active_subscription_for_customer(cid)
    assert sub_after is not None
    assert sub_after.units_consumed == before + 3


def test_record_token_usage_rounds_up_partial_unit(
    registry_with_active_customer: tuple[BillingRegistry, str, str],
) -> None:
    reg, cid, _ = registry_with_active_customer
    _, units_charged = reg.record_token_usage(customer_id=cid, token_count=1)
    assert units_charged == 1


# ---------------------------------------------------------------------------
# Singleton isolation
# ---------------------------------------------------------------------------


def test_reset_billing_registry_for_testing_clears_singleton() -> None:
    from app.core.billing import get_billing_registry

    _reset_billing_registry_for_testing()
    r1 = get_billing_registry()
    _reset_billing_registry_for_testing()
    r2 = get_billing_registry()
    assert r1 is not r2


def test_get_billing_registry_returns_same_instance_across_calls() -> None:
    from app.core.billing import get_billing_registry

    _reset_billing_registry_for_testing()
    r1 = get_billing_registry()
    r2 = get_billing_registry()
    assert r1 is r2
    _reset_billing_registry_for_testing()
