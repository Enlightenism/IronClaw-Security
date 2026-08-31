from __future__ import annotations

import os

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
from unittest.mock import MagicMock, call

import pytest

from app.core.billing import (
    BillingCustomer,
    BillingRegistry,
    BillingSubscription,
)
from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyRecord,
)
from app.persistencebootstrap import InMemoryPersistenceStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store() -> InMemoryPersistenceStore:
    return InMemoryPersistenceStore()


def _future(days: int = 30) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


def _past(days: int = 1) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


def _make_install_key_record(
    owner_key: str,
    subscription_id: str,
    program: str,
) -> InstallKeyRecord:
    from app.core.install_keys import _utc_now

    return InstallKeyRecord(
        key_id=f"ik_test_{program}",
        owner_key=owner_key,
        subscription_id=subscription_id,
        program=program,  # type: ignore[arg-type]
        raw_key=f"ic_install_{program}_testrawkey",
        raw_key_hash="fakehash",
        masked_key="ic_install_***...test",
        label="auto-provisioned",
        active=True,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        units_consumed=0,
        created_at=_utc_now(),
        last_used_at=None,
        metadata={},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_install_key_registry() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def registry(mock_install_key_registry: MagicMock) -> BillingRegistry:
    return BillingRegistry(
        store=_make_store(),
        install_key_registry=mock_install_key_registry,
    )


@pytest.fixture()
def registry_no_ikr() -> BillingRegistry:
    """Registry without a mock install key registry — for has_active_subscription isolation."""
    return BillingRegistry(store=_make_store())


@pytest.fixture()
def customer(registry: BillingRegistry) -> BillingCustomer:
    return registry.create_customer(
        email="buyer@ironclaw.test",
        display_name="Buyer",
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
# has_active_subscription — returns False with no customers
# ---------------------------------------------------------------------------


def test_has_active_subscription_returns_false_with_no_customers(
    registry_no_ikr: BillingRegistry,
) -> None:
    assert registry_no_ikr.has_active_subscription("nobody@ironclaw.test") is False


def test_has_active_subscription_returns_false_empty_registry_any_key(
    registry_no_ikr: BillingRegistry,
) -> None:
    assert registry_no_ikr.has_active_subscription("ic_org_ghost") is False


# ---------------------------------------------------------------------------
# has_active_subscription — returns False with inactive customer
# ---------------------------------------------------------------------------


def test_has_active_subscription_returns_false_when_customer_is_inactive(
    registry_no_ikr: BillingRegistry,
) -> None:
    c = registry_no_ikr.create_customer(
        email="inactive@ironclaw.test",
        display_name="Inactive",
        plan="starter-5k",
    )
    registry_no_ikr.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    registry_no_ikr.deactivate_customer(c.customer_id)
    assert registry_no_ikr.has_active_subscription("inactive@ironclaw.test") is False


def test_has_active_subscription_returns_false_when_customer_has_no_subscription(
    registry_no_ikr: BillingRegistry,
) -> None:
    registry_no_ikr.create_customer(
        email="nosub@ironclaw.test",
        display_name="No Sub",
        plan="starter-5k",
    )
    assert registry_no_ikr.has_active_subscription("nosub@ironclaw.test") is False


def test_has_active_subscription_returns_false_when_subscription_is_cancelled(
    registry_no_ikr: BillingRegistry,
) -> None:
    c = registry_no_ikr.create_customer(
        email="cancelled@ironclaw.test",
        display_name="Cancelled",
        plan="starter-5k",
    )
    sub = registry_no_ikr.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    registry_no_ikr.cancel_subscription(sub.subscription_id)
    assert registry_no_ikr.has_active_subscription("cancelled@ironclaw.test") is False


def test_has_active_subscription_returns_false_when_units_exhausted(
    registry_no_ikr: BillingRegistry,
) -> None:
    from app.core.billing import PLAN_DEFINITIONS

    c = registry_no_ikr.create_customer(
        email="exhausted@ironclaw.test",
        display_name="Exhausted",
        plan="starter-5k",
    )
    registry_no_ikr.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    limit = PLAN_DEFINITIONS["starter-5k"]["unit_limit"]
    registry_no_ikr.record_usage(customer_id=c.customer_id, units=limit)
    assert registry_no_ikr.has_active_subscription("exhausted@ironclaw.test") is False


# ---------------------------------------------------------------------------
# has_active_subscription — returns True with active subscription
# ---------------------------------------------------------------------------


def test_has_active_subscription_returns_true_with_active_subscription(
    registry_no_ikr: BillingRegistry,
) -> None:
    c = registry_no_ikr.create_customer(
        email="active@ironclaw.test",
        display_name="Active",
        plan="starter-5k",
    )
    registry_no_ikr.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    assert registry_no_ikr.has_active_subscription("active@ironclaw.test") is True


def test_has_active_subscription_matches_normalized_email(
    registry_no_ikr: BillingRegistry,
) -> None:
    c = registry_no_ikr.create_customer(
        email="UPPER@IRONCLAW.TEST",
        display_name="Upper",
        plan="starter-5k",
    )
    registry_no_ikr.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    assert registry_no_ikr.has_active_subscription("upper@ironclaw.test") is True


def test_has_active_subscription_does_not_match_different_owner(
    registry_no_ikr: BillingRegistry,
) -> None:
    c = registry_no_ikr.create_customer(
        email="alice@ironclaw.test",
        display_name="Alice",
        plan="starter-5k",
    )
    registry_no_ikr.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    assert registry_no_ikr.has_active_subscription("bob@ironclaw.test") is False


def test_has_active_subscription_true_after_upgrade(
    registry_no_ikr: BillingRegistry,
) -> None:
    c = registry_no_ikr.create_customer(
        email="upgraded@ironclaw.test",
        display_name="Upgraded",
        plan="starter-5k",
    )
    registry_no_ikr.create_subscription(
        customer_id=c.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    registry_no_ikr.upgrade_plan(
        customer_id=c.customer_id,
        new_plan="team-25k",
    )
    assert registry_no_ikr.has_active_subscription("upgraded@ironclaw.test") is True


# ---------------------------------------------------------------------------
# provision_install_keys_on_purchase — raises ValueError when no active subscription
# ---------------------------------------------------------------------------


def test_provision_install_keys_raises_value_error_when_no_active_subscription(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
) -> None:
    c = registry.create_customer(
        email="nosubprovision@ironclaw.test",
        display_name="No Sub",
        plan="starter-5k",
    )
    with pytest.raises(ValueError, match="no active subscription"):
        registry.provision_install_keys_on_purchase(
            customer_id=c.customer_id,
            subscription_id="sub_fake",
            owner_key="nosubprovision@ironclaw.test",
        )


def test_provision_install_keys_raises_value_error_when_no_customers(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
) -> None:
    with pytest.raises(ValueError, match="no active subscription"):
        registry.provision_install_keys_on_purchase(
            customer_id="cus_ghost",
            subscription_id="sub_ghost",
            owner_key="ghost@ironclaw.test",
        )


def test_provision_install_keys_raises_value_error_when_subscription_cancelled(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    registry.cancel_subscription(active_sub.subscription_id)
    with pytest.raises(ValueError, match="no active subscription"):
        registry.provision_install_keys_on_purchase(
            customer_id=customer.customer_id,
            subscription_id=active_sub.subscription_id,
            owner_key=customer.email,
        )


# ---------------------------------------------------------------------------
# provision_install_keys_on_purchase — calls generate_install_key for both programs
# ---------------------------------------------------------------------------


def test_provision_install_keys_calls_generate_install_key_thrice(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert mock_install_key_registry.generate_install_key.call_count == 3


def test_provision_install_keys_calls_generate_install_key_with_openclaw_args(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    first_call = mock_install_key_registry.generate_install_key.call_args_list[0]
    assert first_call == call(
        customer.email,
        active_sub.subscription_id,
        "openclaw",
        label="auto-provisioned",
        metadata={"customer_id": customer.customer_id, "provisioned_by": "billing"},
    )


def test_provision_install_keys_calls_generate_install_key_with_claude_code_args(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    second_call = mock_install_key_registry.generate_install_key.call_args_list[1]
    assert second_call == call(
        customer.email,
        active_sub.subscription_id,
        "claude_code",
        label="auto-provisioned",
        metadata={"customer_id": customer.customer_id, "provisioned_by": "billing"},
    )


def test_provision_install_keys_openclaw_called_before_claude_code_before_hermes(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    calls_log: list[str] = []

    def _side_effect(owner_key: str, sub_id: str, program: str, **kwargs: object) -> InstallKeyRecord:
        calls_log.append(program)
        return _make_install_key_record(owner_key, sub_id, program)

    mock_install_key_registry.generate_install_key.side_effect = _side_effect
    registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert calls_log == ["openclaw", "claude_code", "hermes"]


def test_provision_install_keys_calls_generate_install_key_with_hermes_args(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    third_call = mock_install_key_registry.generate_install_key.call_args_list[2]
    assert third_call == call(
        customer.email,
        active_sub.subscription_id,
        "hermes",
        label="auto-provisioned",
        metadata={"customer_id": customer.customer_id, "provisioned_by": "billing"},
    )


# ---------------------------------------------------------------------------
# provision_install_keys_on_purchase — returns dict with both InstallKeyRecord objects
# ---------------------------------------------------------------------------


def test_provision_install_keys_returns_dict_with_openclaw_key(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    openclaw_record = _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw")
    claude_record = _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code")
    hermes_record = _make_install_key_record(customer.email, active_sub.subscription_id, "hermes")
    mock_install_key_registry.generate_install_key.side_effect = [openclaw_record, claude_record, hermes_record]
    result = registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert result["openclaw"] is openclaw_record


def test_provision_install_keys_returns_dict_with_claude_code_key(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    openclaw_record = _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw")
    claude_record = _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code")
    hermes_record = _make_install_key_record(customer.email, active_sub.subscription_id, "hermes")
    mock_install_key_registry.generate_install_key.side_effect = [openclaw_record, claude_record, hermes_record]
    result = registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert result["claude_code"] is claude_record


def test_provision_install_keys_return_dict_has_exactly_three_keys(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    result = registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert set(result.keys()) == {"openclaw", "claude_code", "hermes"}


def test_provision_install_keys_openclaw_value_is_install_key_record(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    result = registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert isinstance(result["openclaw"], InstallKeyRecord)


def test_provision_install_keys_claude_code_value_is_install_key_record(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    result = registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert isinstance(result["claude_code"], InstallKeyRecord)


def test_provision_install_keys_openclaw_record_program_is_openclaw(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    result = registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert result["openclaw"].program == "openclaw"


def test_provision_install_keys_claude_code_record_program_is_claude_code(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "claude_code"),
        _make_install_key_record(customer.email, active_sub.subscription_id, "hermes"),
    ]
    result = registry.provision_install_keys_on_purchase(
        customer_id=customer.customer_id,
        subscription_id=active_sub.subscription_id,
        owner_key=customer.email,
    )
    assert result["claude_code"].program == "claude_code"


# ---------------------------------------------------------------------------
# provision_install_keys_on_purchase — raises InstallKeyAlreadyExistsError on duplicate
# ---------------------------------------------------------------------------


def test_provision_install_keys_raises_already_exists_on_duplicate_openclaw(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = InstallKeyAlreadyExistsError(customer.email, "openclaw")
    with pytest.raises(InstallKeyAlreadyExistsError):
        registry.provision_install_keys_on_purchase(
            customer_id=customer.customer_id,
            subscription_id=active_sub.subscription_id,
            owner_key=customer.email,
        )


def test_provision_install_keys_raises_already_exists_on_duplicate_claude_code(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(customer.email, active_sub.subscription_id, "openclaw"),
        InstallKeyAlreadyExistsError(customer.email, "claude_code"),
    ]
    with pytest.raises(InstallKeyAlreadyExistsError):
        registry.provision_install_keys_on_purchase(
            customer_id=customer.customer_id,
            subscription_id=active_sub.subscription_id,
            owner_key=customer.email,
        )


def test_provision_install_keys_already_exists_error_has_correct_owner_key(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = InstallKeyAlreadyExistsError(customer.email, "openclaw")
    with pytest.raises(InstallKeyAlreadyExistsError) as exc_info:
        registry.provision_install_keys_on_purchase(
            customer_id=customer.customer_id,
            subscription_id=active_sub.subscription_id,
            owner_key=customer.email,
        )
    assert exc_info.value.owner_key == customer.email


def test_provision_install_keys_already_exists_error_has_correct_program(
    registry: BillingRegistry,
    mock_install_key_registry: MagicMock,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    mock_install_key_registry.generate_install_key.side_effect = InstallKeyAlreadyExistsError(customer.email, "openclaw")
    with pytest.raises(InstallKeyAlreadyExistsError) as exc_info:
        registry.provision_install_keys_on_purchase(
            customer_id=customer.customer_id,
            subscription_id=active_sub.subscription_id,
            owner_key=customer.email,
        )
    assert exc_info.value.program == "openclaw"


# ---------------------------------------------------------------------------
# BillingRegistry method contracts preserved — all existing public methods
# remain callable and return correct types on this isolated registry instance
# ---------------------------------------------------------------------------


def test_billing_registry_create_customer_contract_preserved(
    registry: BillingRegistry,
) -> None:
    c = registry.create_customer(
        email="contract@ironclaw.test",
        display_name="Contract",
        plan="starter-5k",
    )
    assert isinstance(c, BillingCustomer)
    assert c.customer_id.startswith("cus_")


def test_billing_registry_get_customer_contract_preserved(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    fetched = registry.get_customer(customer.customer_id)
    assert fetched is not None
    assert fetched.customer_id == customer.customer_id


def test_billing_registry_list_customers_contract_preserved(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    result = registry.list_customers()
    assert isinstance(result, list)
    assert any(c.customer_id == customer.customer_id for c in result)


def test_billing_registry_create_subscription_contract_preserved(
    registry: BillingRegistry,
    customer: BillingCustomer,
) -> None:
    sub = registry.create_subscription(
        customer_id=customer.customer_id,
        plan="starter-5k",
        status="active",
        period_end=_future(30),
    )
    assert isinstance(sub, BillingSubscription)
    assert sub.subscription_id.startswith("sub_")


def test_billing_registry_get_active_subscription_contract_preserved(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    result = registry.get_active_subscription_for_customer(customer.customer_id)
    assert result is not None
    assert result.subscription_id == active_sub.subscription_id


def test_billing_registry_list_subscriptions_contract_preserved(
    registry: BillingRegistry,
    active_sub: BillingSubscription,
) -> None:
    result = registry.list_subscriptions()
    assert isinstance(result, list)
    assert any(s.subscription_id == active_sub.subscription_id for s in result)


def test_billing_registry_cancel_subscription_contract_preserved(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    sub = registry.cancel_subscription(active_sub.subscription_id)
    assert sub.status == "cancelled"


def test_billing_registry_record_usage_contract_preserved(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    sub = registry.record_usage(customer_id=customer.customer_id, units=1)
    assert sub.units_consumed == 1


def test_billing_registry_can_consume_contract_preserved(
    registry: BillingRegistry,
    customer: BillingCustomer,
    active_sub: BillingSubscription,
) -> None:
    assert registry.can_consume(customer_id=customer.customer_id, units=1) is True


def test_billing_registry_get_plan_definitions_contract_preserved(
    registry: BillingRegistry,
) -> None:
    plans = registry.get_plan_definitions()
    assert isinstance(plans, dict)
    assert "starter-5k" in plans


def test_billing_registry_get_unit_package_catalog_contract_preserved(
    registry: BillingRegistry,
) -> None:
    catalog = registry.get_unit_package_catalog()
    assert isinstance(catalog, list)
    assert len(catalog) == 3
