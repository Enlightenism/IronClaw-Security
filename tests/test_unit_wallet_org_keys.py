from __future__ import annotations

import pytest

from app.core.unit_wallet import (
    ORG_KEY_PREFIX,
    InsufficientUnitsError,
    UnitWalletRegistry,
    is_org_key,
    units_required_for_tokens,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> UnitWalletRegistry:
    """Fresh isolated UnitWalletRegistry for every test."""
    return UnitWalletRegistry()


# ---------------------------------------------------------------------------
# ORG_KEY_PREFIX constant
# ---------------------------------------------------------------------------


def test_org_key_prefix_value() -> None:
    assert ORG_KEY_PREFIX == "ic_org_"


# ---------------------------------------------------------------------------
# is_org_key
# ---------------------------------------------------------------------------


def test_is_org_key_returns_true_for_ic_org_prefix() -> None:
    assert is_org_key("ic_org_acme") is True


def test_is_org_key_returns_true_for_ic_org_prefix_with_dashes() -> None:
    assert is_org_key("ic_org_my-team-123") is True


def test_is_org_key_returns_true_for_ic_org_prefix_uppercase_input() -> None:
    # is_org_key normalizes before checking prefix
    assert is_org_key("IC_ORG_ACME") is True


def test_is_org_key_returns_false_for_plain_email() -> None:
    assert is_org_key("user@example.com") is False


def test_is_org_key_returns_false_for_plain_string() -> None:
    assert is_org_key("acme") is False


def test_is_org_key_returns_false_for_partial_prefix() -> None:
    assert is_org_key("ic_org") is False


def test_is_org_key_returns_false_for_empty_string() -> None:
    assert is_org_key("") is False


def test_is_org_key_returns_false_for_personal_key_lookalike() -> None:
    assert is_org_key("ic_user_acme") is False


# ---------------------------------------------------------------------------
# get_or_create_wallet — org key idempotency
# ---------------------------------------------------------------------------


def test_org_key_get_or_create_is_idempotent(registry: UnitWalletRegistry) -> None:
    owner_key = "ic_org_acme"
    wallet_a = registry.get_or_create_wallet(owner_key)
    wallet_b = registry.get_or_create_wallet(owner_key)
    assert wallet_a.wallet_id == wallet_b.wallet_id


def test_org_key_case_variants_resolve_to_same_wallet(registry: UnitWalletRegistry) -> None:
    """ic_org_acme and IC_ORG_ACME must resolve to the same wallet after normalization."""
    wallet_lower = registry.get_or_create_wallet("ic_org_acme")
    wallet_upper = registry.get_or_create_wallet("IC_ORG_ACME")
    assert wallet_lower.wallet_id == wallet_upper.wallet_id


def test_org_key_mixed_case_resolves_to_same_wallet(registry: UnitWalletRegistry) -> None:
    wallet_a = registry.get_or_create_wallet("ic_org_Acme")
    wallet_b = registry.get_or_create_wallet("ic_org_acme")
    assert wallet_a.wallet_id == wallet_b.wallet_id


def test_org_key_wallet_owner_key_is_normalized(registry: UnitWalletRegistry) -> None:
    wallet = registry.get_or_create_wallet("IC_ORG_ACME")
    assert wallet.owner_key == "ic_org_acme"


def test_org_key_wallet_id_starts_with_wallet_prefix(registry: UnitWalletRegistry) -> None:
    wallet = registry.get_or_create_wallet("ic_org_acme")
    assert wallet.wallet_id.startswith("wallet_")


def test_two_different_org_keys_produce_different_wallets(registry: UnitWalletRegistry) -> None:
    wallet_acme = registry.get_or_create_wallet("ic_org_acme")
    wallet_beta = registry.get_or_create_wallet("ic_org_beta")
    assert wallet_acme.wallet_id != wallet_beta.wallet_id


def test_org_key_and_personal_email_produce_different_wallets(registry: UnitWalletRegistry) -> None:
    wallet_org = registry.get_or_create_wallet("ic_org_acme")
    wallet_personal = registry.get_or_create_wallet("user@acme.com")
    assert wallet_org.wallet_id != wallet_personal.wallet_id


# ---------------------------------------------------------------------------
# Shared org wallet — two logical members share the same balance
# ---------------------------------------------------------------------------


def test_two_members_share_same_org_wallet_after_credit(registry: UnitWalletRegistry) -> None:
    """Both members use the same org key — credit once, both see the same balance."""
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)

    # Member A resolves the wallet
    wallet_a = registry.get_or_create_wallet(org_key)
    # Member B resolves the wallet independently (simulated by re-calling get_or_create_wallet)
    wallet_b = registry.get_or_create_wallet(org_key)

    assert wallet_a.wallet_id == wallet_b.wallet_id
    assert wallet_a.balance_units == 5_000


def test_member_a_debit_reduces_shared_org_balance(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)

    registry.debit_units(owner_key=org_key, units=1_000)

    wallet = registry.get_or_create_wallet(org_key)
    assert wallet.balance_units == 4_000
    assert wallet.total_consumed_units == 1_000


def test_member_b_debit_reduces_same_wallet_as_member_a(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)

    # Both logical members debit the same org key
    registry.debit_units(owner_key=org_key, units=1_000)
    registry.debit_units(owner_key=org_key, units=500)

    wallet = registry.get_or_create_wallet(org_key)
    assert wallet.balance_units == 3_500
    assert wallet.total_consumed_units == 1_500


def test_two_member_debits_cumulative_consumed_units(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=10_000)

    registry.debit_units(owner_key=org_key, units=2_000)
    registry.debit_units(owner_key=org_key, units=3_000)

    wallet = registry.get_or_create_wallet(org_key)
    assert wallet.total_consumed_units == 5_000
    assert wallet.balance_units == 5_000


def test_org_wallet_balance_reflects_multiple_credits_and_debits(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)
    registry.credit_units(owner_key=org_key, units=5_000)

    registry.debit_units(owner_key=org_key, units=3_000)

    wallet = registry.get_or_create_wallet(org_key)
    assert wallet.balance_units == 7_000
    assert wallet.total_purchased_units == 10_000
    assert wallet.total_consumed_units == 3_000


def test_org_wallet_debit_exact_balance_leaves_zero(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)

    wallet = registry.debit_units(owner_key=org_key, units=5_000)
    assert wallet.balance_units == 0
    assert wallet.total_consumed_units == 5_000


# ---------------------------------------------------------------------------
# InsufficientUnitsError — org wallet
# ---------------------------------------------------------------------------


def test_org_wallet_insufficient_units_raises_error(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=100)

    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units(owner_key=org_key, units=500)

    assert exc_info.value.have == 100
    assert exc_info.value.need == 500


def test_org_wallet_insufficient_units_owner_key_is_normalized_org_key(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=100)

    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units(owner_key=org_key, units=9_999)

    assert exc_info.value.owner_key == "ic_org_acme"


def test_org_wallet_insufficient_units_owner_key_normalized_from_uppercase(registry: UnitWalletRegistry) -> None:
    registry.credit_units(owner_key="IC_ORG_ACME", units=50)

    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units(owner_key="IC_ORG_ACME", units=200)

    assert exc_info.value.owner_key == "ic_org_acme"
    assert exc_info.value.have == 50
    assert exc_info.value.need == 200


def test_org_wallet_zero_balance_debit_raises_insufficient_error(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    # No credit — wallet starts at zero

    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units(owner_key=org_key, units=1)

    assert exc_info.value.have == 0
    assert exc_info.value.need == 1
    assert exc_info.value.owner_key == "ic_org_acme"


def test_org_wallet_balance_unchanged_after_failed_debit(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=200)

    with pytest.raises(InsufficientUnitsError):
        registry.debit_units(owner_key=org_key, units=9_999)

    wallet = registry.get_or_create_wallet(org_key)
    assert wallet.balance_units == 200
    assert wallet.total_consumed_units == 0


# ---------------------------------------------------------------------------
# debit_units_for_tokens — org wallet
# ---------------------------------------------------------------------------


def test_org_wallet_debit_for_tokens_consumes_correct_units(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=10)

    wallet, units_debited = registry.debit_units_for_tokens(owner_key=org_key, token_count=25_000)
    assert units_debited == 1
    assert wallet.balance_units == 9


def test_org_wallet_debit_for_tokens_ceiling_division(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=10)

    wallet, units_debited = registry.debit_units_for_tokens(owner_key=org_key, token_count=25_001)
    assert units_debited == 2
    assert wallet.balance_units == 8


def test_org_wallet_debit_for_tokens_insufficient_raises_error(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=1)

    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units_for_tokens(owner_key=org_key, token_count=50_001)

    assert exc_info.value.need == units_required_for_tokens(50_001)
    assert exc_info.value.have == 1
    assert exc_info.value.owner_key == "ic_org_acme"


# ---------------------------------------------------------------------------
# Org wallet isolation from personal wallets
# ---------------------------------------------------------------------------


def test_org_wallet_debit_does_not_affect_personal_wallet(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    personal_key = "user@acme.com"

    registry.credit_units(owner_key=org_key, units=5_000)
    registry.credit_units(owner_key=personal_key, units=5_000)

    registry.debit_units(owner_key=org_key, units=1_000)

    personal_wallet = registry.get_or_create_wallet(personal_key)
    assert personal_wallet.balance_units == 5_000
    assert personal_wallet.total_consumed_units == 0


def test_personal_wallet_debit_does_not_affect_org_wallet(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    personal_key = "user@acme.com"

    registry.credit_units(owner_key=org_key, units=5_000)
    registry.credit_units(owner_key=personal_key, units=5_000)

    registry.debit_units(owner_key=personal_key, units=2_000)

    org_wallet = registry.get_or_create_wallet(org_key)
    assert org_wallet.balance_units == 5_000
    assert org_wallet.total_consumed_units == 0


# ---------------------------------------------------------------------------
# Ledger — org key entries
# ---------------------------------------------------------------------------


def test_org_wallet_ledger_records_credit_entry(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)

    entries = registry.list_ledger_entries(owner_key="ic_org_acme")
    assert len(entries) == 1
    assert entries[0].entry_type == "credit"
    assert entries[0].units == 5_000
    assert entries[0].owner_key == "ic_org_acme"


def test_org_wallet_ledger_records_debit_entry(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)
    registry.debit_units(owner_key=org_key, units=1_000)

    entries = registry.list_ledger_entries(owner_key="ic_org_acme")
    debit_entries = [e for e in entries if e.entry_type == "debit"]
    assert len(debit_entries) == 1
    assert debit_entries[0].units == 1_000
    assert debit_entries[0].owner_key == "ic_org_acme"


def test_org_wallet_ledger_owner_key_is_normalized(registry: UnitWalletRegistry) -> None:
    registry.credit_units(owner_key="IC_ORG_ACME", units=500)

    entries = registry.list_ledger_entries(owner_key="ic_org_acme")
    assert len(entries) == 1
    assert entries[0].owner_key == "ic_org_acme"


def test_org_wallet_ledger_does_not_include_personal_entries(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    personal_key = "user@acme.com"

    registry.credit_units(owner_key=org_key, units=5_000)
    registry.credit_units(owner_key=personal_key, units=5_000)
    registry.debit_units(owner_key=personal_key, units=100)

    org_entries = registry.list_ledger_entries(owner_key="ic_org_acme")
    for entry in org_entries:
        assert entry.owner_key == "ic_org_acme"
        assert entry.owner_key != personal_key


def test_personal_wallet_ledger_does_not_include_org_entries(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    personal_key = "user@acme.com"

    registry.credit_units(owner_key=org_key, units=5_000)
    registry.credit_units(owner_key=personal_key, units=5_000)
    registry.debit_units(owner_key=org_key, units=100)

    personal_entries = registry.list_ledger_entries(owner_key=personal_key)
    for entry in personal_entries:
        assert entry.owner_key == personal_key
        assert not is_org_key(entry.owner_key)


# ---------------------------------------------------------------------------
# Refund — org wallet
# ---------------------------------------------------------------------------


def test_org_wallet_refund_increases_balance(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)
    registry.debit_units(owner_key=org_key, units=1_000)

    wallet = registry.refund_units(owner_key=org_key, units=500)
    assert wallet.balance_units == 4_500
    assert wallet.total_refunded_units == 500
    assert wallet.total_consumed_units == 1_000


def test_org_wallet_refund_ledger_entry_type_is_refund(registry: UnitWalletRegistry) -> None:
    org_key = "ic_org_acme"
    registry.credit_units(owner_key=org_key, units=5_000)
    registry.refund_units(owner_key=org_key, units=200)

    entries = registry.list_ledger_entries(owner_key="ic_org_acme")
    refund_entries = [e for e in entries if e.entry_type == "refund"]
    assert len(refund_entries) == 1
    assert refund_entries[0].units == 200
