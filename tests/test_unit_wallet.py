from __future__ import annotations

from datetime import UTC, datetime
import math
import os

import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")

from app.core.unit_wallet import (
    TOKEN_CHUNK_SIZE,
    UNIT_PACKAGE_CATALOG,
    InsufficientUnitsError,
    UnitLedgerEntry,
    UnitWallet,
    UnitWalletRegistry,
    UnitWalletTransaction,
    units_required_for_tokens,
)

# ---------------------------------------------------------------------------
# Package-tier constants — derived from UNIT_PACKAGE_CATALOG, never hardcoded.
# Starter    : pkg_5000  —  5,000 units — $20.00
# Team       : pkg_25000 — 25,000 units — $90.00
# Enterprise : pkg_60000 — 60,000 units — $180.00
# Each unit covers TOKEN_CHUNK_SIZE (25,000) tokens (ceiling division).
# ---------------------------------------------------------------------------

_PKG_STARTER_UNITS: int = UNIT_PACKAGE_CATALOG["pkg_5000"]["unit_amount"]  # 5_000
_PKG_STARTER_PRICE_USD: float = UNIT_PACKAGE_CATALOG["pkg_5000"]["price_usd"]  # 20.00
_PKG_STARTER_LABEL: str = UNIT_PACKAGE_CATALOG["pkg_5000"]["display_label"]

_PKG_TEAM_UNITS: int = UNIT_PACKAGE_CATALOG["pkg_25000"]["unit_amount"]  # 25_000
_PKG_TEAM_PRICE_USD: float = UNIT_PACKAGE_CATALOG["pkg_25000"]["price_usd"]  # 90.00
_PKG_TEAM_LABEL: str = UNIT_PACKAGE_CATALOG["pkg_25000"]["display_label"]

_PKG_ENTERPRISE_UNITS: int = UNIT_PACKAGE_CATALOG["pkg_60000"]["unit_amount"]  # 60_000
_PKG_ENTERPRISE_PRICE_USD: float = UNIT_PACKAGE_CATALOG["pkg_60000"]["price_usd"]  # 180.00
_PKG_ENTERPRISE_LABEL: str = UNIT_PACKAGE_CATALOG["pkg_60000"]["display_label"]

_TOKENS_PER_UNIT: int = TOKEN_CHUNK_SIZE  # 25_000


# ===========================================================================
# Section 1 — UnitWallet: basic state
# ===========================================================================


def test_wallet_starts_with_zero_balance() -> None:
    wallet = UnitWallet(owner_id="owner-001")

    assert wallet.owner_id == "owner-001"
    assert wallet.balance_units == 0
    assert wallet.total_purchased_units == 0
    assert wallet.total_consumed_units == 0
    assert wallet.total_refunded_units == 0
    assert wallet.transactions == []


def test_purchase_units_increases_balance_and_totals() -> None:
    wallet = UnitWallet(owner_id="owner-001")

    transaction = wallet.purchase_units(
        units=_PKG_STARTER_UNITS,
        source="stripe_checkout",
        reference_id="checkout-001",
        metadata={"plan": "starter"},
    )

    assert isinstance(transaction, UnitWalletTransaction)
    assert transaction.owner_id == "owner-001"
    assert transaction.transaction_type == "purchase"
    assert transaction.units == _PKG_STARTER_UNITS
    assert transaction.source == "stripe_checkout"
    assert transaction.reference_id == "checkout-001"
    assert transaction.metadata == {"plan": "starter"}

    assert wallet.balance_units == _PKG_STARTER_UNITS
    assert wallet.total_purchased_units == _PKG_STARTER_UNITS
    assert wallet.total_consumed_units == 0
    assert wallet.total_refunded_units == 0
    assert len(wallet.transactions) == 1


def test_consume_units_reduces_balance_and_increases_consumed_total() -> None:
    wallet = UnitWallet(owner_id="owner-001")
    wallet.purchase_units(
        units=_PKG_TEAM_UNITS,
        source="stripe_checkout",
        reference_id="checkout-001",
    )

    consume_amount = _PKG_STARTER_UNITS
    transaction = wallet.consume_units(
        units=consume_amount,
        source="usage_metering",
        reference_id="usage-001",
        metadata={"route": "/guard/execute"},
    )

    assert isinstance(transaction, UnitWalletTransaction)
    assert transaction.transaction_type == "consume"
    assert transaction.units == consume_amount
    assert transaction.source == "usage_metering"
    assert transaction.reference_id == "usage-001"
    assert transaction.metadata == {"route": "/guard/execute"}

    assert wallet.balance_units == _PKG_TEAM_UNITS - consume_amount
    assert wallet.total_purchased_units == _PKG_TEAM_UNITS
    assert wallet.total_consumed_units == consume_amount
    assert wallet.total_refunded_units == 0
    assert len(wallet.transactions) == 2


def test_refund_units_increases_balance_and_refunded_total() -> None:
    wallet = UnitWallet(owner_id="owner-001")
    wallet.purchase_units(
        units=_PKG_TEAM_UNITS,
        source="stripe_checkout",
        reference_id="checkout-001",
    )
    consume_amount = _PKG_STARTER_UNITS
    refund_amount = 100
    wallet.consume_units(units=consume_amount, source="usage_metering", reference_id="usage-001")

    transaction = wallet.refund_units(
        units=refund_amount,
        source="manual_adjustment",
        reference_id="refund-001",
        metadata={"reason": "support_credit"},
    )

    assert isinstance(transaction, UnitWalletTransaction)
    assert transaction.transaction_type == "refund"
    assert transaction.units == refund_amount
    assert transaction.source == "manual_adjustment"
    assert transaction.reference_id == "refund-001"
    assert transaction.metadata == {"reason": "support_credit"}

    assert wallet.balance_units == _PKG_TEAM_UNITS - consume_amount + refund_amount
    assert wallet.total_purchased_units == _PKG_TEAM_UNITS
    assert wallet.total_consumed_units == consume_amount
    assert wallet.total_refunded_units == refund_amount
    assert len(wallet.transactions) == 3


def test_consume_units_raises_when_balance_is_insufficient() -> None:
    wallet = UnitWallet(owner_id="owner-001")
    wallet.purchase_units(units=40, source="stripe_checkout", reference_id="checkout-001")

    with pytest.raises(InsufficientUnitsError):
        wallet.consume_units(
            units=100,
            source="usage_metering",
            reference_id="usage-001",
        )

    assert wallet.balance_units == 40
    assert wallet.total_consumed_units == 0
    assert len(wallet.transactions) == 1


def test_transaction_history_preserves_order() -> None:
    wallet = UnitWallet(owner_id="owner-001")

    purchase = wallet.purchase_units(
        units=_PKG_STARTER_UNITS,
        source="stripe_checkout",
        reference_id="checkout-001",
    )
    consume = wallet.consume_units(
        units=20,
        source="usage_metering",
        reference_id="usage-001",
    )
    refund = wallet.refund_units(
        units=5,
        source="manual_adjustment",
        reference_id="refund-001",
    )

    assert wallet.transactions == [purchase, consume, refund]


def test_ledger_entry_can_wrap_transaction_snapshot() -> None:
    transaction = UnitWalletTransaction(
        transaction_id="txn-001",
        owner_id="owner-001",
        transaction_type="purchase",
        units=_PKG_STARTER_UNITS,
        balance_after=_PKG_STARTER_UNITS,
        source="stripe_checkout",
        reference_id="checkout-001",
        created_at=datetime.now(UTC),
        metadata={"plan": "starter"},
    )

    entry = UnitLedgerEntry(
        owner_id="owner-001",
        transaction=transaction,
        recorded_at=datetime.now(UTC),
    )

    assert entry.owner_id == "owner-001"
    assert entry.transaction.transaction_id == "txn-001"
    assert entry.transaction.balance_after == _PKG_STARTER_UNITS
    assert entry.transaction.metadata == {"plan": "starter"}


# ===========================================================================
# Section 2 — Package catalogue correctness
# ===========================================================================


class TestPackageCatalog:
    def test_catalog_contains_all_three_packages(self) -> None:
        assert "pkg_5000" in UNIT_PACKAGE_CATALOG
        assert "pkg_25000" in UNIT_PACKAGE_CATALOG
        assert "pkg_60000" in UNIT_PACKAGE_CATALOG

    def test_starter_unit_amount(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_5000"]["unit_amount"] == 5_000

    def test_starter_price_usd(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_5000"]["price_usd"] == 20.00

    def test_starter_tokens_per_unit(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_5000"]["tokens_per_unit"] == 25_000

    def test_starter_display_label(self) -> None:
        assert "5,000" in UNIT_PACKAGE_CATALOG["pkg_5000"]["display_label"]
        assert "20.00" in UNIT_PACKAGE_CATALOG["pkg_5000"]["display_label"]

    def test_starter_name(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_5000"]["name"] == "Starter"

    def test_team_unit_amount(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_25000"]["unit_amount"] == 25_000

    def test_team_price_usd(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_25000"]["price_usd"] == 90.00

    def test_team_tokens_per_unit(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_25000"]["tokens_per_unit"] == 25_000

    def test_team_display_label(self) -> None:
        assert "25,000" in UNIT_PACKAGE_CATALOG["pkg_25000"]["display_label"]
        assert "90.00" in UNIT_PACKAGE_CATALOG["pkg_25000"]["display_label"]

    def test_team_name(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_25000"]["name"] == "Team"

    def test_enterprise_unit_amount(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_60000"]["unit_amount"] == 60_000

    def test_enterprise_price_usd(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_60000"]["price_usd"] == 180.00

    def test_enterprise_tokens_per_unit(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_60000"]["tokens_per_unit"] == 25_000

    def test_enterprise_display_label(self) -> None:
        assert "60,000" in UNIT_PACKAGE_CATALOG["pkg_60000"]["display_label"]
        assert "180.00" in UNIT_PACKAGE_CATALOG["pkg_60000"]["display_label"]

    def test_enterprise_name(self) -> None:
        assert UNIT_PACKAGE_CATALOG["pkg_60000"]["name"] == "Enterprise"

    def test_tier_unit_ordering(self) -> None:
        assert _PKG_STARTER_UNITS < _PKG_TEAM_UNITS < _PKG_ENTERPRISE_UNITS

    def test_tier_price_ordering(self) -> None:
        assert _PKG_STARTER_PRICE_USD < _PKG_TEAM_PRICE_USD < _PKG_ENTERPRISE_PRICE_USD

    def test_tokens_per_unit_is_25000(self) -> None:
        assert _TOKENS_PER_UNIT == 25_000

    def test_token_chunk_size_constant(self) -> None:
        assert TOKEN_CHUNK_SIZE == 25_000


# ===========================================================================
# Section 3 — units_required_for_tokens() boundary conditions
# ===========================================================================


class TestUnitsRequiredForTokens:
    """
    Coverage rule: units = ceil(token_count / TOKEN_CHUNK_SIZE)
    TOKEN_CHUNK_SIZE = 25_000
    Returns 0 for non-positive inputs.
    """

    def test_zero_tokens_returns_zero(self) -> None:
        assert units_required_for_tokens(0) == 0

    def test_negative_tokens_returns_zero(self) -> None:
        assert units_required_for_tokens(-1) == 0

    def test_negative_large_returns_zero(self) -> None:
        assert units_required_for_tokens(-100_000) == 0

    def test_one_token_requires_one_unit(self) -> None:
        assert units_required_for_tokens(1) == 1

    def test_mid_first_chunk_requires_one_unit(self) -> None:
        assert units_required_for_tokens(12_500) == 1

    def test_exact_first_chunk_boundary(self) -> None:
        assert units_required_for_tokens(25_000) == 1

    def test_one_over_first_chunk_requires_two_units(self) -> None:
        assert units_required_for_tokens(25_001) == 2

    def test_mid_second_chunk_requires_two_units(self) -> None:
        assert units_required_for_tokens(37_500) == 2

    def test_exact_second_chunk_boundary(self) -> None:
        assert units_required_for_tokens(50_000) == 2

    def test_one_over_second_chunk_requires_three_units(self) -> None:
        assert units_required_for_tokens(50_001) == 3

    def test_exact_third_chunk_boundary(self) -> None:
        assert units_required_for_tokens(75_000) == 3

    def test_one_over_third_chunk_requires_four_units(self) -> None:
        assert units_required_for_tokens(75_001) == 4

    def test_matches_math_ceil_formula(self) -> None:
        for n in [1, 9_999, 25_000, 25_001, 49_999, 50_000, 50_001, 74_999, 75_000, 75_001, 100_000]:
            assert units_required_for_tokens(n) == math.ceil(n / _TOKENS_PER_UNIT)

    def test_starter_package_exact_ceiling(self) -> None:
        max_tokens = _PKG_STARTER_UNITS * _TOKENS_PER_UNIT
        assert units_required_for_tokens(max_tokens) == _PKG_STARTER_UNITS

    def test_starter_package_one_over_ceiling(self) -> None:
        max_tokens = _PKG_STARTER_UNITS * _TOKENS_PER_UNIT
        assert units_required_for_tokens(max_tokens + 1) == _PKG_STARTER_UNITS + 1

    def test_team_package_exact_ceiling(self) -> None:
        max_tokens = _PKG_TEAM_UNITS * _TOKENS_PER_UNIT
        assert units_required_for_tokens(max_tokens) == _PKG_TEAM_UNITS

    def test_team_package_one_over_ceiling(self) -> None:
        max_tokens = _PKG_TEAM_UNITS * _TOKENS_PER_UNIT
        assert units_required_for_tokens(max_tokens + 1) == _PKG_TEAM_UNITS + 1

    def test_enterprise_package_exact_ceiling(self) -> None:
        max_tokens = _PKG_ENTERPRISE_UNITS * _TOKENS_PER_UNIT
        assert units_required_for_tokens(max_tokens) == _PKG_ENTERPRISE_UNITS

    def test_enterprise_package_one_over_ceiling(self) -> None:
        max_tokens = _PKG_ENTERPRISE_UNITS * _TOKENS_PER_UNIT
        assert units_required_for_tokens(max_tokens + 1) == _PKG_ENTERPRISE_UNITS + 1


# ===========================================================================
# Section 4 — UnitWallet.consume_units_for_tokens() boundary conditions
# ===========================================================================


class TestConsumeUnitsForTokens:
    """
    Exercises consume_units_for_tokens() on UnitWallet.
    Verifies ceiling division, metadata injection, and
    InsufficientUnitsError when wallet cannot cover the payload.
    """

    def _funded_wallet(self, units: int = _PKG_ENTERPRISE_UNITS) -> UnitWallet:
        wallet = UnitWallet(owner_id="owner-token-test")
        wallet.purchase_units(units=units, source="stripe_checkout", reference_id="checkout-tok")
        return wallet

    def test_exact_one_chunk_consumes_one_unit(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=25_000, source="usage_metering")
        assert txn.units == 1
        assert wallet.total_consumed_units == 1

    def test_one_over_first_chunk_consumes_two_units(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=25_001, source="usage_metering")
        assert txn.units == 2
        assert wallet.total_consumed_units == 2

    def test_exact_two_chunks_consumes_two_units(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=50_000, source="usage_metering")
        assert txn.units == 2

    def test_one_over_two_chunks_consumes_three_units(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=50_001, source="usage_metering")
        assert txn.units == 3

    def test_zero_tokens_consumes_zero_units(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=0, source="usage_metering")
        assert txn.units == 0
        assert wallet.total_consumed_units == 0

    def test_metadata_contains_token_count(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(
            token_count=37_500,
            source="usage_metering",
            reference_id="ref-meta",
        )
        assert txn.metadata["token_count"] == 37_500

    def test_metadata_contains_tokens_per_unit(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=25_000, source="usage_metering")
        assert txn.metadata["tokens_per_unit"] == _TOKENS_PER_UNIT

    def test_metadata_contains_units_required(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=50_001, source="usage_metering")
        assert txn.metadata["units_required"] == 3

    def test_caller_metadata_merged(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(
            token_count=25_000,
            source="usage_metering",
            metadata={"route": "/guard/execute"},
        )
        assert txn.metadata["route"] == "/guard/execute"
        assert txn.metadata["token_count"] == 25_000

    def test_insufficient_units_raises(self) -> None:
        wallet = UnitWallet(owner_id="owner-broke")
        wallet.purchase_units(units=1, source="stripe_checkout", reference_id="checkout-broke")
        with pytest.raises(InsufficientUnitsError):
            wallet.consume_units_for_tokens(token_count=50_001, source="usage_metering")
        assert wallet.balance_units == 1
        assert wallet.total_consumed_units == 0

    def test_balance_reduced_correctly_after_multi_chunk_consume(self) -> None:
        wallet = self._funded_wallet(_PKG_TEAM_UNITS)
        wallet.consume_units_for_tokens(token_count=75_000, source="usage_metering")
        assert wallet.balance_units == _PKG_TEAM_UNITS - 3

    def test_transaction_type_is_consume(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(token_count=25_000, source="usage_metering")
        assert txn.transaction_type == "consume"

    def test_reference_id_propagated(self) -> None:
        wallet = self._funded_wallet()
        txn = wallet.consume_units_for_tokens(
            token_count=25_000,
            source="usage_metering",
            reference_id="ref-abc",
        )
        assert txn.reference_id == "ref-abc"


# ===========================================================================
# Section 5 — UnitWalletRegistry.debit_units_for_tokens() boundary conditions
# ===========================================================================


class TestRegistryDebitUnitsForTokens:
    """
    Exercises UnitWalletRegistry.debit_units_for_tokens() via the in-memory
    persistence backend. Verifies return tuple, balance deduction, metadata
    propagation, and InsufficientUnitsError on under-funded wallets.
    """

    def _registry_with_balance(self, owner: str, units: int) -> UnitWalletRegistry:
        registry = UnitWalletRegistry()
        registry.credit_units(owner_key=owner, units=units)
        return registry

    def test_returns_wallet_and_units_debited(self) -> None:
        registry = self._registry_with_balance("owner-reg-001", _PKG_ENTERPRISE_UNITS)
        wallet, debited = registry.debit_units_for_tokens(owner_key="owner-reg-001", token_count=25_000)
        assert debited == 1
        assert wallet.balance_units == _PKG_ENTERPRISE_UNITS - 1

    def test_exact_first_chunk_debits_one(self) -> None:
        registry = self._registry_with_balance("owner-reg-002", _PKG_TEAM_UNITS)
        _, debited = registry.debit_units_for_tokens(owner_key="owner-reg-002", token_count=25_000)
        assert debited == 1

    def test_one_over_first_chunk_debits_two(self) -> None:
        registry = self._registry_with_balance("owner-reg-003", _PKG_TEAM_UNITS)
        _, debited = registry.debit_units_for_tokens(owner_key="owner-reg-003", token_count=25_001)
        assert debited == 2

    def test_exact_second_chunk_debits_two(self) -> None:
        registry = self._registry_with_balance("owner-reg-004", _PKG_TEAM_UNITS)
        _, debited = registry.debit_units_for_tokens(owner_key="owner-reg-004", token_count=50_000)
        assert debited == 2

    def test_one_over_second_chunk_debits_three(self) -> None:
        registry = self._registry_with_balance("owner-reg-005", _PKG_TEAM_UNITS)
        _, debited = registry.debit_units_for_tokens(owner_key="owner-reg-005", token_count=50_001)
        assert debited == 3

    def test_metadata_contains_token_count(self) -> None:
        owner = "owner-reg-meta-001"
        registry = self._registry_with_balance(owner, _PKG_ENTERPRISE_UNITS)
        registry.debit_units_for_tokens(
            owner_key=owner,
            token_count=37_500,
            metadata={"route": "/guard/execute"},
        )
        entries = registry.list_ledger_entries(owner_key=owner)
        debit_entry = next(e for e in entries if e.entry_type == "debit")
        assert debit_entry.metadata["token_count"] == 37_500
        assert debit_entry.metadata["tokens_per_unit"] == _TOKENS_PER_UNIT
        assert debit_entry.metadata["units_required"] == 2

    def test_caller_metadata_merged_into_ledger(self) -> None:
        owner = "owner-reg-meta-002"
        registry = self._registry_with_balance(owner, _PKG_ENTERPRISE_UNITS)
        registry.debit_units_for_tokens(
            owner_key=owner,
            token_count=25_000,
            metadata={"pipeline": "agent-v2"},
        )
        entries = registry.list_ledger_entries(owner_key=owner)
        debit_entry = next(e for e in entries if e.entry_type == "debit")
        assert debit_entry.metadata["pipeline"] == "agent-v2"

    def test_insufficient_units_raises(self) -> None:
        owner = "owner-reg-broke"
        registry = self._registry_with_balance(owner, 1)
        with pytest.raises(InsufficientUnitsError):
            registry.debit_units_for_tokens(owner_key=owner, token_count=50_001)
        wallet = registry.get_wallet(owner)
        assert wallet is not None
        assert wallet.balance_units == 1

    def test_balance_decremented_by_correct_unit_count(self) -> None:
        owner = "owner-reg-balance"
        registry = self._registry_with_balance(owner, _PKG_ENTERPRISE_UNITS)
        registry.debit_units_for_tokens(owner_key=owner, token_count=75_000)
        wallet = registry.get_wallet(owner)
        assert wallet is not None
        assert wallet.balance_units == _PKG_ENTERPRISE_UNITS - 3

    def test_zero_tokens_debits_zero(self) -> None:
        owner = "owner-reg-zero"
        registry = self._registry_with_balance(owner, _PKG_STARTER_UNITS)
        _, debited = registry.debit_units_for_tokens(owner_key=owner, token_count=0)
        assert debited == 0
        wallet = registry.get_wallet(owner)
        assert wallet is not None
        assert wallet.balance_units == _PKG_STARTER_UNITS
