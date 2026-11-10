from __future__ import annotations

from datetime import UTC, datetime
import math
import os
import uuid

import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")

from app.core.unit_wallet import (
    TOKEN_CHUNK_SIZE,
    UNIT_PACKAGE_CATALOG,
    InsufficientUnitsError,
    MemoryUnitWalletRepository,
    RegistryUnitLedgerEntry,
    RegistryUnitWallet,
    UnitLedgerEntry,
    UnitWallet,
    UnitWalletRegistry,
    UnitWalletTransaction,
    units_required_for_tokens,
)
from app.supabaseclient import TOKENS_PER_UNIT as _SUPABASE_TOKENS_PER_UNIT

# ---------------------------------------------------------------------------
# Package-tier constants — derived from UNIT_PACKAGE_CATALOG, never hardcoded.
# Starter    : pkg_5000  —  5,000 units — $20.00
# Team       : pkg_25000 — 25,000 units — $90.00
# Enterprise : pkg_60000 — 60,000 units — $180.00
# Each unit covers TOKEN_CHUNK_SIZE (25,000) tokens (ceiling division).
# ---------------------------------------------------------------------------

_PKG_STARTER_UNITS: int = UNIT_PACKAGE_CATALOG["pkg_5000"]["unit_amount"]
_PKG_STARTER_PRICE_USD: float = UNIT_PACKAGE_CATALOG["pkg_5000"]["price_usd"]
_PKG_STARTER_LABEL: str = UNIT_PACKAGE_CATALOG["pkg_5000"]["display_label"]

_PKG_TEAM_UNITS: int = UNIT_PACKAGE_CATALOG["pkg_25000"]["unit_amount"]
_PKG_TEAM_PRICE_USD: float = UNIT_PACKAGE_CATALOG["pkg_25000"]["price_usd"]
_PKG_TEAM_LABEL: str = UNIT_PACKAGE_CATALOG["pkg_25000"]["display_label"]

_PKG_ENTERPRISE_UNITS: int = UNIT_PACKAGE_CATALOG["pkg_60000"]["unit_amount"]
_PKG_ENTERPRISE_PRICE_USD: float = UNIT_PACKAGE_CATALOG["pkg_60000"]["price_usd"]
_PKG_ENTERPRISE_LABEL: str = UNIT_PACKAGE_CATALOG["pkg_60000"]["display_label"]

_TOKENS_PER_UNIT: int = TOKEN_CHUNK_SIZE  # 25_000


# ===========================================================================
# Section 0 — Cross-module constant sync guard
# ===========================================================================


def test_token_chunk_size_matches_supabase_tokens_per_unit() -> None:
    """TOKEN_CHUNK_SIZE and supabaseclient.TOKENS_PER_UNIT must always be equal."""
    assert TOKEN_CHUNK_SIZE == _SUPABASE_TOKENS_PER_UNIT, f"Billing integrity failure: TOKEN_CHUNK_SIZE={TOKEN_CHUNK_SIZE} != TOKENS_PER_UNIT={_SUPABASE_TOKENS_PER_UNIT}. These constants must always be equal. Update the diverged module."


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
    wallet.purchase_units(units=_PKG_TEAM_UNITS, source="stripe_checkout", reference_id="checkout-001")
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
    wallet.purchase_units(units=_PKG_TEAM_UNITS, source="stripe_checkout", reference_id="checkout-001")
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
        wallet.consume_units(units=100, source="usage_metering", reference_id="usage-001")
    assert wallet.balance_units == 40
    assert wallet.total_consumed_units == 0
    assert len(wallet.transactions) == 1


def test_consume_units_insufficient_error_carries_have_need_owner() -> None:
    wallet = UnitWallet(owner_id="owner-err-001")
    wallet.purchase_units(units=5, source="stripe_checkout", reference_id="chk-err")
    with pytest.raises(InsufficientUnitsError) as exc_info:
        wallet.consume_units(units=20, source="usage_metering")
    err = exc_info.value
    assert err.have == 5
    assert err.need == 20
    assert err.owner_key == "owner-err-001"


def test_transaction_history_preserves_order() -> None:
    wallet = UnitWallet(owner_id="owner-001")
    purchase = wallet.purchase_units(units=_PKG_STARTER_UNITS, source="stripe_checkout", reference_id="checkout-001")
    consume = wallet.consume_units(units=20, source="usage_metering", reference_id="usage-001")
    refund = wallet.refund_units(units=5, source="manual_adjustment", reference_id="refund-001")
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

    def test_catalog_contains_exactly_three_packages(self) -> None:
        assert set(UNIT_PACKAGE_CATALOG.keys()) == {"pkg_5000", "pkg_25000", "pkg_60000"}

    def test_no_max_tokens_covered_key_in_any_entry(self) -> None:
        for pkg_id, pkg in UNIT_PACKAGE_CATALOG.items():
            assert "max_tokens_covered" not in pkg, f"package {pkg_id!r} must not expose 'max_tokens_covered' — use token_coverage computed at the route layer instead"

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

    def test_one_million_tokens_is_40_units(self) -> None:
        assert units_required_for_tokens(1_000_000) == 40

    def test_ten_million_tokens_is_400_units_no_cap(self) -> None:
        result = units_required_for_tokens(10_000_000)
        assert result == 400
        assert result == math.ceil(10_000_000 / _TOKENS_PER_UNIT)

    def test_arbitrarily_large_token_count_matches_formula(self) -> None:
        for n in [500_000, 1_000_000, 5_000_000, 10_000_000, 100_000_000]:
            expected = math.ceil(n / _TOKENS_PER_UNIT)
            assert units_required_for_tokens(n) == expected


# ===========================================================================
# Section 4 — UnitWallet.consume_units_for_tokens() boundary conditions
# ===========================================================================


class TestConsumeUnitsForTokens:
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
        txn = wallet.consume_units_for_tokens(token_count=37_500, source="usage_metering", reference_id="ref-meta")
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
        txn = wallet.consume_units_for_tokens(token_count=25_000, source="usage_metering", reference_id="ref-abc")
        assert txn.reference_id == "ref-abc"

    def test_large_token_count_consumes_correct_units(self) -> None:
        wallet = self._funded_wallet(units=100)
        txn = wallet.consume_units_for_tokens(token_count=1_000_000, source="usage_metering")
        assert txn.units == 40
        assert wallet.balance_units == 60

    def test_large_token_count_insufficient_error_carries_need(self) -> None:
        wallet = UnitWallet(owner_id="owner-large-broke")
        wallet.purchase_units(units=0, source="stripe_checkout", reference_id="chk-lb")
        with pytest.raises(InsufficientUnitsError) as exc_info:
            wallet.consume_units_for_tokens(token_count=1_000_000, source="usage_metering")
        err = exc_info.value
        assert err.need == 40
        assert err.have == 0


# ===========================================================================
# Section 5 — MemoryUnitWalletRepository round-trip
# ===========================================================================


class TestMemoryRepository:
    """
    Direct repo layer tests: upsert_wallet/fetch_wallet round-trip,
    fetch_wallet returns None for unknown owner, append_ledger_entry/
    fetch_ledger_entries round-trip with limit enforcement.
    """

    def _make_wallet(self, owner: str = "owner-repo-001") -> RegistryUnitWallet:
        return RegistryUnitWallet(
            wallet_id=f"wallet-{uuid.uuid4().hex[:8]}",
            owner_key=owner,
        )

    def _make_entry(self, wallet: RegistryUnitWallet, idx: int = 0) -> RegistryUnitLedgerEntry:
        return RegistryUnitLedgerEntry(
            entry_id=f"entry-{uuid.uuid4().hex}",
            wallet_id=wallet.wallet_id,
            owner_key=wallet.owner_key,
            entry_type="credit",
            units=1,
            balance_after=idx + 1,
        )

    def test_upsert_then_fetch_returns_wallet(self) -> None:
        repo = MemoryUnitWalletRepository()
        wallet = self._make_wallet("owner-rt-001")
        repo.upsert_wallet(wallet)
        fetched = repo.fetch_wallet(owner_key="owner-rt-001")
        assert fetched is not None
        assert fetched.wallet_id == wallet.wallet_id
        assert fetched.owner_key == "owner-rt-001"

    def test_fetch_wallet_returns_none_for_unknown_owner(self) -> None:
        repo = MemoryUnitWalletRepository()
        assert repo.fetch_wallet(owner_key="ghost-owner-xyz") is None

    def test_upsert_overwrites_existing_wallet(self) -> None:
        repo = MemoryUnitWalletRepository()
        wallet = self._make_wallet("owner-upsert-001")
        repo.upsert_wallet(wallet)
        updated = RegistryUnitWallet(
            wallet_id=wallet.wallet_id,
            owner_key=wallet.owner_key,
            balance_units=999,
        )
        repo.upsert_wallet(updated)
        fetched = repo.fetch_wallet(owner_key="owner-upsert-001")
        assert fetched is not None
        assert fetched.balance_units == 999

    def test_append_then_fetch_ledger_entries_round_trip(self) -> None:
        repo = MemoryUnitWalletRepository()
        wallet = self._make_wallet("owner-ledger-001")
        repo.upsert_wallet(wallet)
        entries = [self._make_entry(wallet, i) for i in range(5)]
        for e in entries:
            repo.append_ledger_entry(e)
        fetched = repo.fetch_ledger_entries(owner_key="owner-ledger-001")
        assert len(fetched) == 5
        fetched_ids = [e.entry_id for e in fetched]
        for e in entries:
            assert e.entry_id in fetched_ids

    def test_fetch_ledger_entries_empty_for_unknown_owner(self) -> None:
        repo = MemoryUnitWalletRepository()
        assert repo.fetch_ledger_entries(owner_key="unknown-ledger-owner") == []

    def test_fetch_ledger_entries_limit_respected(self) -> None:
        repo = MemoryUnitWalletRepository()
        wallet = self._make_wallet("owner-limit-001")
        repo.upsert_wallet(wallet)
        for i in range(10):
            repo.append_ledger_entry(self._make_entry(wallet, i))
        fetched = repo.fetch_ledger_entries(owner_key="owner-limit-001", limit=3)
        assert len(fetched) <= 3

    def test_fetch_ledger_entries_filters_by_owner(self) -> None:
        repo = MemoryUnitWalletRepository()
        wallet_a = self._make_wallet("owner-filter-a")
        wallet_b = self._make_wallet("owner-filter-b")
        repo.upsert_wallet(wallet_a)
        repo.upsert_wallet(wallet_b)
        repo.append_ledger_entry(self._make_entry(wallet_a))
        repo.append_ledger_entry(self._make_entry(wallet_b))
        fetched = repo.fetch_ledger_entries(owner_key="owner-filter-a")
        assert all(e.owner_key == "owner-filter-a" for e in fetched)


# ===========================================================================
# Section 6 — UnitWalletRegistry operations
# ===========================================================================


class TestUnitWalletRegistry:
    """
    Registry-layer tests: get_or_create_wallet idempotency, credit_units,
    debit_units, refund_units, get_wallet returns None for unknown owner,
    list_ledger_entries insertion order.
    """

    def test_get_or_create_wallet_creates_and_caches(self) -> None:
        registry = UnitWalletRegistry()
        w1 = registry.get_or_create_wallet(owner_key="owner-gc-001")
        w2 = registry.get_or_create_wallet(owner_key="owner-gc-001")
        assert w1.wallet_id == w2.wallet_id

    def test_get_wallet_returns_none_for_unknown_owner(self) -> None:
        registry = UnitWalletRegistry()
        assert registry.get_wallet("ghost-owner-registry-xyz") is None

    def test_credit_units_increases_balance(self) -> None:
        registry = UnitWalletRegistry()
        registry.credit_units(owner_key="owner-credit-001", units=100)
        wallet = registry.get_wallet("owner-credit-001")
        assert wallet is not None
        assert wallet.balance_units == 100

    def test_debit_units_decreases_balance(self) -> None:
        registry = UnitWalletRegistry()
        registry.credit_units(owner_key="owner-debit-001", units=50)
        registry.debit_units(owner_key="owner-debit-001", units=20)
        wallet = registry.get_wallet("owner-debit-001")
        assert wallet is not None
        assert wallet.balance_units == 30

    def test_debit_units_raises_on_zero_balance(self) -> None:
        registry = UnitWalletRegistry()
        registry.get_or_create_wallet(owner_key="owner-zero-001")
        with pytest.raises(InsufficientUnitsError):
            registry.debit_units(owner_key="owner-zero-001", units=1)

    def test_refund_units_increments_balance(self) -> None:
        registry = UnitWalletRegistry()
        registry.credit_units(owner_key="owner-refund-001", units=100)
        registry.debit_units(owner_key="owner-refund-001", units=50)
        registry.refund_units(owner_key="owner-refund-001", units=25)
        wallet = registry.get_wallet("owner-refund-001")
        assert wallet is not None
        assert wallet.balance_units == 75

    def test_refund_units_increments_total_refunded(self) -> None:
        registry = UnitWalletRegistry()
        registry.credit_units(owner_key="owner-refund-002", units=100)
        registry.debit_units(owner_key="owner-refund-002", units=50)
        registry.refund_units(owner_key="owner-refund-002", units=30)
        wallet = registry.get_wallet("owner-refund-002")
        assert wallet is not None
        assert wallet.total_refunded_units == 30

    def test_list_ledger_entries_insertion_order(self) -> None:
        """Entries must be returned in the order they were appended."""
        registry = UnitWalletRegistry()
        owner = "owner-order-001"
        registry.credit_units(owner_key=owner, units=100)
        registry.debit_units(owner_key=owner, units=10)
        registry.refund_units(owner_key=owner, units=5)
        entries = registry.list_ledger_entries(owner_key=owner)
        types = [e.entry_type for e in entries]
        assert types == ["credit", "debit", "refund"]

    def test_list_ledger_entries_returns_empty_for_unknown_owner(self) -> None:
        registry = UnitWalletRegistry()
        assert registry.list_ledger_entries(owner_key="ghost-ledger-xyz") == []

    def test_revoke_units_for_checkout_claws_back_once(self) -> None:
        registry = UnitWalletRegistry()
        owner = "owner-revoke-001"
        registry.credit_units(owner_key=owner, units=100, metadata={"checkout_session_id": "cs_revoke_001"})
        registry.debit_units(owner_key=owner, units=20)
        revoked = registry.revoke_units_for_checkout(owner_key=owner, checkout_session_id="cs_revoke_001")
        wallet = registry.get_wallet(owner)
        assert revoked == 80
        assert wallet is not None
        assert wallet.balance_units == 0
        assert registry.revoke_units_for_checkout(owner_key=owner, checkout_session_id="cs_revoke_001") == 0

    def test_revoke_purchase_units_floors_at_zero_and_links_purchase(self) -> None:
        registry = UnitWalletRegistry()
        owner = "owner-revoke-purchase-001"
        registry.credit_units(owner_key=owner, units=30, metadata={"checkout_session_id": "cs_purchase_001"})
        revoked = registry.revoke_purchase_units(owner_key=owner, purchase_reference="cs_purchase_001", units=50)
        wallet = registry.get_wallet(owner)
        assert revoked == 30
        assert wallet is not None
        assert wallet.balance_units == 0
        assert wallet.total_consumed_units == 0
        revoke_entries = [entry for entry in registry.list_ledger_entries(owner_key=owner, limit=10) if entry.entry_type == "refund_revoke"]
        assert len(revoke_entries) == 1
        assert revoke_entries[0].units == 30
        assert revoke_entries[0].purchase_id == "cs_purchase_001"
        assert revoke_entries[0].checkout_session_id == "cs_purchase_001"
        assert registry.revoke_purchase_units(owner_key=owner, purchase_reference="cs_purchase_001", units=50) == 0

    def test_revoke_units_for_refund_matches_payment_intent_and_invoice(self) -> None:
        registry = UnitWalletRegistry()
        owner = "owner-revoke-refund-001"
        registry.credit_units(
            owner_key=owner,
            units=40,
            metadata={"checkout_session_id": "cs_refund_001", "payment_intent": "pi_refund_001"},
        )
        registry.credit_units(
            owner_key=owner,
            units=60,
            metadata={"purchase_reference": "in_refund_001", "invoice_id": "in_refund_001"},
        )
        registry.debit_units(owner_key=owner, units=30)
        revoked = registry.revoke_units_for_refund(
            [owner, "ghost-refund-owner-001"],
            payment_intent="pi_refund_001",
            invoice_id="in_refund_001",
        )
        wallet = registry.get_wallet(owner)
        assert revoked == {"cs_refund_001": 40, "in_refund_001": 30}
        assert wallet is not None
        assert wallet.balance_units == 0
        assert registry.get_wallet("ghost-refund-owner-001") is None
        assert registry.revoke_units_for_refund([owner], payment_intent="pi_refund_001", invoice_id="in_refund_001") == {}

    def test_debit_units_for_install_key_tracks_owner_key_program_and_metadata(self) -> None:
        registry = UnitWalletRegistry()
        registry.credit_units(owner_key="owner-install-metadata", units=25)

        _, usage, ledger_entry = registry.debit_units_for_install_key(
            owner_key="owner-install-metadata",
            key_id="key_install_001",
            program="openclaw",
            units=7,
            payment_id="pay_123",
            action_type="prompt",
            metadata={"source": "runtime"},
        )

        wallet = registry.get_wallet("owner-install-metadata")
        assert wallet is not None
        assert wallet.total_consumed_units == 7
        assert wallet.install_key_usage["key_install_001"].owner_key == "owner-install-metadata"
        assert wallet.install_key_usage["key_install_001"].program == "openclaw"
        assert wallet.install_key_usage["key_install_001"].metadata["owner_key"] == "owner-install-metadata"
        assert wallet.install_key_usage["key_install_001"].metadata["key_id"] == "key_install_001"
        assert wallet.install_key_usage["key_install_001"].metadata["program"] == "openclaw"
        assert wallet.install_key_usage["key_install_001"].metadata["payment_id"] == "pay_123"
        assert wallet.install_key_usage["key_install_001"].metadata["payment_id"] == "pay_123"
        assert wallet.install_key_usage["key_install_001"].metadata["action_type"] == "prompt"
        assert usage.metadata["source"] == "runtime"
        assert ledger_entry.metadata["owner_key"] == "owner-install-metadata"
        assert ledger_entry.metadata["key_id"] == "key_install_001"
        assert ledger_entry.metadata["program"] == "openclaw"
        assert ledger_entry.metadata["payment_id"] == "pay_123"
        assert ledger_entry.metadata["action_type"] == "prompt"

    def test_install_key_usage_summary_exposes_balance_and_consumed_units(self) -> None:
        wallet = UnitWallet(owner_id="owner-install-summary")
        wallet.purchase_units(units=40, source="stripe_checkout", reference_id="checkout-a")
        wallet.consume_units_for_install_key(
            key_id="key_summary_001",
            program="claude_code",
            units=5,
            payment_id="pay_summary",
            action_type="tool_call",
            metadata={"source": "guard"},
        )

        summary = wallet.get_key_usage_summary("key_summary_001")
        assert summary["owner_key"] == "owner-install-summary"
        assert summary["wallet_balance_units"] == 35
        assert summary["total_consumed_units"] == 5
        assert summary["install_key_usage"]["key_summary_001"]["program"] == "claude_code"


# ===========================================================================
# Section 7 — UnitWalletRegistry.debit_units_for_tokens() boundary conditions
# ===========================================================================


class TestRegistryDebitUnitsForTokens:
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
        registry.debit_units_for_tokens(owner_key=owner, token_count=37_500, metadata={"route": "/guard/execute"})
        entries = registry.list_ledger_entries(owner_key=owner)
        debit_entry = next(e for e in entries if e.entry_type == "debit")
        assert debit_entry.metadata["token_count"] == 37_500
        assert debit_entry.metadata["tokens_per_unit"] == _TOKENS_PER_UNIT
        assert debit_entry.metadata["units_required"] == 2

    def test_caller_metadata_merged_into_ledger(self) -> None:
        owner = "owner-reg-meta-002"
        registry = self._registry_with_balance(owner, _PKG_ENTERPRISE_UNITS)
        registry.debit_units_for_tokens(owner_key=owner, token_count=25_000, metadata={"pipeline": "agent-v2"})
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

    def test_insufficient_error_carries_have_need_owner_key(self) -> None:
        owner = "owner-reg-err-attrs"
        registry = self._registry_with_balance(owner, 10)
        with pytest.raises(InsufficientUnitsError) as exc_info:
            registry.debit_units(owner_key=owner, units=99)
        err = exc_info.value
        assert err.have == 10
        assert err.need == 99
        assert err.owner_key == owner

    def test_large_token_count_computes_40_units_and_raises_with_need(self) -> None:
        owner = "owner-reg-large-broke"
        registry = UnitWalletRegistry()
        registry.get_or_create_wallet(owner_key=owner)
        with pytest.raises(InsufficientUnitsError) as exc_info:
            registry.debit_units_for_tokens(owner_key=owner, token_count=1_000_000)
        err = exc_info.value
        assert err.need == 40
        assert err.have == 0

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


# ===========================================================================
# Section 8 — MemoryUnitWalletRepository ledger trim (_LEDGER_MAX_SIZE)
# ===========================================================================


class TestMemoryLedgerTrim:
    def test_ledger_trim_at_overflow(self) -> None:
        from app.core.unit_wallet import _LEDGER_MAX_SIZE  # type: ignore[attr-defined]

        repo = MemoryUnitWalletRepository()
        wallet = RegistryUnitWallet(wallet_id="wallet-trim-test", owner_key="owner-trim")
        repo.upsert_wallet(wallet)

        for i in range(_LEDGER_MAX_SIZE + 50):
            repo.append_ledger_entry(
                RegistryUnitLedgerEntry(
                    entry_id=f"ledger_{uuid.uuid4().hex}",
                    wallet_id=wallet.wallet_id,
                    owner_key=wallet.owner_key,
                    entry_type="credit",
                    units=1,
                    balance_after=i + 1,
                )
            )

        assert len(repo._ledger) <= _LEDGER_MAX_SIZE

    def test_ledger_below_max_is_not_trimmed(self) -> None:
        from app.core.unit_wallet import _LEDGER_MAX_SIZE  # type: ignore[attr-defined]

        repo = MemoryUnitWalletRepository()
        wallet = RegistryUnitWallet(wallet_id="wallet-notrim-test", owner_key="owner-notrim")
        repo.upsert_wallet(wallet)

        count = min(10, _LEDGER_MAX_SIZE - 1)
        for i in range(count):
            repo.append_ledger_entry(
                RegistryUnitLedgerEntry(
                    entry_id=f"ledger_{uuid.uuid4().hex}",
                    wallet_id=wallet.wallet_id,
                    owner_key=wallet.owner_key,
                    entry_type="credit",
                    units=1,
                    balance_after=i + 1,
                )
            )

        assert len(repo._ledger) == count


# ===========================================================================
# Section 9 — UnitWalletRegistry cache eviction (_WALLET_CACHE_MAX)
# ===========================================================================


class TestRegistryCacheEviction:
    def test_cache_eviction_does_not_lose_wallet_from_persistence(self) -> None:
        from app.core.unit_wallet import _WALLET_CACHE_MAX  # type: ignore[attr-defined]

        registry = UnitWalletRegistry()
        overflow_count = _WALLET_CACHE_MAX + 10
        owners = [f"owner-evict-{i:05d}" for i in range(overflow_count)]
        for owner in owners:
            registry.credit_units(owner_key=owner, units=1)

        first_owner = owners[0]
        wallet = registry.get_wallet(first_owner)
        assert wallet is not None
        assert wallet.owner_key == first_owner
        assert wallet.balance_units == 1

    def test_cache_size_bounded_after_overflow(self) -> None:
        from app.core.unit_wallet import _WALLET_CACHE_MAX  # type: ignore[attr-defined]

        registry = UnitWalletRegistry()
        overflow_count = _WALLET_CACHE_MAX + 20
        for i in range(overflow_count):
            registry.get_or_create_wallet(owner_key=f"owner-cache-{i:05d}")

        assert len(registry._wallets) <= _WALLET_CACHE_MAX
