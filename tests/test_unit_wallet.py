from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.unit_wallet import (
    InsufficientUnitsError,
    UnitLedgerEntry,
    UnitWallet,
    UnitWalletTransaction,
)


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
        units=250,
        source="stripe_checkout",
        reference_id="checkout-001",
        metadata={"plan": "starter"},
    )

    assert isinstance(transaction, UnitWalletTransaction)
    assert transaction.owner_id == "owner-001"
    assert transaction.transaction_type == "purchase"
    assert transaction.units == 250
    assert transaction.source == "stripe_checkout"
    assert transaction.reference_id == "checkout-001"
    assert transaction.metadata == {"plan": "starter"}

    assert wallet.balance_units == 250
    assert wallet.total_purchased_units == 250
    assert wallet.total_consumed_units == 0
    assert wallet.total_refunded_units == 0
    assert len(wallet.transactions) == 1


def test_consume_units_reduces_balance_and_increases_consumed_total() -> None:
    wallet = UnitWallet(owner_id="owner-001")
    wallet.purchase_units(units=300, source="stripe_checkout", reference_id="checkout-001")

    transaction = wallet.consume_units(
        units=75,
        source="usage_metering",
        reference_id="usage-001",
        metadata={"route": "/guard/execute"},
    )

    assert isinstance(transaction, UnitWalletTransaction)
    assert transaction.transaction_type == "consume"
    assert transaction.units == 75
    assert transaction.source == "usage_metering"
    assert transaction.reference_id == "usage-001"
    assert transaction.metadata == {"route": "/guard/execute"}

    assert wallet.balance_units == 225
    assert wallet.total_purchased_units == 300
    assert wallet.total_consumed_units == 75
    assert wallet.total_refunded_units == 0
    assert len(wallet.transactions) == 2


def test_refund_units_increases_balance_and_refunded_total() -> None:
    wallet = UnitWallet(owner_id="owner-001")
    wallet.purchase_units(units=300, source="stripe_checkout", reference_id="checkout-001")
    wallet.consume_units(units=100, source="usage_metering", reference_id="usage-001")

    transaction = wallet.refund_units(
        units=25,
        source="manual_adjustment",
        reference_id="refund-001",
        metadata={"reason": "support_credit"},
    )

    assert isinstance(transaction, UnitWalletTransaction)
    assert transaction.transaction_type == "refund"
    assert transaction.units == 25
    assert transaction.source == "manual_adjustment"
    assert transaction.reference_id == "refund-001"
    assert transaction.metadata == {"reason": "support_credit"}

    assert wallet.balance_units == 225
    assert wallet.total_purchased_units == 300
    assert wallet.total_consumed_units == 100
    assert wallet.total_refunded_units == 25
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

    purchase = wallet.purchase_units(units=100, source="stripe_checkout", reference_id="checkout-001")
    consume = wallet.consume_units(units=20, source="usage_metering", reference_id="usage-001")
    refund = wallet.refund_units(units=5, source="manual_adjustment", reference_id="refund-001")

    assert wallet.transactions == [purchase, consume, refund]


def test_ledger_entry_can_wrap_transaction_snapshot() -> None:
    transaction = UnitWalletTransaction(
        transaction_id="txn-001",
        owner_id="owner-001",
        transaction_type="purchase",
        units=150,
        balance_after=150,
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
    assert entry.transaction.balance_after == 150
    assert entry.transaction.metadata == {"plan": "starter"}
