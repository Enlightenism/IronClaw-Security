from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any


class InsufficientUnitsError(ValueError):
    pass


@dataclass
class UnitWalletTransaction:
    transaction_id: str
    owner_id: str
    transaction_type: str
    units: int
    balance_after: int
    source: str
    reference_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class UnitLedgerEntry:
    owner_id: str
    transaction: UnitWalletTransaction
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class UnitWallet:
    owner_id: str
    balance_units: int = 0
    total_purchased_units: int = 0
    total_consumed_units: int = 0
    total_refunded_units: int = 0
    transactions: list[UnitWalletTransaction] = field(default_factory=list)

    def purchase_units(
        self,
        units: int,
        source: str,
        reference_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> UnitWalletTransaction:
        safe_units = max(0, int(units))
        self.balance_units += safe_units
        self.total_purchased_units += safe_units
        transaction = UnitWalletTransaction(
            transaction_id=f"txn_{len(self.transactions) + 1}",
            owner_id=self.owner_id,
            transaction_type="purchase",
            units=safe_units,
            balance_after=self.balance_units,
            source=source,
            reference_id=reference_id,
            metadata=metadata or {},
        )
        self.transactions.append(transaction)
        return transaction

    def consume_units(
        self,
        units: int,
        source: str,
        reference_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> UnitWalletTransaction:
        safe_units = max(0, int(units))
        if safe_units > self.balance_units:
            raise InsufficientUnitsError("Insufficient protection units")
        self.balance_units -= safe_units
        self.total_consumed_units += safe_units
        transaction = UnitWalletTransaction(
            transaction_id=f"txn_{len(self.transactions) + 1}",
            owner_id=self.owner_id,
            transaction_type="consume",
            units=safe_units,
            balance_after=self.balance_units,
            source=source,
            reference_id=reference_id,
            metadata=metadata or {},
        )
        self.transactions.append(transaction)
        return transaction

    def refund_units(
        self,
        units: int,
        source: str,
        reference_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> UnitWalletTransaction:
        safe_units = max(0, int(units))
        self.balance_units += safe_units
        self.total_refunded_units += safe_units
        transaction = UnitWalletTransaction(
            transaction_id=f"txn_{len(self.transactions) + 1}",
            owner_id=self.owner_id,
            transaction_type="refund",
            units=safe_units,
            balance_after=self.balance_units,
            source=source,
            reference_id=reference_id,
            metadata=metadata or {},
        )
        self.transactions.append(transaction)
        return transaction


@dataclass
class RegistryUnitWallet:
    wallet_id: str
    owner_key: str
    balance_units: int = 0
    total_purchased_units: int = 0
    total_consumed_units: int = 0
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RegistryUnitLedgerEntry:
    entry_id: str
    wallet_id: str
    owner_key: str
    entry_type: str
    units: int
    balance_after: int
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


class UnitWalletRegistry:
    """
    In-memory prepaid unit wallet registry.

    This supports:
    - creating or resolving a wallet for an owner,
    - crediting units after a package purchase,
    - debiting units as protection events are consumed,
    - returning a compact ledger for UI and billing routes.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._wallets: dict[str, RegistryUnitWallet] = {}
        self._wallets_by_owner: dict[str, str] = {}
        self._ledger: list[RegistryUnitLedgerEntry] = []

    def get_or_create_wallet(
        self,
        owner_key: str,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        normalized_owner = owner_key.strip().lower()

        with self._lock:
            wallet_id = self._wallets_by_owner.get(normalized_owner)
            if wallet_id is not None:
                return self._wallets[wallet_id]

            wallet_id = f"wallet_{len(self._wallets) + 1}"
            wallet = RegistryUnitWallet(
                wallet_id=wallet_id,
                owner_key=normalized_owner,
                metadata=metadata or {},
            )
            self._wallets[wallet_id] = wallet
            self._wallets_by_owner[normalized_owner] = wallet_id
            return wallet

    def credit_units(
        self,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        safe_units = max(0, int(units))
        wallet = self.get_or_create_wallet(owner_key=owner_key)

        with self._lock:
            wallet.balance_units += safe_units
            wallet.total_purchased_units += safe_units
            wallet.updated_at = datetime.now(UTC)

            self._ledger.append(
                RegistryUnitLedgerEntry(
                    entry_id=f"ledger_{len(self._ledger) + 1}",
                    wallet_id=wallet.wallet_id,
                    owner_key=wallet.owner_key,
                    entry_type="credit",
                    units=safe_units,
                    balance_after=wallet.balance_units,
                    metadata=metadata or {},
                )
            )
            return wallet

    def debit_units(
        self,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        safe_units = max(0, int(units))
        wallet = self.get_or_create_wallet(owner_key=owner_key)

        with self._lock:
            if safe_units > wallet.balance_units:
                raise InsufficientUnitsError("Insufficient protection units")

            wallet.balance_units -= safe_units
            wallet.total_consumed_units += safe_units
            wallet.updated_at = datetime.now(UTC)

            self._ledger.append(
                RegistryUnitLedgerEntry(
                    entry_id=f"ledger_{len(self._ledger) + 1}",
                    wallet_id=wallet.wallet_id,
                    owner_key=wallet.owner_key,
                    entry_type="debit",
                    units=safe_units,
                    balance_after=wallet.balance_units,
                    metadata=metadata or {},
                )
            )
            return wallet

    def get_wallet(self, owner_key: str) -> RegistryUnitWallet | None:
        normalized_owner = owner_key.strip().lower()
        with self._lock:
            wallet_id = self._wallets_by_owner.get(normalized_owner)
            if wallet_id is None:
                return None
            return self._wallets[wallet_id]

    def list_ledger_entries(
        self,
        owner_key: str | None = None,
        limit: int = 100,
    ) -> list[RegistryUnitLedgerEntry]:
        safe_limit = max(1, min(int(limit), 500))
        normalized_owner = owner_key.strip().lower() if owner_key else None

        with self._lock:
            entries = self._ledger
            if normalized_owner is not None:
                entries = [entry for entry in entries if entry.owner_key == normalized_owner]
            return list(entries[-safe_limit:])


_unit_wallet_registry = UnitWalletRegistry()


def get_unit_wallet_registry() -> UnitWalletRegistry:
    return _unit_wallet_registry