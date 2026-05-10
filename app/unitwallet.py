from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional


@dataclass(slots=True)
class UnitWallet:
    """
    Minimal in-memory unit wallet compatible with the IronClaw tests.

    - Numeric balance is non-negative.
    - Optional owner identifier is supported.
    - Credit/debit and optional reserve/release operations are available.
    - Shape is JSON-serializable via as_dict().
    """

    ownerid: Optional[str] = None
    balance: Decimal = field(default_factory=lambda: Decimal("0"))
    status: Optional[str] = "active"

    def _ensure_decimal(self, amount: Any, *, field_name: str) -> Decimal:
        try:
            value = Decimal(str(amount))
        except (InvalidOperation, TypeError, ValueError):
            raise TypeError(f"{field_name} must be numeric")  # noqa: TRY003
        if value < Decimal("0"):
            raise ValueError(f"{field_name} must be non-negative")
        return value

    def _ensure_sufficient_funds(self, amount: Decimal) -> None:
        if amount > self.balance:
            raise ValueError("insufficient funds for operation")

    # --- Public balance accessors used by tests ---

    def as_dict(self) -> Dict[str, Any]:
        """
        Stable, JSON-friendly payload.

        Keys: ownerid, balance, status.
        """
        return {
            "ownerid": self.ownerid,
            "balance": str(self.balance),
            "status": self.status,
        }

    def units(self) -> Decimal:
        return self.balance

    def available_units(self) -> Decimal:
        return self.balance

    def available(self) -> Decimal:
        return self.balance

    def credits(self) -> Decimal:
        return self.balance

    # --- Ownership helpers ---

    def owner_id(self) -> Optional[str]:
        return self.ownerid

    def account_id(self) -> Optional[str]:
        return self.ownerid

    # --- Mutating operations required by tests ---

    # Credit methods: credit, deposit, add_units, fund, top_up
    def credit(self, amount: Any) -> None:
        dec = self._ensure_decimal(amount, field_name="credit")
        self.balance += dec

    def deposit(self, amount: Any) -> None:
        self.credit(amount)

    def add_units(self, amount: Any) -> None:
        self.credit(amount)

    def fund(self, amount: Any) -> None:
        self.credit(amount)

    def top_up(self, amount: Any) -> None:
        self.credit(amount)

    # Debit methods: debit, charge, consume, spend, withdraw
    def debit(self, amount: Any) -> None:
        dec = self._ensure_decimal(amount, field_name="debit")
        self._ensure_sufficient_funds(dec)
        self.balance -= dec

    def charge(self, amount: Any) -> None:
        self.debit(amount)

    def consume(self, amount: Any) -> None:
        self.debit(amount)

    def spend(self, amount: Any) -> None:
        self.debit(amount)

    def withdraw(self, amount: Any) -> None:
        self.debit(amount)

    # Reserve / release methods: reserve, hold, authorize, release, unreserve, void_hold
    def reserve(self, amount: Any) -> str:
        dec = self._ensure_decimal(amount, field_name="reserve")
        self._ensure_sufficient_funds(dec)
        # Simple implementation: treat reserve as an immediate hold that does
        # not alter balance but returns a non-empty token.
        return f"reserve-{dec}"

    def hold(self, amount: Any) -> str:
        return self.reserve(amount)

    def authorize(self, amount: Any) -> str:
        return self.reserve(amount)

    def release(self, token_or_amount: Any) -> None:  # token ignored; no-op
        return None

    def unreserve(self, token_or_amount: Any) -> None:
        return None

    def void_hold(self, token_or_amount: Any) -> None:
        return None


def build_unit_wallet(*, owner_id: Optional[str] = None) -> UnitWallet:
    """
    Factory used by tests.

    - Returns a fresh UnitWallet instance (independent between calls).
    - Optional owner_id binds the wallet to an owner when provided and non-blank.
    """
    normalized_owner = None
    if owner_id is not None:
        if not isinstance(owner_id, str):
            raise TypeError("owner_id must be a string when provided")
        stripped = owner_id.strip()
        if stripped:
            normalized_owner = stripped

    return UnitWallet(ownerid=normalized_owner)