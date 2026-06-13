from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import math
import os
from threading import Lock
from typing import Any
import uuid

logger = logging.getLogger(__name__)

__all__ = [
    "TOKEN_CHUNK_SIZE",
    "ORG_KEY_PREFIX",
    "is_org_key",
    "InsufficientUnitsError",
    "units_required_for_tokens",
    "UNIT_PACKAGE_CATALOG",
    "UnitWalletTransaction",
    "UnitLedgerEntry",
    "UnitWallet",
    "RegistryUnitWallet",
    "RegistryUnitLedgerEntry",
    "SupabaseUnitWalletRepository",
    "MemoryUnitWalletRepository",
    "UnitWalletRegistry",
    "get_unit_wallet_registry",
]

# ---------------------------------------------------------------------------
# Org-key convention
#
# When owner_key is prefixed with ORG_KEY_PREFIX ("ic_org_"), the wallet is
# org-scoped: all team members who share the same org key consume units from
# the same wallet.  The key is typically set by the billing or auth layer as
# "ic_org_<org_id>" and passed directly into get_or_create_wallet().
#
# No wallet mechanics change — owner_key is already a freeform string.
# get_or_create_wallet() is idempotent for org keys exactly as it is for
# individual keys: first call creates the wallet, subsequent calls return the
# same wallet_id.
# ---------------------------------------------------------------------------

ORG_KEY_PREFIX: str = "ic_org_"


def is_org_key(owner_key: str) -> bool:
    """Return True if *owner_key* is an org-scoped wallet key.

    Org keys are prefixed with ORG_KEY_PREFIX (``"ic_org_"``).  All team
    members that share the same org key debit from a single shared wallet.
    """
    return owner_key.strip().lower().startswith(ORG_KEY_PREFIX)


# ---------------------------------------------------------------------------
# Structured insufficient-units exception
# ---------------------------------------------------------------------------


class InsufficientUnitsError(ValueError):
    """Raised when a wallet debit cannot be satisfied.

    Attributes:
        have      — units currently in the wallet
        need      — units required for the operation
        owner_key — normalized wallet owner key
    """

    def __init__(
        self,
        message: str = "Insufficient protection units",
        *,
        have: int = 0,
        need: int = 0,
        owner_key: str = "",
    ) -> None:
        super().__init__(message)
        self.have = int(have)
        self.need = int(need)
        self.owner_key = str(owner_key)


# ---------------------------------------------------------------------------
# Token-to-unit coverage constants
#
# Each protection unit covers one inspection window of up to TOKEN_CHUNK_SIZE
# tokens. Any request exceeding the boundary consumes one additional unit
# per additional chunk (ceiling division).  Scans are UNLIMITED — units
# auto-deduct in 25,000-token chunks with no ceiling.
#
# Coverage rule:
#   units_required = ceil(token_count / TOKEN_CHUNK_SIZE)
#
# Examples:
#   1 token       → 1 unit
#   25_000 tokens → 1 unit
#   25_001 tokens → 2 units
#   50_000 tokens → 2 units
#   50_001 tokens → 3 units
# ---------------------------------------------------------------------------

TOKEN_CHUNK_SIZE: int = 25_000


def units_required_for_tokens(token_count: int) -> int:
    """Return the number of protection units required to cover *token_count* tokens.

    Uses ceiling division so any partial chunk above a boundary consumes a
    full additional unit.  Returns 0 for non-positive token counts.
    No maximum is imposed — scans are unlimited.
    """
    if token_count <= 0:
        return 0
    return math.ceil(token_count / TOKEN_CHUNK_SIZE)


# ---------------------------------------------------------------------------
# Canonical package catalog — derived from billing.PLAN_DEFINITIONS
# Single source of truth: billing.py owns plan codes + limits + prices.
# unit_wallet.py maps them to purchasable package records.
#
# Authoritative package IDs and pricing:
#   pkg_5000   — Starter    —  5,000 units — $20.00
#   pkg_25000  — Team       — 25,000 units — $90.00
#   pkg_60000  — Enterprise — 60,000 units — $180.00
# ---------------------------------------------------------------------------


def _build_package_catalog() -> dict[str, dict[str, Any]]:
    """Derive the unit package catalog from billing.PLAN_DEFINITIONS.

    Keeps unit_wallet.py in sync with billing.py automatically.
    Falls back to hardcoded values only if billing import fails.
    """
    try:
        from app.core.billing import PLAN_DEFINITIONS

        _PKG_META: dict[str, dict[str, str]] = {
            "starter-5k": {
                "package_id": "pkg_5000",
                "name": "Starter",
                "display_label": "5,000 units — $20.00",
                "description": ("Prepaid protection units for individual builders who want guarded " "prompt handling, tool-call review, source inspection, and safe response release."),
            },
            "team-25k": {
                "package_id": "pkg_25000",
                "name": "Team",
                "display_label": "25,000 units — $90.00",
                "description": ("Prepaid protection units for teams running higher volumes of AI-assisted " "development, research, and guarded agent workflows."),
            },
            "enterprise-60k": {
                "package_id": "pkg_60000",
                "name": "Enterprise",
                "display_label": "60,000 units — $180.00",
                "description": ("Prepaid protection units for organizations protecting large-scale agent " "operations, sensitive workflows, and high-frequency prompt activity."),
            },
        }

        catalog: dict[str, dict[str, Any]] = {}
        for plan_code, plan_def in PLAN_DEFINITIONS.items():
            meta = _PKG_META.get(plan_code)
            if meta is None:
                logger.warning(
                    "unit_wallet: no package metadata for plan_code=%r — skipping",
                    plan_code,
                )
                continue
            pkg_id = meta["package_id"]
            catalog[pkg_id] = {
                "package_id": pkg_id,
                "name": meta["name"],
                "unit_amount": plan_def["unit_limit"],
                "price_usd": float(plan_def["price_usd"]),
                "display_label": meta["display_label"],
                "description": meta["description"],
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
            }
        return catalog

    except Exception:
        logger.exception(
            "unit_wallet: failed to derive catalog from billing.PLAN_DEFINITIONS; using hardcoded fallback",
        )
        return {
            "pkg_5000": {
                "package_id": "pkg_5000",
                "name": "Starter",
                "unit_amount": 5_000,
                "price_usd": 20.00,
                "display_label": "5,000 units — $20.00",
                "description": ("Prepaid protection units for individual builders who want guarded " "prompt handling, tool-call review, source inspection, and safe response release."),
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
            },
            "pkg_25000": {
                "package_id": "pkg_25000",
                "name": "Team",
                "unit_amount": 25_000,
                "price_usd": 90.00,
                "display_label": "25,000 units — $90.00",
                "description": ("Prepaid protection units for teams running higher volumes of AI-assisted " "development, research, and guarded agent workflows."),
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
            },
            "pkg_60000": {
                "package_id": "pkg_60000",
                "name": "Enterprise",
                "unit_amount": 60_000,
                "price_usd": 180.00,
                "display_label": "60,000 units — $180.00",
                "description": ("Prepaid protection units for organizations protecting large-scale agent " "operations, sensitive workflows, and high-frequency prompt activity."),
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
            },
        }


UNIT_PACKAGE_CATALOG: dict[str, dict[str, Any]] = _build_package_catalog()

# ---------------------------------------------------------------------------
# Module-level integrity assertion — catches catalog drift at startup
# ---------------------------------------------------------------------------

_EXPECTED_PACKAGES = {
    "pkg_5000": (5_000, 20.00),
    "pkg_25000": (25_000, 90.00),
    "pkg_60000": (60_000, 180.00),
}

for _pkg_id, (_expected_units, _expected_price) in _EXPECTED_PACKAGES.items():
    _entry = UNIT_PACKAGE_CATALOG.get(_pkg_id)
    assert _entry is not None, f"unit_wallet: UNIT_PACKAGE_CATALOG is missing required package {_pkg_id!r}"
    assert _entry["unit_amount"] == _expected_units, f"unit_wallet: {_pkg_id} unit_amount mismatch: got {_entry['unit_amount']}, expected {_expected_units}"
    assert _entry["price_usd"] == _expected_price, f"unit_wallet: {_pkg_id} price_usd mismatch: got {_entry['price_usd']}, expected {_expected_price}"
    assert _entry["tokens_per_unit"] == TOKEN_CHUNK_SIZE, f"unit_wallet: {_pkg_id} tokens_per_unit mismatch: got {_entry['tokens_per_unit']}, expected {TOKEN_CHUNK_SIZE}"

# ---------------------------------------------------------------------------
# In-memory cache and ledger size guards
# ---------------------------------------------------------------------------

_WALLET_CACHE_MAX: int = 5_000
_LEDGER_MAX_SIZE: int = 10_000

# ---------------------------------------------------------------------------
# Domain dataclasses
# ---------------------------------------------------------------------------


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
            transaction_id=f"txn_{uuid.uuid4().hex}",
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
            raise InsufficientUnitsError(
                "Insufficient protection units",
                have=self.balance_units,
                need=safe_units,
                owner_key=self.owner_id,
            )
        self.balance_units -= safe_units
        self.total_consumed_units += safe_units
        transaction = UnitWalletTransaction(
            transaction_id=f"txn_{uuid.uuid4().hex}",
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

    def consume_units_for_tokens(
        self,
        token_count: int,
        source: str,
        reference_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> UnitWalletTransaction:
        """Consume the correct number of units to cover *token_count* tokens.

        Calculates required units via ceiling division against TOKEN_CHUNK_SIZE
        then delegates to consume_units.  Raises InsufficientUnitsError if
        the wallet does not have enough units to cover the full token payload.
        No maximum token count is enforced — scans are unlimited.
        """
        required = units_required_for_tokens(token_count)
        combined_metadata = {
            "token_count": token_count,
            "tokens_per_unit": TOKEN_CHUNK_SIZE,
            "units_required": required,
            **(metadata or {}),
        }
        return self.consume_units(
            units=required,
            source=source,
            reference_id=reference_id,
            metadata=combined_metadata,
        )

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
            transaction_id=f"txn_{uuid.uuid4().hex}",
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
    total_refunded_units: int = 0
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


# ---------------------------------------------------------------------------
# Supabase persistence layer — only used when Supabase is configured
# ---------------------------------------------------------------------------


class SupabaseUnitWalletRepository:
    """Durable wallet + ledger persistence via Supabase.

    Table contracts expected in Supabase:
      unit_wallets  (wallet_id, owner_key, balance_units,
                     total_purchased_units, total_consumed_units,
                     total_refunded_units, updated_at, metadata)
      unit_ledger   (entry_id, wallet_id, owner_key, entry_type,
                     units, balance_after, created_at, metadata)
    """

    _WALLETS_TABLE = "unit_wallets"
    _LEDGER_TABLE = "unit_ledger"

    def __init__(self) -> None:
        from app.supabaseclient import supabaseclient

        self._client = supabaseclient()

    def upsert_wallet(self, wallet: RegistryUnitWallet) -> None:
        self._client.table(self._WALLETS_TABLE).upsert(
            {
                "wallet_id": wallet.wallet_id,
                "owner_key": wallet.owner_key,
                "balance_units": wallet.balance_units,
                "total_purchased_units": wallet.total_purchased_units,
                "total_consumed_units": wallet.total_consumed_units,
                "total_refunded_units": wallet.total_refunded_units,
                "updated_at": wallet.updated_at.isoformat(),
                "metadata": wallet.metadata,
            },
            on_conflict="wallet_id",
        ).execute()

    def fetch_wallet(self, owner_key: str) -> RegistryUnitWallet | None:
        result = self._client.table(self._WALLETS_TABLE).select("*").eq("owner_key", owner_key).limit(1).execute()
        if not result.data:
            return None
        row = result.data[0]
        return RegistryUnitWallet(
            wallet_id=row["wallet_id"],
            owner_key=row["owner_key"],
            balance_units=row["balance_units"],
            total_purchased_units=row["total_purchased_units"],
            total_consumed_units=row["total_consumed_units"],
            total_refunded_units=row.get("total_refunded_units", 0),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=row.get("metadata") or {},
        )

    def append_ledger_entry(self, entry: RegistryUnitLedgerEntry) -> None:
        self._client.table(self._LEDGER_TABLE).insert(
            {
                "entry_id": entry.entry_id,
                "wallet_id": entry.wallet_id,
                "owner_key": entry.owner_key,
                "entry_type": entry.entry_type,
                "units": entry.units,
                "balance_after": entry.balance_after,
                "created_at": entry.created_at.isoformat(),
                "metadata": entry.metadata,
            }
        ).execute()

    def fetch_ledger_entries(
        self,
        owner_key: str | None = None,
        limit: int = 100,
    ) -> list[RegistryUnitLedgerEntry]:
        safe_limit = max(1, min(int(limit), 500))
        query = self._client.table(self._LEDGER_TABLE).select("*").order("created_at", desc=True).limit(safe_limit)
        if owner_key is not None:
            query = query.eq("owner_key", owner_key)
        result = query.execute()
        entries: list[RegistryUnitLedgerEntry] = []
        for row in result.data or []:
            entries.append(
                RegistryUnitLedgerEntry(
                    entry_id=row["entry_id"],
                    wallet_id=row["wallet_id"],
                    owner_key=row["owner_key"],
                    entry_type=row["entry_type"],
                    units=row["units"],
                    balance_after=row["balance_after"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    metadata=row.get("metadata") or {},
                )
            )
        return list(reversed(entries))


# ---------------------------------------------------------------------------
# Pure in-memory repository — used when IRONCLAW_PERSISTENCE_MODE=memory
# or when Supabase is not configured
# ---------------------------------------------------------------------------


class MemoryUnitWalletRepository:
    """Zero-dependency in-memory backend for tests and local-first mode."""

    def __init__(self) -> None:
        self._wallets: dict[str, RegistryUnitWallet] = {}
        self._wallets_by_owner: dict[str, str] = {}
        self._ledger: list[RegistryUnitLedgerEntry] = []
        self._lock = Lock()

    def upsert_wallet(self, wallet: RegistryUnitWallet) -> None:
        with self._lock:
            self._wallets[wallet.wallet_id] = wallet
            self._wallets_by_owner[wallet.owner_key] = wallet.wallet_id

    def fetch_wallet(self, owner_key: str) -> RegistryUnitWallet | None:
        with self._lock:
            wallet_id = self._wallets_by_owner.get(owner_key)
            if wallet_id is None:
                return None
            return self._wallets[wallet_id]

    def append_ledger_entry(self, entry: RegistryUnitLedgerEntry) -> None:
        with self._lock:
            self._ledger.append(entry)
            if len(self._ledger) > _LEDGER_MAX_SIZE:
                # Trim oldest entries to stay within memory bound
                self._ledger = self._ledger[-_LEDGER_MAX_SIZE:]

    def fetch_ledger_entries(
        self,
        owner_key: str | None = None,
        limit: int = 100,
    ) -> list[RegistryUnitLedgerEntry]:
        safe_limit = max(1, min(int(limit), 500))
        with self._lock:
            entries = self._ledger if owner_key is None else [e for e in self._ledger if e.owner_key == owner_key]
            return list(entries[-safe_limit:])


# ---------------------------------------------------------------------------
# Repository factory — picks backend from env at first use
# ---------------------------------------------------------------------------


def _make_repo() -> SupabaseUnitWalletRepository | MemoryUnitWalletRepository:
    if os.environ.get("IRONCLAW_PERSISTENCE_MODE", "").lower() == "memory":
        return MemoryUnitWalletRepository()

    try:
        from app.supabaseclient import is_supabase_configured

        if not is_supabase_configured():
            logger.info("unit_wallet: Supabase not configured — using MemoryUnitWalletRepository")
            return MemoryUnitWalletRepository()

        repo = SupabaseUnitWalletRepository()
        logger.info("unit_wallet: SupabaseUnitWalletRepository initialized")
        return repo

    except Exception:
        logger.exception("unit_wallet: Supabase init failed — falling back to MemoryUnitWalletRepository")
        return MemoryUnitWalletRepository()


# ---------------------------------------------------------------------------
# Registry — in-memory cache with pluggable persistence backend
# ---------------------------------------------------------------------------


class UnitWalletRegistry:
    """Prepaid unit wallet registry with pluggable persistence backend.

    Supports:
    - creating or resolving a wallet for an owner,
    - crediting units after a package purchase,
    - debiting units as protection events are consumed,
    - debiting the correct number of units for a given token count (unlimited),
    - returning units to a wallet as a refund,
    - returning a compact ledger for UI and billing routes.

    Token scans are UNLIMITED — units auto-deduct in TOKEN_CHUNK_SIZE chunks
    with no ceiling imposed by this module.

    Org-scoped wallets
    ------------------
    owner_key is a freeform string.  When prefixed with ORG_KEY_PREFIX
    (``"ic_org_"``), the wallet is shared across an entire organization: all
    team members who pass the same org key consume units from one wallet.
    The caller (billing router, auth layer) is responsible for constructing
    the org key as ``f"ic_org_{org_id}"``.

    get_or_create_wallet() is fully idempotent for org keys — the first call
    creates the wallet and all subsequent calls return the same wallet_id,
    whether the lookup hits the in-memory cache or falls through to the
    persistence backend.  No special handling is required for org keys vs
    individual keys.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._wallets: dict[str, RegistryUnitWallet] = {}
        self._wallets_by_owner: dict[str, str] = {}
        self._repo: SupabaseUnitWalletRepository | MemoryUnitWalletRepository = _make_repo()

    def _evict_cache_if_needed(self) -> None:
        """Trim the in-memory wallet cache when it exceeds _WALLET_CACHE_MAX.

        Evicts the oldest half of entries by insertion order.
        Must be called while self._lock is held.
        """
        if len(self._wallets_by_owner) > _WALLET_CACHE_MAX:
            evict_count = _WALLET_CACHE_MAX // 2
            evict_owners = list(self._wallets_by_owner.keys())[:evict_count]
            for owner in evict_owners:
                wid = self._wallets_by_owner.pop(owner, None)
                if wid is not None:
                    self._wallets.pop(wid, None)

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

        existing = self._repo.fetch_wallet(normalized_owner)
        if existing is not None:
            with self._lock:
                self._wallets[existing.wallet_id] = existing
                self._wallets_by_owner[normalized_owner] = existing.wallet_id
                self._evict_cache_if_needed()
            return existing

        with self._lock:
            wallet_id = self._wallets_by_owner.get(normalized_owner)
            if wallet_id is not None:
                return self._wallets[wallet_id]

            new_wallet_id = f"wallet_{uuid.uuid4().hex}"
            wallet = RegistryUnitWallet(
                wallet_id=new_wallet_id,
                owner_key=normalized_owner,
                metadata=metadata or {},
            )
            self._wallets[new_wallet_id] = wallet
            self._wallets_by_owner[normalized_owner] = new_wallet_id
            self._evict_cache_if_needed()

        self._repo.upsert_wallet(wallet)
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

            entry = RegistryUnitLedgerEntry(
                entry_id=f"ledger_{uuid.uuid4().hex}",
                wallet_id=wallet.wallet_id,
                owner_key=wallet.owner_key,
                entry_type="credit",
                units=safe_units,
                balance_after=wallet.balance_units,
                metadata=metadata or {},
            )

        self._repo.upsert_wallet(wallet)
        self._repo.append_ledger_entry(entry)
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
                raise InsufficientUnitsError(
                    "Insufficient protection units",
                    have=wallet.balance_units,
                    need=safe_units,
                    owner_key=wallet.owner_key,
                )

            wallet.balance_units -= safe_units
            wallet.total_consumed_units += safe_units
            wallet.updated_at = datetime.now(UTC)

            entry = RegistryUnitLedgerEntry(
                entry_id=f"ledger_{uuid.uuid4().hex}",
                wallet_id=wallet.wallet_id,
                owner_key=wallet.owner_key,
                entry_type="debit",
                units=safe_units,
                balance_after=wallet.balance_units,
                metadata=metadata or {},
            )

        self._repo.upsert_wallet(wallet)
        self._repo.append_ledger_entry(entry)
        return wallet

    def debit_units_for_tokens(
        self,
        owner_key: str,
        token_count: int,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[RegistryUnitWallet, int]:
        """Debit the correct number of units to cover *token_count* tokens.

        Uses ceiling division against TOKEN_CHUNK_SIZE with no upper bound.
        Returns the updated wallet and the number of units actually debited.

        Raises InsufficientUnitsError (with have/need/owner_key) if the
        wallet cannot cover the full token payload.
        """
        required = units_required_for_tokens(token_count)
        combined_metadata = {
            "token_count": token_count,
            "tokens_per_unit": TOKEN_CHUNK_SIZE,
            "units_required": required,
            **(metadata or {}),
        }
        wallet = self.debit_units(
            owner_key=owner_key,
            units=required,
            metadata=combined_metadata,
        )
        return wallet, required

    def refund_units(
        self,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        """Credit units back to a wallet as a refund, tracked separately from purchases."""
        safe_units = max(0, int(units))
        wallet = self.get_or_create_wallet(owner_key=owner_key)

        with self._lock:
            wallet.balance_units += safe_units
            wallet.total_refunded_units += safe_units
            wallet.updated_at = datetime.now(UTC)

            entry = RegistryUnitLedgerEntry(
                entry_id=f"ledger_{uuid.uuid4().hex}",
                wallet_id=wallet.wallet_id,
                owner_key=wallet.owner_key,
                entry_type="refund",
                units=safe_units,
                balance_after=wallet.balance_units,
                metadata=metadata or {},
            )

        self._repo.upsert_wallet(wallet)
        self._repo.append_ledger_entry(entry)
        return wallet

    def get_wallet(self, owner_key: str) -> RegistryUnitWallet | None:
        normalized_owner = owner_key.strip().lower()
        with self._lock:
            wallet_id = self._wallets_by_owner.get(normalized_owner)
            if wallet_id is not None:
                return self._wallets[wallet_id]
        return self._repo.fetch_wallet(normalized_owner)

    def list_ledger_entries(
        self,
        owner_key: str | None = None,
        limit: int = 100,
    ) -> list[RegistryUnitLedgerEntry]:
        return self._repo.fetch_ledger_entries(owner_key=owner_key, limit=limit)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_unit_wallet_registry = UnitWalletRegistry()


def get_unit_wallet_registry() -> UnitWalletRegistry:
    return _unit_wallet_registry
