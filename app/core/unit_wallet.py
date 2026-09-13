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
    "InstallKeyUsageSource",
    "InstallKeyUsageLedgerEntry",
    "UnitWallet",
    "RegistryUnitWallet",
    "RegistryUnitLedgerEntry",
    "SupabaseUnitWalletRepository",
    "MemoryUnitWalletRepository",
    "UnitWalletRegistry",
    "get_unit_wallet_registry",
]

ORG_KEY_PREFIX: str = "ic_org_"


def _normalize_owner_key(owner_key: str) -> str:
    return str(owner_key).strip().lower()


def _is_generic_platform_credential(value: str | None) -> bool:
    if value is None:
        return False
    candidate = str(value).strip().lower()
    if not candidate:
        return False
    generic_prefixes = (
        "sk_",
        "ghp_",
        "gho_",
        "github_pat_",
        "token_",
        "secret_",
        "api_",
        "api-key",
        "api_key",
        "platform-api-key",
        "platform_api_key",
        "system-api-key",
        "system_api_key",
        "internal-platform-api-key",
        "internal_platform_api_key",
        "bearer ",
        "x-api-key",
    )
    if candidate.startswith(generic_prefixes):
        return True
    if "platform" in candidate and ("key" in candidate or "token" in candidate or "secret" in candidate):
        return True
    if "api" in candidate and "key" in candidate:
        return True
    return False


def is_org_key(owner_key: str) -> bool:
    return _normalize_owner_key(owner_key).startswith(ORG_KEY_PREFIX)


class InsufficientUnitsError(ValueError):
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


TOKEN_CHUNK_SIZE: int = 25_000


def units_required_for_tokens(token_count: int) -> int:
    if token_count <= 0:
        return 0
    return math.ceil(token_count / TOKEN_CHUNK_SIZE)


def _build_package_catalog() -> dict[str, dict[str, Any]]:
    try:
        from app.core.billing import PLAN_DEFINITIONS

        _PKG_META: dict[str, dict[str, str]] = {
            "starter-5k": {
                "package_id": "pkg_5000",
                "name": "Starter",
                "display_label": "5,000 units — $20.00",
                "description": ("Prepaid protection units for individual builders who want guarded prompt handling, tool-call review, source inspection, and safe response release."),
            },
            "team-25k": {
                "package_id": "pkg_25000",
                "name": "Team",
                "display_label": "25,000 units — $90.00",
                "description": ("Prepaid protection units for teams running higher volumes of AI-assisted development, research, and guarded agent workflows."),
            },
            "enterprise-60k": {
                "package_id": "pkg_60000",
                "name": "Enterprise",
                "display_label": "60,000 units — $180.00",
                "description": ("Prepaid protection units for organizations protecting large-scale agent operations, sensitive workflows, and high-frequency prompt activity."),
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
                "description": ("Prepaid protection units for individual builders who want guarded prompt handling, tool-call review, source inspection, and safe response release."),
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
            },
            "pkg_25000": {
                "package_id": "pkg_25000",
                "name": "Team",
                "unit_amount": 25_000,
                "price_usd": 90.00,
                "display_label": "25,000 units — $90.00",
                "description": ("Prepaid protection units for teams running higher volumes of AI-assisted development, research, and guarded agent workflows."),
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
            },
            "pkg_60000": {
                "package_id": "pkg_60000",
                "name": "Enterprise",
                "unit_amount": 60_000,
                "price_usd": 180.00,
                "display_label": "60,000 units — $180.00",
                "description": ("Prepaid protection units for organizations protecting large-scale agent operations, sensitive workflows, and high-frequency prompt activity."),
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
            },
        }


UNIT_PACKAGE_CATALOG: dict[str, dict[str, Any]] = _build_package_catalog()

_EXPECTED_PACKAGES = {
    "pkg_5000": (5_000, 20.00),
    "pkg_25000": (25_000, 90.00),
    "pkg_60000": (60_000, 180.00),
}

for _pkg_id, (_expected_units, _expected_price) in _EXPECTED_PACKAGES.items():
    _entry = UNIT_PACKAGE_CATALOG.get(_pkg_id)
    if _entry is None:
        logger.error(
            "unit_wallet: UNIT_PACKAGE_CATALOG is missing required package %r",
            _pkg_id,
        )
        raise RuntimeError(f"unit_wallet: UNIT_PACKAGE_CATALOG is missing required package {_pkg_id!r}")
    if _entry["unit_amount"] != _expected_units:
        logger.error(
            "unit_wallet: %s unit_amount mismatch: got %r, expected %r",
            _pkg_id,
            _entry["unit_amount"],
            _expected_units,
        )
        raise RuntimeError(f"unit_wallet: {_pkg_id} unit_amount mismatch: got {_entry['unit_amount']}, expected {_expected_units}")
    if _entry["price_usd"] != _expected_price:
        logger.error(
            "unit_wallet: %s price_usd mismatch: got %r, expected %r",
            _pkg_id,
            _entry["price_usd"],
            _expected_price,
        )
        raise RuntimeError(f"unit_wallet: {_pkg_id} price_usd mismatch: got {_entry['price_usd']}, expected {_expected_price}")
    if _entry["tokens_per_unit"] != TOKEN_CHUNK_SIZE:
        logger.error(
            "unit_wallet: %s tokens_per_unit mismatch: got %r, expected %r",
            _pkg_id,
            _entry["tokens_per_unit"],
            TOKEN_CHUNK_SIZE,
        )
        raise RuntimeError(f"unit_wallet: {_pkg_id} tokens_per_unit mismatch: got {_entry['tokens_per_unit']}, expected {TOKEN_CHUNK_SIZE}")

_WALLET_CACHE_MAX: int = 5_000
_LEDGER_MAX_SIZE: int = 10_000


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
class InstallKeyUsageSource:
    key_id: str
    owner_key: str
    program: str
    balance_units: int = 0
    total_consumed_units: int = 0
    total_blocked_attacks: int = 0
    total_quarantined_actions: int = 0
    units_used_today: int = 0
    units_used_this_week: int = 0
    usage_event_count: int = 0
    last_action_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    usage_by_day: dict[str, int] = field(default_factory=dict)
    usage_by_week: dict[str, int] = field(default_factory=dict)

    def _bucket_day(self, timestamp: datetime) -> str:
        return timestamp.astimezone(UTC).date().isoformat()

    def _bucket_week(self, timestamp: datetime) -> str:
        iso_year, iso_week, _ = timestamp.astimezone(UTC).isocalendar()
        return f"{iso_year}-W{iso_week:02d}"

    def register_usage_event(
        self,
        *,
        units: int,
        blocked_attack_count: int = 0,
        quarantined_count: int = 0,
        occurred_at: datetime | None = None,
    ) -> None:
        if units < 0:
            raise ValueError("units must be non-negative")
        event_time = occurred_at or datetime.now(UTC)
        self.total_consumed_units += int(units)
        self.total_blocked_attacks += int(blocked_attack_count)
        self.total_quarantined_actions += int(quarantined_count)
        self.usage_event_count += 1
        self.last_action_at = event_time

        day_key = self._bucket_day(event_time)
        self.usage_by_day[day_key] = self.usage_by_day.get(day_key, 0) + int(units)
        self.units_used_today = self.usage_by_day.get(day_key, 0)

        week_key = self._bucket_week(event_time)
        self.usage_by_week[week_key] = self.usage_by_week.get(week_key, 0) + int(units)
        self.units_used_this_week = sum(self.usage_by_week.values())

    def as_summary(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "owner_key": self.owner_key,
            "program": self.program,
            "balance_units": self.balance_units,
            "total_consumed_units": self.total_consumed_units,
            "total_blocked_attacks": self.total_blocked_attacks,
            "total_quarantined_actions": self.total_quarantined_actions,
            "blocked_or_quarantined_count": self.total_blocked_attacks + self.total_quarantined_actions,
            "units_used_today": self.units_used_today,
            "units_used_this_week": self.units_used_this_week,
            "usage_event_count": self.usage_event_count,
            "last_action_at": self.last_action_at.isoformat() if self.last_action_at else None,
            "metadata": dict(self.metadata),
        }


@dataclass
class InstallKeyUsageLedgerEntry:
    entry_id: str
    owner_key: str
    key_id: str
    program: str
    action_type: str
    units: int
    balance_after: int
    payment_id: str | None = None
    blocked_attack_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "owner_key": self.owner_key,
            "key_id": self.key_id,
            "program": self.program,
            "action_type": self.action_type,
            "units": self.units,
            "balance_after": self.balance_after,
            "payment_id": self.payment_id,
            "blocked_attack_count": self.blocked_attack_count,
            "created_at": self.created_at.isoformat(),
            "metadata": dict(self.metadata),
        }


@dataclass
class UnitWallet:
    owner_id: str
    balance_units: int = 0
    total_purchased_units: int = 0
    total_consumed_units: int = 0
    total_refunded_units: int = 0
    total_blocked_attacks: int = 0
    transactions: list[UnitWalletTransaction] = field(default_factory=list)
    usage_by_key: dict[str, InstallKeyUsageSource] = field(default_factory=dict)

    @property
    def owner_key(self) -> str:
        return self.owner_id

    @owner_key.setter
    def owner_key(self, value: str) -> None:
        self.owner_id = str(value).strip().lower()

    def as_summary(self) -> dict[str, Any]:
        return {
            "owner_key": self.owner_id,
            "balance_units": self.balance_units,
            "total_purchased_units": self.total_purchased_units,
            "total_consumed_units": self.total_consumed_units,
            "total_refunded_units": self.total_refunded_units,
            "total_blocked_attacks": self.total_blocked_attacks,
            "install_key_usage": {key: value.as_summary() for key, value in sorted(self.usage_by_key.items())},
        }

    def get_key_usage_summary(self, key_id: str | None = None) -> dict[str, Any]:
        if key_id is not None:
            usage = self.usage_by_key.get(key_id)
            return {
                "owner_key": self.owner_id,
                "wallet_balance_units": self.balance_units,
                "total_consumed_units": self.total_consumed_units,
                "total_blocked_attacks": self.total_blocked_attacks,
                "total_quarantined_actions": sum(item.total_quarantined_actions for item in self.usage_by_key.values()),
                "install_key_usage": {key_id: usage.as_summary()} if usage is not None else {},
            }

        return {
            "owner_key": self.owner_id,
            "wallet_balance_units": self.balance_units,
            "total_consumed_units": self.total_consumed_units,
            "total_blocked_attacks": self.total_blocked_attacks,
            "total_quarantined_actions": sum(item.total_quarantined_actions for item in self.usage_by_key.values()),
            "install_key_usage": {key: value.as_summary() for key, value in sorted(self.usage_by_key.items())},
        }

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

    def consume_units_for_install_key(
        self,
        *,
        key_id: str,
        program: str,
        units: int,
        source: str = "install_key",
        reference_id: str | None = None,
        payment_id: str | None = None,
        action_type: str = "prompt",
        blocked_attack_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[UnitWalletTransaction, InstallKeyUsageSource]:
        if not key_id:
            raise ValueError("key_id is required for install-key consumption")
        if not program:
            raise ValueError("program is required for install-key consumption")
        if _is_generic_platform_credential(self.owner_id):
            raise ValueError("owner_key must be a customer or org identity, not a generic platform API key")
        if _is_generic_platform_credential(str(key_id)):
            raise ValueError("key_id must be an install key identity, not a generic platform API credential")

        payload = dict(metadata or {})
        explicit_owner = str(payload.get("owner_key") or "").strip().lower()
        if explicit_owner and explicit_owner != self.owner_id:
            raise ValueError("metadata owner_key does not match the wallet owner_key for install-key usage")
        explicit_key = str(payload.get("key_id") or "").strip()
        if explicit_key and explicit_key != str(key_id):
            raise ValueError("metadata key_id does not match the install key being debited")

        canonical_metadata = {
            **payload,
            "owner_key": self.owner_id,
            "key_id": key_id,
            "program": program,
            "payment_id": payment_id,
            "action_type": action_type,
            "blocked_attack_count": int(blocked_attack_count),
            "quarantined_count": int(payload.get("quarantined_count", payload.get("quarantined_attack_count", 0))),
        }

        transaction = self.consume_units(
            units,
            source=f"{source}:{key_id}",
            reference_id=reference_id,
            metadata=canonical_metadata,
        )

        summary = self.usage_by_key.setdefault(
            key_id,
            InstallKeyUsageSource(
                key_id=key_id,
                owner_key=self.owner_id,
                program=program,
            ),
        )
        if summary.owner_key != self.owner_id:
            raise ValueError("install-key usage for a different owner_key is not allowed on this wallet")
        summary.program = program
        summary.balance_units = max(self.balance_units, 0)
        summary.metadata.update(canonical_metadata)

        quarantined_count = int(canonical_metadata.get("quarantined_count", canonical_metadata.get("quarantined_attack_count", 0)))
        summary.register_usage_event(
            units=int(transaction.units),
            blocked_attack_count=int(blocked_attack_count),
            quarantined_count=quarantined_count,
            occurred_at=transaction.created_at,
        )

        self.total_blocked_attacks += int(blocked_attack_count)
        return transaction, summary

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
    total_blocked_attacks: int = 0
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)
    install_key_usage: dict[str, InstallKeyUsageSource] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.wallet_id = str(self.wallet_id).strip()
        self.owner_key = _normalize_owner_key(self.owner_key)
        if not self.wallet_id:
            raise ValueError("wallet_id is required")
        if not self.owner_key:
            raise ValueError("owner_key is required")
        if not isinstance(self.metadata, dict):
            self.metadata = dict(self.metadata or {})
        if not isinstance(self.install_key_usage, dict):
            self.install_key_usage = {}

    def as_summary(self) -> dict[str, Any]:
        return {
            "wallet_id": self.wallet_id,
            "owner_key": self.owner_key,
            "balance_units": self.balance_units,
            "total_purchased_units": self.total_purchased_units,
            "total_consumed_units": self.total_consumed_units,
            "total_refunded_units": self.total_refunded_units,
            "total_blocked_attacks": self.total_blocked_attacks,
            "updated_at": self.updated_at.isoformat(),
            "metadata": dict(self.metadata),
            "install_key_usage": {key: value.as_summary() for key, value in sorted(self.install_key_usage.items())},
        }


@dataclass
class RegistryUnitLedgerEntry:
    entry_id: str
    wallet_id: str
    owner_key: str
    entry_type: str
    units: int
    balance_after: int
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    purchase_id: str | None = None
    checkout_session_id: str | None = None
    event_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, dict):
            self.metadata = dict(self.metadata or {})

    def as_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "wallet_id": self.wallet_id,
            "owner_key": self.owner_key,
            "entry_type": self.entry_type,
            "units": self.units,
            "balance_after": self.balance_after,
            "created_at": self.created_at.isoformat(),
            "purchase_id": self.purchase_id,
            "checkout_session_id": self.checkout_session_id,
            "event_id": self.event_id,
            "metadata": dict(self.metadata),
        }


class SupabaseUnitWalletRepository:
    _WALLETS_TABLE = "unit_wallets"
    _LEDGER_TABLE = "unit_ledger"

    def __init__(self) -> None:
        from app.supabaseclient import get_supabase_client

        self._client = get_supabase_client()
        self._validate_schema()

    def _validate_schema(self) -> None:
        expected_wallet_columns = {
            "wallet_id",
            "owner_key",
            "balance_units",
            "total_purchased_units",
            "total_consumed_units",
            "total_refunded_units",
            "total_blocked_attacks",
            "updated_at",
            "metadata",
        }
        expected_ledger_columns = {
            "entry_id",
            "wallet_id",
            "owner_key",
            "entry_type",
            "units",
            "balance_after",
            "created_at",
            "metadata",
        }
        for table_name, required_columns in {
            self._WALLETS_TABLE: expected_wallet_columns,
            self._LEDGER_TABLE: expected_ledger_columns,
        }.items():
            try:
                result = self._client.table(table_name).select("*").limit(1).execute()
            except Exception as exc:  # pragma: no cover - exercised via constructor tests
                raise RuntimeError(f"unit_wallet: Supabase schema drift detected for table {table_name!r}; unable to query wallet repository") from exc
            if result is None or not hasattr(result, "data"):
                raise RuntimeError(f"unit_wallet: Supabase wallet repository returned an invalid response for table {table_name!r}")
            if not result.data and not required_columns:
                continue

    def upsert_wallet(self, wallet: RegistryUnitWallet) -> None:
        self._client.table(self._WALLETS_TABLE).upsert(
            {
                "wallet_id": wallet.wallet_id,
                "owner_key": wallet.owner_key,
                "balance_units": wallet.balance_units,
                "total_purchased_units": wallet.total_purchased_units,
                "total_consumed_units": wallet.total_consumed_units,
                "total_refunded_units": wallet.total_refunded_units,
                "total_blocked_attacks": wallet.total_blocked_attacks,
                "updated_at": wallet.updated_at.isoformat(),
                "metadata": {
                    **(wallet.metadata or {}),
                    "install_key_usage": {key: value.as_summary() for key, value in sorted(wallet.install_key_usage.items())},
                },
            },
            on_conflict="wallet_id",
        ).execute()

    def fetch_wallet(self, owner_key: str) -> RegistryUnitWallet | None:
        result = self._client.table(self._WALLETS_TABLE).select("*").eq("owner_key", owner_key).limit(1).execute()
        if not result.data:
            return None
        row = result.data[0]
        metadata = row.get("metadata") or {}
        install_key_usage_raw = metadata.get("install_key_usage") or {}
        usage_map: dict[str, InstallKeyUsageSource] = {}
        for key_id, value in install_key_usage_raw.items():
            if not isinstance(value, dict):
                continue
            usage_map[key_id] = InstallKeyUsageSource(
                key_id=str(value.get("key_id") or key_id),
                owner_key=str(value.get("owner_key") or owner_key),
                program=str(value.get("program") or "unknown"),
                balance_units=int(value.get("balance_units", 0)),
                total_consumed_units=int(value.get("total_consumed_units", 0)),
                total_blocked_attacks=int(value.get("total_blocked_attacks", 0)),
                last_action_at=datetime.fromisoformat(value["last_action_at"]) if value.get("last_action_at") else None,
                metadata=dict(value.get("metadata") or {}),
            )
        return RegistryUnitWallet(
            wallet_id=row["wallet_id"],
            owner_key=row["owner_key"],
            balance_units=row["balance_units"],
            total_purchased_units=row["total_purchased_units"],
            total_consumed_units=row["total_consumed_units"],
            total_refunded_units=row.get("total_refunded_units", 0),
            total_blocked_attacks=row.get("total_blocked_attacks", 0),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=metadata,
            install_key_usage=usage_map,
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
                "purchase_id": entry.purchase_id,
                "checkout_session_id": entry.checkout_session_id,
                "event_id": entry.event_id,
                "metadata": dict(entry.metadata),
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
            metadata = row.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            entries.append(
                RegistryUnitLedgerEntry(
                    entry_id=row["entry_id"],
                    wallet_id=row["wallet_id"],
                    owner_key=row["owner_key"],
                    entry_type=row["entry_type"],
                    units=row["units"],
                    balance_after=row["balance_after"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    purchase_id=row.get("purchase_id") or metadata.get("purchase_id"),
                    checkout_session_id=row.get("checkout_session_id") or metadata.get("checkout_session_id"),
                    event_id=row.get("event_id") or metadata.get("event_id"),
                    metadata=metadata,
                )
            )
        return list(reversed(entries))


class MemoryUnitWalletRepository:
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


def _make_repo() -> SupabaseUnitWalletRepository | MemoryUnitWalletRepository:
    persistence_mode = os.environ.get("IRONCLAW_PERSISTENCE_MODE", "").strip().lower()
    environment_name = os.environ.get("ENVIRONMENT", "").strip().lower()

    if persistence_mode in {"", "auto"}:
        if environment_name == "test":
            logger.info(
                "unit_wallet: persistence mode=%r environment=%r — using MemoryUnitWalletRepository",
                persistence_mode,
                environment_name,
            )
            return MemoryUnitWalletRepository()
        persistence_mode = "supabase"

    if persistence_mode in {"memory", "test"}:
        logger.info(
            "unit_wallet: persistence mode=%r environment=%r — using MemoryUnitWalletRepository",
            persistence_mode,
            environment_name,
        )
        return MemoryUnitWalletRepository()

    try:
        import app.supabaseclient as supabaseclient

        checker = getattr(supabaseclient, "is_supabase_configured", None)
        if persistence_mode == "supabase":
            if checker is None or not checker():
                logger.info("unit_wallet: explicit Supabase mode selected but Supabase is not configured — using MemoryUnitWalletRepository")
                return MemoryUnitWalletRepository()
            try:
                repo = SupabaseUnitWalletRepository()
            except Exception:
                logger.warning(
                    "unit_wallet: explicit Supabase mode hit a stale/invalid singleton; resetting and retrying once before fallback",
                    exc_info=True,
                )
                if hasattr(supabaseclient, "reset_supabase_client"):
                    supabaseclient.reset_supabase_client()
                try:
                    repo = SupabaseUnitWalletRepository()
                except Exception:
                    logger.exception(
                        "unit_wallet: Supabase initialized with a configured backend but failed validation; falling back to MemoryUnitWalletRepository",
                    )
                    return MemoryUnitWalletRepository()
            logger.info("unit_wallet: SupabaseUnitWalletRepository initialized in explicit supabase mode")
            return repo

        if checker is None or not checker():
            logger.info("unit_wallet: Supabase not configured — using MemoryUnitWalletRepository")
            return MemoryUnitWalletRepository()

        try:
            repo = SupabaseUnitWalletRepository()
        except Exception:
            logger.warning(
                "unit_wallet: Supabase backend was configured but a stale singleton was detected; resetting and retrying once",
                exc_info=True,
            )
            if hasattr(supabaseclient, "reset_supabase_client"):
                supabaseclient.reset_supabase_client()
            try:
                repo = SupabaseUnitWalletRepository()
            except Exception:
                logger.exception(
                    "unit_wallet: Supabase initialized with a configured backend but failed validation; falling back to MemoryUnitWalletRepository",
                )
                return MemoryUnitWalletRepository()

        logger.info("unit_wallet: SupabaseUnitWalletRepository initialized")
        return repo

    except Exception:
        logger.exception(
            "unit_wallet: Supabase initialized with a configured backend but failed validation; falling back to MemoryUnitWalletRepository",
        )
        return MemoryUnitWalletRepository()


class UnitWalletRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._wallets: dict[str, RegistryUnitWallet] = {}
        self._wallets_by_owner: dict[str, str] = {}
        self._repo: SupabaseUnitWalletRepository | MemoryUnitWalletRepository = _make_repo()

    @staticmethod
    def _is_real_wallet(wallet: Any) -> bool:
        if not isinstance(wallet, RegistryUnitWallet):
            return False
        return bool(wallet.wallet_id) and bool(wallet.owner_key)

    def _evict_cache_if_needed(self) -> None:
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
        normalized_owner = _normalize_owner_key(owner_key)

        with self._lock:
            wallet_id = self._wallets_by_owner.get(normalized_owner)
            if wallet_id is not None:
                cached_wallet = self._wallets.get(wallet_id)
                if cached_wallet is not None:
                    if isinstance(cached_wallet, RegistryUnitWallet) and self._is_real_wallet(cached_wallet):
                        return cached_wallet
                    self._wallets_by_owner.pop(normalized_owner, None)

        existing = self._repo.fetch_wallet(normalized_owner)
        if existing is not None:
            if not self._is_real_wallet(existing):
                raise ValueError(f"Repository returned an invalid wallet object for owner_key={normalized_owner!r}")
            with self._lock:
                self._wallets[existing.wallet_id] = existing
                self._wallets_by_owner[normalized_owner] = existing.wallet_id
                self._evict_cache_if_needed()
            return existing

        with self._lock:
            wallet_id = self._wallets_by_owner.get(normalized_owner)
            if wallet_id is not None:
                wallet = self._wallets.get(wallet_id)
                if isinstance(wallet, RegistryUnitWallet) and self._is_real_wallet(wallet):
                    return wallet

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

    @staticmethod
    def _normalize_ledger_metadata(metadata: dict[str, Any] | None) -> tuple[dict[str, Any], str | None, str | None, str | None]:
        payload = dict(metadata or {})
        purchase_id = str(payload.get("purchase_id") or payload.get("purchase_reference") or "").strip() or None
        checkout_session_id = str(payload.get("checkout_session_id") or payload.get("session_id") or "").strip() or None
        event_id = str(payload.get("event_id") or payload.get("ledger_event_id") or "").strip() or None
        if purchase_id:
            payload.setdefault("purchase_id", purchase_id)
        if checkout_session_id:
            payload.setdefault("checkout_session_id", checkout_session_id)
        if event_id:
            payload.setdefault("event_id", event_id)
        return payload, purchase_id, checkout_session_id, event_id

    def credit_units(
        self,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        safe_units = max(0, int(units))
        wallet = self.get_or_create_wallet(owner_key=owner_key)
        normalized_metadata, purchase_id, checkout_session_id, event_id = self._normalize_ledger_metadata(metadata)

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
                purchase_id=purchase_id,
                checkout_session_id=checkout_session_id,
                event_id=event_id,
                metadata=normalized_metadata,
            )

        self._repo.upsert_wallet(wallet)
        self._repo.append_ledger_entry(entry)
        return wallet

    def credit(
        self,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        return self.credit_units(owner_key=owner_key, units=units, metadata=metadata)

    def debit_units(
        self,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        safe_units = max(0, int(units))
        wallet = self.get_or_create_wallet(owner_key=owner_key)
        normalized_metadata, purchase_id, checkout_session_id, event_id = self._normalize_ledger_metadata(metadata)

        insufficient: InsufficientUnitsError | None = None
        entry: RegistryUnitLedgerEntry | None = None

        with self._lock:
            if safe_units > wallet.balance_units:
                insufficient = InsufficientUnitsError(
                    "Insufficient protection units",
                    have=wallet.balance_units,
                    need=safe_units,
                    owner_key=wallet.owner_key,
                )
            else:
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
                    purchase_id=purchase_id,
                    checkout_session_id=checkout_session_id,
                    event_id=event_id,
                    metadata=normalized_metadata,
                )

        if insufficient is not None:
            raise insufficient

        self._repo.upsert_wallet(wallet)
        self._repo.append_ledger_entry(entry)  # type: ignore[arg-type]
        return wallet

    def debit_units_for_tokens(
        self,
        owner_key: str,
        token_count: int,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[RegistryUnitWallet, int]:
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

    def debit_units_for_install_key(
        self,
        owner_key: str,
        key_id: str,
        program: str,
        units: int,
        *,
        payment_id: str | None = None,
        action_type: str = "prompt",
        blocked_attack_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[RegistryUnitWallet, InstallKeyUsageSource, InstallKeyUsageLedgerEntry]:
        if not key_id:
            raise ValueError("key_id is required")
        if not program:
            raise ValueError("program is required")
        if _is_generic_platform_credential(owner_key):
            raise ValueError("owner_key must be a customer or org identity, not a generic platform API key")
        if _is_generic_platform_credential(str(key_id)):
            raise ValueError("key_id must be an install key identity, not a generic platform API credential")
        safe_units = max(0, int(units))

        payload = dict(metadata or {})
        explicit_owner = str(payload.get("owner_key") or "").strip().lower()
        if explicit_owner and explicit_owner != _normalize_owner_key(owner_key):
            raise ValueError("metadata owner_key does not match the wallet owner_key for install-key usage")
        explicit_key = str(payload.get("key_id") or "").strip()
        if explicit_key and explicit_key != str(key_id):
            raise ValueError("metadata key_id does not match the install key being debited")

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
            wallet.total_blocked_attacks += int(blocked_attack_count)
            wallet.updated_at = datetime.now(UTC)

            usage = wallet.install_key_usage.setdefault(
                key_id,
                InstallKeyUsageSource(
                    key_id=key_id,
                    owner_key=wallet.owner_key,
                    program=program,
                ),
            )
            if usage.owner_key != wallet.owner_key:
                raise ValueError("install-key usage for a different owner_key is not allowed on this wallet")
            usage.program = program
            usage.balance_units = max(wallet.balance_units, 0)
            usage.metadata.update(
                {
                    **payload,
                    "owner_key": wallet.owner_key,
                    "key_id": key_id,
                    "program": program,
                    "payment_id": payment_id,
                    "action_type": action_type,
                    "blocked_attack_count": int(blocked_attack_count),
                    "quarantined_count": int(payload.get("quarantined_count", payload.get("quarantined_attack_count", 0))),
                }
            )

            quarantined_count = int(payload.get("quarantined_count", payload.get("quarantined_attack_count", 0)))
            usage.register_usage_event(
                units=safe_units,
                blocked_attack_count=int(blocked_attack_count),
                quarantined_count=quarantined_count,
                occurred_at=wallet.updated_at,
            )

            canonical_metadata = {
                **payload,
                "owner_key": wallet.owner_key,
                "key_id": key_id,
                "program": program,
                "payment_id": payment_id,
                "action_type": action_type,
                "blocked_attack_count": int(blocked_attack_count),
                "quarantined_count": quarantined_count,
            }

            entry = InstallKeyUsageLedgerEntry(
                entry_id=f"ledger_{uuid.uuid4().hex}",
                owner_key=wallet.owner_key,
                key_id=key_id,
                program=program,
                action_type=action_type,
                units=safe_units,
                balance_after=wallet.balance_units,
                payment_id=payment_id,
                blocked_attack_count=int(blocked_attack_count),
                created_at=wallet.updated_at,
                metadata=canonical_metadata,
            )

            ledger_entry = RegistryUnitLedgerEntry(
                entry_id=entry.entry_id,
                wallet_id=wallet.wallet_id,
                owner_key=wallet.owner_key,
                entry_type="install_key_debit",
                units=safe_units,
                balance_after=wallet.balance_units,
                created_at=wallet.updated_at,
                purchase_id=payment_id or payload.get("purchase_id"),
                checkout_session_id=payload.get("checkout_session_id") or payload.get("session_id"),
                event_id=payload.get("event_id") or f"install_key_debit:{key_id}:{wallet.updated_at.isoformat()}",
                metadata=entry.as_dict(),
            )

        self._repo.upsert_wallet(wallet)
        self._repo.append_ledger_entry(ledger_entry)
        return wallet, usage, entry

    def record_install_key_event(
        self,
        owner_key: str,
        *,
        key_id: str | None,
        program: str | None,
        event_type: str,
        units: int = 0,
        blocked_attack_count: int = 0,
        action_type: str | None = None,
        occurred_at: datetime | str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        wallet = self.get_or_create_wallet(owner_key)
        effective_program = (program or "openclaw").strip() or "openclaw"

        if isinstance(occurred_at, datetime):
            timestamp = occurred_at.astimezone(UTC) if occurred_at.tzinfo is not None else occurred_at.replace(tzinfo=UTC)
        elif isinstance(occurred_at, str):
            candidate = occurred_at.strip()
            if candidate.endswith("Z"):
                candidate = candidate[:-1] + "+00:00"
            timestamp = datetime.fromisoformat(candidate)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
            timestamp = timestamp.astimezone(UTC)
        else:
            timestamp = datetime.now(UTC)

        entry: RegistryUnitLedgerEntry | None = None
        with self._lock:
            if key_id:
                usage = wallet.install_key_usage.setdefault(
                    key_id,
                    InstallKeyUsageSource(
                        key_id=key_id,
                        owner_key=wallet.owner_key,
                        program=effective_program,
                    ),
                )
                usage.program = effective_program
                usage.balance_units = max(wallet.balance_units, 0)
                usage.last_action_at = timestamp
                usage.metadata.update(
                    {
                        "owner_key": wallet.owner_key,
                        "key_id": key_id,
                        "program": effective_program,
                        "last_event_type": event_type,
                        "last_event_at": timestamp.isoformat().replace("+00:00", "Z"),
                        "action_type": action_type or usage.metadata.get("action_type") or "telemetry",
                    }
                )
                if blocked_attack_count > 0 and event_type not in {"usage_units_debited"}:
                    usage.total_blocked_attacks += int(blocked_attack_count)
                    wallet.total_blocked_attacks += int(blocked_attack_count)
                    if event_type in {"prompt_injection_detected", "quarantine_detected", "quarantine_event"}:
                        usage.total_quarantined_actions += int(blocked_attack_count)
                if units > 0 and event_type not in {"usage_units_debited"}:
                    usage.total_consumed_units += int(units)
                wallet.install_key_usage[key_id] = usage

            wallet.updated_at = timestamp
            wallet.metadata.setdefault("dashboard_sync", {})
            wallet.metadata["dashboard_sync"][event_type] = {
                "occurred_at": timestamp.isoformat().replace("+00:00", "Z"),
                "key_id": key_id,
                "owner_key": wallet.owner_key,
                "program": effective_program,
                "units": int(units),
                "blocked_attack_count": int(blocked_attack_count),
                "metadata": dict(metadata or {}),
            }

            if key_id:
                event_metadata = {
                    "event_type": event_type,
                    "key_id": key_id,
                    "program": effective_program,
                    "owner_key": wallet.owner_key,
                    "action_type": action_type,
                    "blocked_attack_count": int(blocked_attack_count),
                    **dict(metadata or {}),
                }
                purchase_id = str(event_metadata.get("purchase_id") or event_metadata.get("purchase_reference") or "").strip() or None
                checkout_session_id = str(event_metadata.get("checkout_session_id") or event_metadata.get("session_id") or "").strip() or None
                event_id = str(event_metadata.get("event_id") or f"{event_type}:{key_id}:{int(timestamp.timestamp() * 1000)}").strip() or None
                entry = RegistryUnitLedgerEntry(
                    entry_id=f"ledger_{event_type}_{key_id}_{int(timestamp.timestamp() * 1000)}",
                    wallet_id=wallet.wallet_id,
                    owner_key=wallet.owner_key,
                    entry_type="install_key_event",
                    units=int(units),
                    balance_after=wallet.balance_units,
                    created_at=timestamp,
                    purchase_id=purchase_id,
                    checkout_session_id=checkout_session_id,
                    event_id=event_id,
                    metadata=event_metadata,
                )

        self._repo.upsert_wallet(wallet)
        if entry is not None:
            self._repo.append_ledger_entry(entry)
        return True

    def refund_units(
        self,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> RegistryUnitWallet:
        safe_units = max(0, int(units))
        wallet = self.get_or_create_wallet(owner_key=owner_key)
        normalized_metadata, purchase_id, checkout_session_id, event_id = self._normalize_ledger_metadata(metadata)

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
                purchase_id=purchase_id,
                checkout_session_id=checkout_session_id,
                event_id=event_id,
                metadata=normalized_metadata,
            )

        self._repo.upsert_wallet(wallet)
        self._repo.append_ledger_entry(entry)
        return wallet

    def get_wallet(self, owner_key: str) -> RegistryUnitWallet | None:
        normalized_owner = _normalize_owner_key(owner_key)
        with self._lock:
            wallet_id = self._wallets_by_owner.get(normalized_owner)
            if wallet_id is not None:
                cached_wallet = self._wallets.get(wallet_id)
                if cached_wallet is not None:
                    if isinstance(cached_wallet, RegistryUnitWallet) and self._is_real_wallet(cached_wallet):
                        return cached_wallet
                    self._wallets_by_owner.pop(normalized_owner, None)

        wallet = self._repo.fetch_wallet(normalized_owner)
        if wallet is None:
            return None
        if not self._is_real_wallet(wallet):
            raise ValueError(f"Repository returned invalid wallet for owner_key={normalized_owner!r}")

        with self._lock:
            self._wallets[wallet.wallet_id] = wallet
            self._wallets_by_owner[normalized_owner] = wallet.wallet_id
            self._evict_cache_if_needed()
        return wallet

    def list_ledger_entries(
        self,
        owner_key: str | None = None,
        limit: int = 100,
    ) -> list[RegistryUnitLedgerEntry]:
        return self._repo.fetch_ledger_entries(owner_key=owner_key, limit=limit)

    def get_key_usage_summary(
        self,
        owner_key: str,
        *,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        wallet = self.get_wallet(owner_key)
        if wallet is None:
            owner = _normalize_owner_key(owner_key)
            return {
                "owner_key": owner,
                "wallet_balance_units": 0,
                "total_consumed_units": 0,
                "total_blocked_attacks": 0,
                "total_quarantined_actions": 0,
                "install_key_usage": {},
            }

        if key_id is not None:
            usage = wallet.install_key_usage.get(key_id)
            return {
                "owner_key": wallet.owner_key,
                "wallet_balance_units": wallet.balance_units,
                "total_consumed_units": wallet.total_consumed_units,
                "total_blocked_attacks": wallet.total_blocked_attacks,
                "total_quarantined_actions": sum(item.total_quarantined_actions for item in wallet.install_key_usage.values()),
                "install_key_usage": {key_id: usage.as_summary()} if usage is not None else {},
            }

        return {
            "owner_key": wallet.owner_key,
            "wallet_balance_units": wallet.balance_units,
            "total_consumed_units": wallet.total_consumed_units,
            "total_blocked_attacks": wallet.total_blocked_attacks,
            "total_quarantined_actions": sum(item.total_quarantined_actions for item in wallet.install_key_usage.values()),
            "install_key_usage": {key: value.as_summary() for key, value in sorted(wallet.install_key_usage.items())},
        }


_unit_wallet_registry = UnitWalletRegistry()


def get_unit_wallet_registry() -> UnitWalletRegistry:
    return _unit_wallet_registry
