from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, Protocol


BillingOperation = Literal["scan", "action_policy", "action_decision", "execute", "unknown"]
BillingProvider = Literal["stub", "memory"]
BillingStatus = Literal["accepted", "rejected", "noop"]


DEFAULT_PROVIDER: Final[BillingProvider] = "stub"
DEFAULT_LEDGER_DIRNAME: Final[str] = ".ironclaw"
DEFAULT_LEDGER_FILENAME: Final[str] = "skill-billing-ledger.jsonl"
DEFAULT_UNITS_PER_SCAN: Final[int] = 1
DEFAULT_UNITS_PER_ACTION_POLICY: Final[int] = 1
DEFAULT_UNITS_PER_ACTION_DECISION: Final[int] = 1
DEFAULT_UNITS_PER_EXECUTE: Final[int] = 2
DEFAULT_BLOCK_ON_EXHAUSTED: Final[bool] = False
DEFAULT_BALANCE: Final[int] = 0


class IronClawBillingError(RuntimeError):
    """Raised when billing hook processing fails."""


@dataclass(frozen=True, slots=True)
class BillingContext:
    request_id: str | None = None
    client_id: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    source_platform: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BillingEvent:
    operation: BillingOperation
    units: int
    provider: BillingProvider
    status: BillingStatus
    timestamp: float
    reason: str | None = None
    request_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    balance_before: int | None = None
    balance_after: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BillingResult:
    ok: bool
    operation: BillingOperation
    units_charged: int
    provider: BillingProvider
    status: BillingStatus
    reason: str | None = None
    balance_before: int | None = None
    balance_after: int | None = None
    event: BillingEvent | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if self.event is not None:
            payload["event"] = self.event.to_dict()
        return payload


@dataclass(slots=True)
class BillingPolicy:
    provider: BillingProvider = DEFAULT_PROVIDER
    units_per_scan: int = DEFAULT_UNITS_PER_SCAN
    units_per_action_policy: int = DEFAULT_UNITS_PER_ACTION_POLICY
    units_per_action_decision: int = DEFAULT_UNITS_PER_ACTION_DECISION
    units_per_execute: int = DEFAULT_UNITS_PER_EXECUTE
    block_on_exhausted: bool = DEFAULT_BLOCK_ON_EXHAUSTED
    default_balance: int = DEFAULT_BALANCE
    ledger_path: Path | None = None

    def cost_for(self, operation: str) -> int:
        normalized = operation.strip().lower()
        if normalized == "scan":
            return self.units_per_scan
        if normalized == "action_policy":
            return self.units_per_action_policy
        if normalized == "action_decision":
            return self.units_per_action_decision
        if normalized == "execute":
            return self.units_per_execute
        return 0


class BillingHook(Protocol):
    def charge(
        self,
        *,
        operation: BillingOperation,
        context: BillingContext | None = None,
        metadata: dict[str, Any] | None = None,
        units: int | None = None,
    ) -> BillingResult: ...


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _coerce_int(value: Any, *, default: int, field_name: str) -> int:
    if value is None or value == "":
        return default
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise IronClawBillingError(f"Invalid integer for {field_name}: {value!r}") from exc
    if result < 0:
        raise IronClawBillingError(f"{field_name} must be >= 0")
    return result


def _default_ledger_path() -> Path:
    configured = _normalize_optional_text(os.getenv("IRONCLAW_BILLING_LEDGER_PATH"))
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / DEFAULT_LEDGER_DIRNAME / DEFAULT_LEDGER_FILENAME).resolve()


def load_billing_policy() -> BillingPolicy:
    provider_raw = (_normalize_optional_text(os.getenv("IRONCLAW_BILLING_PROVIDER")) or DEFAULT_PROVIDER).lower()
    if provider_raw not in {"stub", "memory"}:
        raise IronClawBillingError(f"Unsupported billing provider: {provider_raw}")

    return BillingPolicy(
        provider=provider_raw,  # type: ignore[arg-type]
        units_per_scan=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_SCAN"),
            default=DEFAULT_UNITS_PER_SCAN,
            field_name="IRONCLAW_UNITS_PER_SCAN",
        ),
        units_per_action_policy=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_ACTION_POLICY"),
            default=DEFAULT_UNITS_PER_ACTION_POLICY,
            field_name="IRONCLAW_UNITS_PER_ACTION_POLICY",
        ),
        units_per_action_decision=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_ACTION_DECISION"),
            default=DEFAULT_UNITS_PER_ACTION_DECISION,
            field_name="IRONCLAW_UNITS_PER_ACTION_DECISION",
        ),
        units_per_execute=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_EXECUTE"),
            default=DEFAULT_UNITS_PER_EXECUTE,
            field_name="IRONCLAW_UNITS_PER_EXECUTE",
        ),
        block_on_exhausted=_coerce_bool(
            os.getenv("IRONCLAW_BILLING_BLOCK_ON_EXHAUSTED"),
            default=DEFAULT_BLOCK_ON_EXHAUSTED,
        ),
        default_balance=_coerce_int(
            os.getenv("IRONCLAW_BILLING_DEFAULT_BALANCE"),
            default=DEFAULT_BALANCE,
            field_name="IRONCLAW_BILLING_DEFAULT_BALANCE",
        ),
        ledger_path=_default_ledger_path(),
    )


class StubBillingHook:
    """No-op provider that exposes unit charge hook points without enforcing balance."""

    def __init__(self, policy: BillingPolicy | None = None) -> None:
        self._policy = policy or load_billing_policy()

    def charge(
        self,
        *,
        operation: BillingOperation,
        context: BillingContext | None = None,
        metadata: dict[str, Any] | None = None,
        units: int | None = None,
    ) -> BillingResult:
        effective_units = self._policy.cost_for(operation) if units is None else max(units, 0)
        event = BillingEvent(
            operation=operation,
            units=effective_units,
            provider="stub",
            status="noop",
            timestamp=time.time(),
            reason="stub_billing_provider",
            request_id=context.request_id if context else None,
            metadata=metadata or {},
            balance_before=None,
            balance_after=None,
        )
        return BillingResult(
            ok=True,
            operation=operation,
            units_charged=effective_units,
            provider="stub",
            status="noop",
            reason="stub_billing_provider",
            balance_before=None,
            balance_after=None,
            event=event,
        )


class MemoryBillingHook:
    """In-memory/unit-ledger provider for local testing and future billing integration."""

    def __init__(self, policy: BillingPolicy | None = None) -> None:
        self._policy = policy or load_billing_policy()
        self._lock = threading.Lock()
        self._balance = self._policy.default_balance
        self._ledger_path = self._policy.ledger_path or _default_ledger_path()

    @property
    def balance(self) -> int:
        return self._balance

    @property
    def ledger_path(self) -> Path:
        return self._ledger_path

    def reset_balance(self, units: int) -> None:
        if units < 0:
            raise IronClawBillingError("reset balance must be >= 0")
        with self._lock:
            self._balance = units

    def charge(
        self,
        *,
        operation: BillingOperation,
        context: BillingContext | None = None,
        metadata: dict[str, Any] | None = None,
        units: int | None = None,
    ) -> BillingResult:
        effective_units = self._policy.cost_for(operation) if units is None else max(units, 0)

        with self._lock:
            before = self._balance
            if self._policy.block_on_exhausted and effective_units > before:
                event = BillingEvent(
                    operation=operation,
                    units=effective_units,
                    provider="memory",
                    status="rejected",
                    timestamp=time.time(),
                    reason="insufficient_units",
                    request_id=context.request_id if context else None,
                    metadata=metadata or {},
                    balance_before=before,
                    balance_after=before,
                )
                self._append_ledger(event)
                return BillingResult(
                    ok=False,
                    operation=operation,
                    units_charged=0,
                    provider="memory",
                    status="rejected",
                    reason="insufficient_units",
                    balance_before=before,
                    balance_after=before,
                    event=event,
                )

            after = before - effective_units
            self._balance = after

            event = BillingEvent(
                operation=operation,
                units=effective_units,
                provider="memory",
                status="accepted",
                timestamp=time.time(),
                reason=None,
                request_id=context.request_id if context else None,
                metadata=metadata or {},
                balance_before=before,
                balance_after=after,
            )
            self._append_ledger(event)

            return BillingResult(
                ok=True,
                operation=operation,
                units_charged=effective_units,
                provider="memory",
                status="accepted",
                reason=None,
                balance_before=before,
                balance_after=after,
                event=event,
            )

    def _append_ledger(self, event: BillingEvent) -> None:
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self._ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")


def create_billing_hook(policy: BillingPolicy | None = None) -> BillingHook:
    resolved_policy = policy or load_billing_policy()
    if resolved_policy.provider == "stub":
        return StubBillingHook(resolved_policy)
    if resolved_policy.provider == "memory":
        return MemoryBillingHook(resolved_policy)
    raise IronClawBillingError(f"Unsupported billing provider: {resolved_policy.provider}")


def build_billing_context_from_request_context(request_context: Any) -> BillingContext:
    return BillingContext(
        request_id=_normalize_optional_text(getattr(request_context, "request_id", None)),
        client_id=_normalize_optional_text(getattr(request_context, "client_id", None)),
        session_id=_normalize_optional_text(getattr(request_context, "session_id", None)),
        user_id=_normalize_optional_text(getattr(request_context, "user_id", None)),
        tenant_id=_normalize_optional_text(getattr(request_context, "tenant_id", None)),
        source_platform=_normalize_optional_text(getattr(request_context, "source_platform", None)),
    )


def charge_units(
    *,
    operation: BillingOperation,
    hook: BillingHook | None = None,
    context: BillingContext | None = None,
    metadata: dict[str, Any] | None = None,
    units: int | None = None,
) -> BillingResult:
    resolved_hook = hook or create_billing_hook()
    return resolved_hook.charge(
        operation=operation,
        context=context,
        metadata=metadata,
        units=units,
    )


__all__ = [
    "BillingContext",
    "BillingEvent",
    "BillingHook",
    "BillingPolicy",
    "BillingResult",
    "IronClawBillingError",
    "MemoryBillingHook",
    "StubBillingHook",
    "build_billing_context_from_request_context",
    "charge_units",
    "create_billing_hook",
    "load_billing_policy",
]