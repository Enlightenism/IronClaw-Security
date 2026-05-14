from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from .contracts import SkillProvider, SkillRequestContext
from .errors import (
    ProviderConfigurationError,
    ProviderExecutionError,
    ProviderUnavailableError,
)

BillingOperation = Literal["scan", "actionpolicy", "actiondecision", "execute", "unknown"]
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


@dataclass(frozen=True, slots=True)
class BillingContext:
    request_id: str | None = None
    client_id: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    organization_id: str | None = None
    customer_id: str | None = None
    actor_id: str | None = None
    source_platform: str | None = None
    environment: str | None = None
    route: str | None = None
    method: str | None = None
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

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

    def cost_for(self, operation: BillingOperation) -> int:
        if operation == "scan":
            return self.units_per_scan
        if operation == "actionpolicy":
            return self.units_per_action_policy
        if operation == "actiondecision":
            return self.units_per_action_decision
        if operation == "execute":
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
    text = str(value).strip()
    return text or None


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
        raise ProviderConfigurationError(
            f"Invalid integer for {field_name}: {value!r}",
        ) from exc
    if result < 0:
        raise ProviderConfigurationError(f"{field_name} must be >= 0")
    return result


def default_ledger_path() -> Path:
    configured = _normalize_optional_text(os.getenv("IRONCLAW_BILLING_LEDGER_PATH"))
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / DEFAULT_LEDGER_DIRNAME / DEFAULT_LEDGER_FILENAME).resolve()


def load_billing_policy() -> BillingPolicy:
    provider_raw = _normalize_optional_text(os.getenv("IRONCLAW_BILLING_PROVIDER")) or DEFAULT_PROVIDER
    provider = provider_raw.lower()
    if provider not in {"stub", "memory"}:
        raise ProviderConfigurationError(f"Unsupported billing provider: {provider_raw}")

    return BillingPolicy(
        provider=provider,  # type: ignore[arg-type]
        units_per_scan=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_SCAN") or os.getenv("IRONCLAWUNITSPERSCAN"),
            default=DEFAULT_UNITS_PER_SCAN,
            field_name="IRONCLAW_UNITS_PER_SCAN",
        ),
        units_per_action_policy=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_ACTION_POLICY") or os.getenv("IRONCLAWUNITSPERACTIONPOLICY"),
            default=DEFAULT_UNITS_PER_ACTION_POLICY,
            field_name="IRONCLAW_UNITS_PER_ACTION_POLICY",
        ),
        units_per_action_decision=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_ACTION_DECISION") or os.getenv("IRONCLAWUNITSPERACTIONDECISION"),
            default=DEFAULT_UNITS_PER_ACTION_DECISION,
            field_name="IRONCLAW_UNITS_PER_ACTION_DECISION",
        ),
        units_per_execute=_coerce_int(
            os.getenv("IRONCLAW_UNITS_PER_EXECUTE") or os.getenv("IRONCLAWUNITSPEREXECUTE"),
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
        ledger_path=default_ledger_path(),
    )


class StubBillingHook:
    """No-op provider that records unit charges without enforcing balance."""

    def __init__(self, policy: BillingPolicy | None = None) -> None:
        self.policy = policy or load_billing_policy()

    def charge(
        self,
        *,
        operation: BillingOperation,
        context: BillingContext | None = None,
        metadata: dict[str, Any] | None = None,
        units: int | None = None,
    ) -> BillingResult:
        effective_units = self.policy.cost_for(operation) if units is None else max(int(units), 0)
        event = BillingEvent(
            operation=operation,
            units=effective_units,
            provider="stub",
            status="noop",
            timestamp=time.time(),
            reason="stub-billing-provider",
            request_id=context.request_id if context else None,
            metadata=dict(metadata or {}),
            balance_before=None,
            balance_after=None,
        )
        return BillingResult(
            ok=True,
            operation=operation,
            units_charged=effective_units,
            provider="stub",
            status="noop",
            reason="stub-billing-provider",
            balance_before=None,
            balance_after=None,
            event=event,
        )


class MemoryBillingHook:
    """In-memory unit ledger provider for local testing and future integration."""

    def __init__(self, policy: BillingPolicy | None = None) -> None:
        self.policy = policy or load_billing_policy()
        self._lock = threading.Lock()
        self._balance = self.policy.default_balance
        self._ledger_path = self.policy.ledger_path or default_ledger_path()

    @property
    def balance(self) -> int:
        return self._balance

    @property
    def ledger_path(self) -> Path:
        return self._ledger_path

    def reset_balance(self, units: int) -> None:
        if units < 0:
            raise ProviderConfigurationError("reset balance must be >= 0")
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
        effective_units = self.policy.cost_for(operation) if units is None else max(int(units), 0)

        with self._lock:
            before = self._balance

            if self.policy.block_on_exhausted and effective_units > before:
                event = BillingEvent(
                    operation=operation,
                    units=effective_units,
                    provider="memory",
                    status="rejected",
                    timestamp=time.time(),
                    reason="insufficient-units",
                    request_id=context.request_id if context else None,
                    metadata=dict(metadata or {}),
                    balance_before=before,
                    balance_after=before,
                )
                self._append_ledger_event(event)
                return BillingResult(
                    ok=False,
                    operation=operation,
                    units_charged=0,
                    provider="memory",
                    status="rejected",
                    reason="insufficient-units",
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
                metadata=dict(metadata or {}),
                balance_before=before,
                balance_after=after,
            )
            self._append_ledger_event(event)

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

    def _append_ledger_event(self, event: BillingEvent) -> None:
        try:
            self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with self._ledger_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        except OSError as exc:
            raise ProviderExecutionError(f"Failed to append billing ledger: {exc}") from exc


def create_billing_hook(policy: BillingPolicy | None = None) -> BillingHook:
    resolved_policy = policy or load_billing_policy()
    if resolved_policy.provider == "stub":
        return StubBillingHook(resolved_policy)
    if resolved_policy.provider == "memory":
        return MemoryBillingHook(resolved_policy)
    raise ProviderUnavailableError(f"Unsupported billing provider: {resolved_policy.provider}")


def _coerce_provider_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, SkillProvider):
        return value.value
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str) and enum_value.strip():
        return enum_value.strip()
    return _normalize_optional_text(value)


def build_billing_context_from_request_context(
    request_context: SkillRequestContext | Any,
) -> BillingContext | None:
    if request_context is None:
        return None

    tags_value = getattr(request_context, "tags", ())
    if isinstance(tags_value, (list, tuple, set)):
        tags = tuple(str(item).strip() for item in tags_value if str(item).strip())
    elif isinstance(tags_value, str) and tags_value.strip():
        tags = tuple(part.strip() for part in tags_value.split(",") if part.strip())
    else:
        tags = ()

    meta_value = getattr(request_context, "metadata", {})
    metadata = dict(meta_value) if isinstance(meta_value, dict) else {}

    source_platform = _normalize_optional_text(getattr(request_context, "source_platform", None))
    if source_platform is None:
        provider = getattr(request_context, "provider", None)
        source_platform = _coerce_provider_value(provider)

    return BillingContext(
        request_id=_normalize_optional_text(getattr(request_context, "request_id", None)),
        client_id=_normalize_optional_text(getattr(request_context, "client_id", None)),
        session_id=_normalize_optional_text(getattr(request_context, "session_id", None)),
        user_id=_normalize_optional_text(getattr(request_context, "user_id", None)),
        tenant_id=_normalize_optional_text(getattr(request_context, "tenant_id", None)),
        organization_id=_normalize_optional_text(getattr(request_context, "organization_id", None)),
        customer_id=_normalize_optional_text(getattr(request_context, "customer_id", None)),
        actor_id=_normalize_optional_text(getattr(request_context, "actor_id", None)),
        source_platform=source_platform,
        environment=_normalize_optional_text(getattr(request_context, "environment", None)),
        route=_normalize_optional_text(getattr(request_context, "route", None)),
        method=_normalize_optional_text(getattr(request_context, "method", None)),
        tags=tags,
        metadata=metadata,
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


# Backwards-compatible aliases for CLI and external callers
chargeunits = charge_units
createbillinghook = create_billing_hook


__all__ = [
    "DEFAULT_BALANCE",
    "DEFAULT_BLOCK_ON_EXHAUSTED",
    "DEFAULT_LEDGER_DIRNAME",
    "DEFAULT_LEDGER_FILENAME",
    "DEFAULT_PROVIDER",
    "DEFAULT_UNITS_PER_ACTION_DECISION",
    "DEFAULT_UNITS_PER_ACTION_POLICY",
    "DEFAULT_UNITS_PER_EXECUTE",
    "DEFAULT_UNITS_PER_SCAN",
    "BillingContext",
    "BillingEvent",
    "BillingHook",
    "BillingOperation",
    "BillingPolicy",
    "BillingProvider",
    "BillingResult",
    "BillingStatus",
    "MemoryBillingHook",
    "StubBillingHook",
    "build_billing_context_from_request_context",
    "charge_units",
    "chargeunits",
    "create_billing_hook",
    "createbillinghook",
    "default_ledger_path",
    "load_billing_policy",
]
