from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Protocol
from uuid import uuid4

from .adapterclaude import ClaudeSkillAdapter
from .adapteropenclaw import OpenClawSkillAdapter
from .config import IronClawSkillConfig, load_config
from .contracts import (
    RiskLevel,
    SkillDecision,
    SkillExecutionRequest,
    SkillExecutionResult,
    SkillProvider,
    SkillProviderDecision,
    SkillUsage,
)
from .errors import IronClawConfigurationError, IronClawRuntimeError

JsonDict = dict[str, Any]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _clean_mapping(value: dict[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _coerce_provider(value: Any, default: SkillProvider) -> SkillProvider:
    if isinstance(value, SkillProvider):
        return value
    normalized = _normalize_text(getattr(value, "value", value)).lower()
    if normalized == SkillProvider.CLAUDE.value:
        return SkillProvider.CLAUDE
    if normalized == SkillProvider.OPENCLAW.value:
        return SkillProvider.OPENCLAW
    return default


def _coerce_risk_level(value: Any, default: RiskLevel = RiskLevel.LOW) -> RiskLevel:
    if isinstance(value, RiskLevel):
        return value
    normalized = _normalize_text(getattr(value, "value", value)).lower()
    if normalized == RiskLevel.LOW.value:
        return RiskLevel.LOW
    if normalized == RiskLevel.MEDIUM.value:
        return RiskLevel.MEDIUM
    if normalized == RiskLevel.HIGH.value:
        return RiskLevel.HIGH
    if normalized == RiskLevel.CRITICAL.value:
        return RiskLevel.CRITICAL
    return default


def _coerce_skill_decision(
    allowed: bool,
    blocked: bool,
    requires_review: bool,
    explicit: Any = None,
) -> SkillDecision:
    if isinstance(explicit, SkillDecision):
        return explicit
    explicit_value = _normalize_text(getattr(explicit, "value", explicit)).lower()
    if explicit_value == SkillDecision.ALLOW.value:
        return SkillDecision.ALLOW
    if explicit_value == SkillDecision.REVIEW.value:
        return SkillDecision.REVIEW
    if explicit_value == SkillDecision.BLOCK.value:
        return SkillDecision.BLOCK
    if explicit_value == SkillDecision.ERROR.value:
        return SkillDecision.ERROR
    if blocked:
        return SkillDecision.BLOCK
    if requires_review:
        return SkillDecision.REVIEW
    if allowed:
        return SkillDecision.ALLOW
    return SkillDecision.ERROR


class RuntimeAdapter(Protocol):
    def execute(self, request: SkillExecutionRequest) -> SkillProviderDecision:
        ...


@dataclass(slots=True, frozen=True)
class RuntimeExecutionTrace:
    request_id: str
    trace_id: str
    provider: str
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    allowed: bool
    blocked: bool
    requires_review: bool
    policy_hits: tuple[str, ...] = field(default_factory=tuple)
    metadata: JsonDict = field(default_factory=dict)

    def as_dict(self) -> JsonDict:
        return {
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "provider": self.provider,
            "started_at": self.started_at.astimezone(UTC).isoformat(),
            "finished_at": self.finished_at.astimezone(UTC).isoformat(),
            "duration_ms": self.duration_ms,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "requires_review": self.requires_review,
            "policy_hits": list(self.policy_hits),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IronClawRuntime:
    config: IronClawSkillConfig
    _adapters: dict[str, RuntimeAdapter] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Do not eagerly build adapters; defer to first execute/health to
        # avoid raising configuration errors at import time during tests.
        if self._adapters is None:
            self._adapters = {}

    @classmethod
    def create(
        cls,
        *,
        config: IronClawSkillConfig | None = None,
        config_path: str | None = None,
    ) -> IronClawRuntime:
        resolved = config or load_config(config_path=config_path)
        return cls(config=resolved)

    @property
    def adapters(self) -> dict[str, RuntimeAdapter]:
        if not self._adapters:
            self._adapters = self._build_adapters()
        return self._adapters

    def execute(self, request: SkillExecutionRequest) -> SkillExecutionResult:
        started_at = _utc_now()
        started_clock = perf_counter()
        try:
            provider_name = self._resolve_provider_name(request)
            adapter = self._require_adapter(provider_name)
            decision = adapter.execute(request)
            result = self._build_result(
                request=request,
                provider_name=provider_name,
                decision=decision,
                started_at=started_at,
                started_clock=started_clock,
            )
            self._enforce_fail_closed(result)
            return result
        except Exception as exc:
            if isinstance(exc, IronClawRuntimeError):
                raise
            raise IronClawRuntimeError(str(exc)) from exc

    def run(self, request: SkillExecutionRequest) -> SkillExecutionResult:
        return self.execute(request)

    def execute_with_trace(
        self,
        request: SkillExecutionRequest,
    ) -> tuple[SkillExecutionResult, RuntimeExecutionTrace]:
        result = self.execute(request)
        started_at = result.startedat or result.finishedat
        finished_at = result.finishedat
        trace = RuntimeExecutionTrace(
            request_id=result.requestid,
            trace_id=str(result.metadata.get("trace_id", self._resolve_trace_id(request))),
            provider=result.provider.value,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=result.usage.latencyms,
            allowed=result.decision is SkillDecision.ALLOW,
            blocked=result.decision is SkillDecision.BLOCK,
            requires_review=result.decision is SkillDecision.REVIEW,
            policy_hits=tuple(self._coerce_str_list(result.metadata.get("policy_hits"))),
            metadata=dict(result.metadata),
        )
        return result, trace

    def health(self) -> JsonDict:
        providers: JsonDict = {}
        for name, adapter in self.adapters.items():
            provider_cfg = self.config.providers.get(name)
            providers[name] = {
                "enabled": bool(provider_cfg.enabled) if provider_cfg else True,
                "configured": bool(provider_cfg.configured) if provider_cfg else True,
                "adapter": adapter.__class__.__name__,
            }
        return {
            "ok": True,
            "app_name": self.config.app_name,
            "environment": self.config.environment,
            "default_provider": self.config.default_provider,
            "fail_closed": self.config.fail_closed,
            "providers": providers,
        }

    def _build_adapters(self) -> dict[str, RuntimeAdapter]:
        adapters: dict[str, RuntimeAdapter] = {}
        openclaw_cfg = self.config.providers.get("openclaw")
        if openclaw_cfg and openclaw_cfg.enabled:
            adapters["openclaw"] = OpenClawSkillAdapter(config=self.config)
        claude_cfg = self.config.providers.get("claude")
        if claude_cfg and claude_cfg.enabled:
            adapters["claude"] = ClaudeSkillAdapter(config=self.config)
        # For import-time health checks and tests, do not raise if there are no
        # enabled adapters; an empty mapping is acceptable and will cause
        # a clear configuration error only when execute() is called.
        return adapters

    def _require_adapter(self, provider_name: str) -> RuntimeAdapter:
        adapter = self.adapters.get(provider_name)
        if adapter is None:
            raise IronClawConfigurationError(f"Provider '{provider_name}' is not available")
        return adapter

    def _resolve_provider_name(self, request: SkillExecutionRequest) -> str:
        provider = getattr(request, "provider", None)
        if isinstance(provider, SkillProvider):
            return provider.value
        normalized = _normalize_text(provider)
        if normalized:
            return normalized.lower()
        default_provider = _normalize_text(self.config.default_provider).lower()
        return default_provider or SkillProvider.OPENCLAW.value

    def _resolve_trace_id(self, request: SkillExecutionRequest) -> str:
        context = getattr(request, "context", None)
        trace_id = _normalize_text(getattr(context, "traceid", None))
        return trace_id or f"trace_{uuid4().hex}"

    def _build_result(
        self,
        *,
        request: SkillExecutionRequest,
        provider_name: str,
        decision: SkillProviderDecision,
        started_at: datetime,
        started_clock: float,
    ) -> SkillExecutionResult:
        finished_at = _utc_now()
        duration_ms = max(0, int((perf_counter() - started_clock) * 1000))
        explicit_decision = self._decision_field(decision, "decision")
        allowed = self._decision_bool(
            decision,
            "allowed",
            default=explicit_decision == SkillDecision.ALLOW,
        )
        blocked = self._decision_bool(
            decision,
            "blocked",
            default=explicit_decision == SkillDecision.BLOCK,
        )
        requires_review = self._decision_bool(
            decision,
            "requires_review",
            default=explicit_decision == SkillDecision.REVIEW,
        )
        resolved_decision = _coerce_skill_decision(
            allowed=allowed,
            blocked=blocked,
            requires_review=requires_review,
            explicit=explicit_decision,
        )
        risk = _coerce_risk_level(self._decision_field(decision, "risk"), default=RiskLevel.LOW)
        usage = self._coerce_usage(self._decision_field(decision, "usage"), duration_ms=duration_ms)
        metadata = _clean_mapping(self._decision_field(decision, "metadata"))
        metadata.update(
            {
                "trace_id": self._resolve_trace_id(request),
                "runtime_provider": provider_name,
                "runtime_environment": self.config.environment,
                "policy_hits": self._coerce_str_list(self._decision_field(decision, "policy_hits")),
                "warnings": self._coerce_str_list(self._decision_field(decision, "warnings")),
                "raw_response": self._decision_field(decision, "raw_response"),
            }
        )
        status = "completed"
        if resolved_decision is SkillDecision.BLOCK:
            status = "blocked"
        elif resolved_decision is SkillDecision.REVIEW:
            status = "review"
        elif resolved_decision is SkillDecision.ERROR:
            status = "failed"
        message = _normalize_text(self._decision_field(decision, "message")) or None
        output_text = _normalize_text(self._decision_field(decision, "output_text")) or None
        return SkillExecutionResult(
            requestid=request.requestid,
            provider=_coerce_provider(provider_name, default=request.provider),
            decision=resolved_decision,
            risk=risk,
            status=status,
            message=message,
            outputtext=output_text,
            usage=usage,
            metadata=metadata,
            startedat=started_at,
            finishedat=finished_at,
        )

    def _enforce_fail_closed(self, result: SkillExecutionResult) -> None:
        if not self.config.fail_closed:
            return
        if result.decision is SkillDecision.ERROR:
            raise IronClawRuntimeError("Runtime decision resolved to error under fail-closed mode")

    @staticmethod
    def _decision_field(decision: Any, name: str) -> Any:
        if hasattr(decision, name):
            return getattr(decision, name)
        if isinstance(decision, dict):
            return decision.get(name)
        return None

    @staticmethod
    def _decision_bool(decision: Any, name: str, default: bool = False) -> bool:
        value = IronClawRuntime._decision_field(decision, name)
        if value is None:
            return default
        return bool(value)

    @staticmethod
    def _coerce_str_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).strip()
        return [text] if text else []

    @staticmethod
    def _coerce_usage(value: Any, *, duration_ms: int) -> SkillUsage:
        if isinstance(value, SkillUsage):
            return value
        if isinstance(value, dict):
            return SkillUsage(
                inputtokens=int(value.get("inputtokens", value.get("input_tokens", 0)) or 0),
                outputtokens=int(value.get("outputtokens", value.get("output_tokens", 0)) or 0),
                totaltokens=int(value.get("totaltokens", value.get("total_tokens", 0)) or 0),
                computeunits=int(value.get("computeunits", value.get("compute_units", 0)) or 0),
                billableunits=int(value.get("billableunits", value.get("billable_units", 0)) or 0),
                estimatedcostusd=float(
                    value.get("estimatedcostusd", value.get("estimated_cost_usd", 0.0)) or 0.0
                ),
                latencyms=int(value.get("latencyms", duration_ms) or duration_ms),
            )
        return SkillUsage(latencyms=duration_ms)


IronClawSkillRuntime = IronClawRuntime


def create_runtime(
    *,
    config: IronClawSkillConfig | None = None,
    config_path: str | None = None,
) -> IronClawRuntime:
    return IronClawRuntime.create(config=config, config_path=config_path)


# Backwards-compatible alias for router imports
createruntime = create_runtime


def runtimesnapshot(
    *,
    config: IronClawSkillConfig | None = None,
    config_path: str | None = None,
) -> JsonDict:
    """
    Backwards-compatible helper for CLI: return a lightweight runtime
    health snapshot without forcing callers to construct a runtime directly.
    """
    runtime = IronClawRuntime.create(config=config, config_path=config_path)
    return runtime.health()


__all__ = [
    "IronClawRuntime",
    "IronClawSkillRuntime",
    "RuntimeExecutionTrace",
    "RuntimeAdapter",
    "create_runtime",
    "createruntime",
    "runtimesnapshot",
]