from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Protocol
from uuid import uuid4

from .adapterclaude import ClaudeSkillAdapter
from .adaptergroq import GroqSkillAdapter
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
    if normalized == SkillProvider.GROQ.value:
        return SkillProvider.GROQ
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
    def execute(self, request: SkillExecutionRequest) -> SkillProviderDecision: ...


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
        groq_cfg = self.config.providers.get("groq")
        if groq_cfg and groq_cfg.enabled:
            adapters["groq"] = GroqSkillAdapter(config=self.config)
        return adapters

    def _require_adapter(self, provider_name: str) -> RuntimeAdapter:
        adapter = self.adapters.get(provider_name)
        if adapter is None:
            raise IronClawConfigurationError(f"Provider '{provider_name}' is not available")
        return adapter

    def _resolve_provider_name(self, request: SkillExecutionRequest) -> str:
        provider = getattr(request, "provider", None)
        coerced = _coerce_provider(provider, SkillProvider.OPENCLAW)
        if coerced is not SkillProvider.OPENCLAW or (isinstance(provider, SkillProvider) and provider is SkillProvider.OPENCLAW):
            return coerced.value
        normalized = _normalize_text(getattr(provider, "value", provider)).lower()
        if normalized:
            return normalized
        default = _normalize_text(self.config.default_provider).lower()
        return default or SkillProvider.OPENCLAW.value

    def _resolve_trace_id(self, request: SkillExecutionRequest) -> str:
        ctx = getattr(request, "context", None)
        if ctx is not None:
            tid = getattr(ctx, "traceid", None)
            if tid:
                return str(tid)
        return str(uuid4())

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
        elapsed_ms = int((perf_counter() - started_clock) * 1000)
        coerced_decision = _coerce_skill_decision(
            allowed=decision.decision is SkillDecision.ALLOW,
            blocked=decision.decision is SkillDecision.BLOCK,
            requires_review=decision.decision is SkillDecision.REVIEW,
            explicit=decision.decision,
        )
        coerced_risk = _coerce_risk_level(decision.risk)
        usage = decision.usage if isinstance(decision.usage, SkillUsage) else SkillUsage()
        updated_usage = SkillUsage(
            inputtokens=usage.inputtokens,
            outputtokens=usage.outputtokens,
            totaltokens=usage.totaltokens,
            computeunits=usage.computeunits,
            billableunits=usage.billableunits,
            estimatedcostusd=usage.estimatedcostusd,
            latencyms=elapsed_ms,
        )
        metadata = _clean_mapping(dict(decision.metadata))
        metadata.setdefault("trace_id", self._resolve_trace_id(request))
        if decision.reasons:
            metadata["policy_hits"] = [r.label for r in decision.reasons if r.label]
        provider = _coerce_provider(provider_name, SkillProvider.OPENCLAW)
        status_map = {
            SkillDecision.ALLOW: "completed",
            SkillDecision.BLOCK: "blocked",
            SkillDecision.REVIEW: "review",
            SkillDecision.ERROR: "failed",
        }
        return SkillExecutionResult(
            requestid=request.requestid,
            provider=provider,
            decision=coerced_decision,
            risk=coerced_risk,
            status=status_map.get(coerced_decision, "completed"),
            usage=updated_usage,
            metadata=metadata,
            startedat=started_at,
            finishedat=finished_at,
        )

    def _enforce_fail_closed(self, result: SkillExecutionResult) -> None:
        if self.config.fail_closed and result.decision is SkillDecision.ERROR:
            raise IronClawRuntimeError(f"Fail-closed policy triggered: execution returned ERROR for request '{result.requestid}'")

    @staticmethod
    def _coerce_str_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value]
        return [str(value)]


# Alias — test and middleware imports use IronClawSkillRuntime
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
    runtime = IronClawRuntime.create(config=config, config_path=config_path)
    return runtime.health()


__all__ = [
    "IronClawRuntime",
    "IronClawSkillRuntime",
    "RuntimeAdapter",
    "RuntimeExecutionTrace",
    "create_runtime",
    "createruntime",
    "runtimesnapshot",
]
