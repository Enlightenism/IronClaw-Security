from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import Any, Final

__version__: Final[str] = "0.1.0"
__package_name__: Final[str] = "ironclawskill"

_MODULE_NAMES: Final[tuple[str, ...]] = (
    "adapterclaude",
    "adaptergroq",
    "adapteropenclaw",
    "billing",
    "cli",
    "config",
    "context",
    "contracts",
    "errors",
    "middleware",
    "router",
    "runtime",
)

_EXPORT_NAMES: Final[dict[str, str]] = {
    # contracts
    "SkillProvider": "contracts",
    "SkillMode": "contracts",
    "SkillDecision": "contracts",
    "RiskLevel": "contracts",
    "EventKind": "contracts",
    "SkillActor": "contracts",
    "SkillExecutionTarget": "contracts",
    "SkillContextSnapshot": "contracts",
    "SkillInputArtifact": "contracts",
    "SkillPolicyHint": "contracts",
    "SkillReason": "contracts",
    "SkillDetection": "contracts",
    "SkillUsage": "contracts",
    "SkillOutputArtifact": "contracts",
    "SkillExecutionEvent": "contracts",
    "SkillExecutionResult": "contracts",
    "SkillHealthStatus": "contracts",
    "SkillCapability": "contracts",
    "SkillProviderDecision": "contracts",
    "SkillExecutionRequest": "contracts",
    "SkillResponseEnvelopeRuntime": "contracts",
    "JsonValue": "contracts",  # canonical definition — NOT config
    "JsonPrimitive": "contracts",
    "build_allowed_result": "contracts",
    "build_blocked_result": "contracts",
    "build_error_result": "contracts",
    "build_review_result": "contracts",
    "buildallowedresult": "contracts",
    "buildblockedresult": "contracts",
    "builderrorresult": "contracts",
    "buildreviewresult": "contracts",
    # context
    "SkillRequestContext": "context",
    "SkillRuntimeContext": "context",
    "create_request_context": "context",
    "create_runtime_context": "context",
    "createrequestcontext": "context",
    "createruntimecontext": "context",
    # errors
    "ErrorContext": "errors",
    "IronClawSkillError": "errors",
    "SkillConfigurationError": "errors",
    "SkillValidationError": "errors",
    "SkillAuthenticationError": "errors",
    "SkillAuthorizationError": "errors",
    "SkillPolicyBlockedError": "errors",
    "SkillReviewRequiredError": "errors",
    "SkillProviderUnavailableError": "errors",
    "SkillTimeoutError": "errors",
    "SkillExecutionFailedError": "errors",
    "SkillRateLimitError": "errors",
    "ProviderAuthenticationError": "errors",
    "ProviderExecutionError": "errors",
    "ProviderConfigurationError": "errors",
    "ProviderUnavailableError": "errors",
    "IronClawConfigurationError": "errors",
    "IronClawRuntimeError": "errors",
    "build_error_context": "errors",
    "builderrorcontext": "errors",
    # middleware
    "IronClawSkillMiddleware": "middleware",
    "SkillHandler": "middleware",
    "buildmiddleware": "middleware",
    # runtime
    "IronClawSkillRuntime": "runtime",
    "IronClawRuntime": "runtime",
    "RuntimeAdapter": "runtime",
    "RuntimeExecutionTrace": "runtime",
    "create_runtime": "runtime",
    "createruntime": "runtime",
    "runtimesnapshot": "runtime",
    # router
    "build_router": "router",
    "create_router": "router",
    "get_router": "router",
    "createrouter": "router",
    "getrouter": "router",
    "router": "router",
    "IronClawSkillRouter": "router",
    # config
    "IronClawSkillConfig": "config",
    "PathsConfig": "config",
    "SecurityConfig": "config",
    "ProviderConfig": "config",
    "load_config": "config",
    "loadconfig": "config",
}

__all__ = [
    "__package_name__",
    "__version__",
    *_MODULE_NAMES,
    *_EXPORT_NAMES.keys(),
]


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(globals().keys()))


def __getattr__(name: str) -> Any:
    if name in _MODULE_NAMES:
        module = import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module

    module_name = _EXPORT_NAMES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module: ModuleType = import_module(f"{__name__}.{module_name}")
    value = getattr(module, name)
    globals()[name] = value
    return value
