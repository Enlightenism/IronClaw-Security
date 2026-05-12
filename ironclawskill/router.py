from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from .adapterclaude import ClaudeSkillAdapter, adaptclauderequest, adaptclauderesponse
from .adapteropenclaw import OpenClawSkillAdapter, adaptopenclawrequest, adaptopenclawresponse
from .config import IronClawSkillConfig, loadconfig
from .contracts import (
    SkillDecision,
    SkillExecutionRequest,
    SkillExecutionResult,
    SkillProvider,
)
from .errors import (
    ErrorContext,
    IronClawSkillError,
    SkillConfigurationError,
    SkillValidationError,
)
from .middleware import IronClawSkillMiddleware
from .runtime import IronClawSkillRuntime, createruntime


def _new_router(*, config: IronClawSkillConfig | None = None) -> APIRouter:
    router = APIRouter(prefix="/ironclawskill", tags=["ironclaw-skill"])
    state = _RouterState(config=config)

    @router.get("/health", response_model="SkillRouterHealthResponse")
    async def health() -> SkillRouterHealthResponse:  # type: ignore[name-defined]
        return state.health()

    @router.get("/providers", response_model="SkillProviderRegistryResponse")
    async def providers() -> SkillProviderRegistryResponse:  # type: ignore[name-defined]
        return state.providers()

    @router.post(
        "/execute",
        response_model="SkillExecutionEnvelope",
        status_code=status.HTTP_200_OK,
    )
    async def execute(request: SkillExecutionAPIRequest) -> SkillExecutionEnvelope:  # type: ignore[name-defined]
        return await state.execute(request)

    @router.post(
        "/claude",
        response_model=dict[str, Any],
        status_code=status.HTTP_200_OK,
    )
    async def claude(request: dict[str, Any]) -> dict[str, Any]:
        return await state.execute_claude(request)

    @router.post(
        "/openclaw",
        response_model=dict[str, Any],
        status_code=status.HTTP_200_OK,
    )
    async def openclaw(request: dict[str, Any]) -> dict[str, Any]:
        return await state.execute_openclaw(request)

    return router


def _provider_value(value: Any) -> SkillProvider:
    if isinstance(value, SkillProvider):
        return value
    normalized = str(value or "").strip().lower()
    if normalized == SkillProvider.CLAUDE.value:
        return SkillProvider.CLAUDE
    return SkillProvider.OPENCLAW


def _decision_value(value: Any) -> SkillDecision:
    if isinstance(value, SkillDecision):
        return value
    normalized = str(value or "").strip().lower()
    for item in SkillDecision:
        if item.value == normalized:
            return item
    return SkillDecision.ERROR


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


class SkillExecutionAPIRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    provider: str | None = Field(default=None)
    operation: str = Field(default="execute", min_length=1)
    action: str = Field(default="execute", min_length=1)
    target: str = Field(default="runtime", min_length=1)
    content: str = Field(default="")
    model: str | None = Field(default=None)
    systemprompt: str | None = Field(default=None)
    messages: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    requestid: str | None = Field(default=None)
    traceid: str | None = Field(default=None)
    sessionid: str | None = Field(default=None)
    organizationid: str | None = Field(default=None)
    customerid: str | None = Field(default=None)
    actorid: str | None = Field(default=None)
    reviewrequired: bool = Field(default=False)
    sandboxenabled: bool | None = Field(default=None)
    networkallowed: bool | None = Field(default=None)
    filesystemwriteallowed: bool | None = Field(default=None)
    toolinvocationallowed: bool | None = Field(default=None)


class SkillExecutionEnvelope(BaseModel):
    """
    Lightweight API envelope; keep `result` as an untyped mapping so Pydantic
    does not recurse through arbitrary JsonValue and hit recursive type limits.
    """

    model_config = ConfigDict(extra="allow")

    requestid: str
    traceid: str
    provider: str
    decision: str
    summary: str
    allowed: bool
    blocked: bool
    reviewrequired: bool
    statuscode: int
    result: dict[str, Any] = Field(default_factory=dict)


class SkillProviderDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool
    configured: bool
    default: bool
    model: str | None = None
    endpoint: str | None = None
    timeoutseconds: int
    connecttimeoutseconds: int
    maxretries: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class SkillProviderRegistryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaultprovider: str
    enabledproviders: list[str] = Field(default_factory=list)
    providers: list[SkillProviderDescriptor] = Field(default_factory=list)


class SkillRouterHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    appname: str
    environment: str
    defaultprovider: str
    failclosed: bool
    telemetryenabled: bool
    providersconfigured: int
    providersenabled: int
    sandboxenabled: bool
    runtime: dict[str, Any] = Field(default_factory=dict)


class _RouterState:
    def __init__(self, *, config: IronClawSkillConfig | None = None) -> None:
        self.config = config or loadconfig()
        self.runtime: IronClawSkillRuntime = createruntime(config=self.config)  # lazy adapters now
        self.middleware = IronClawSkillMiddleware(config=self.config)
        self.claude = ClaudeSkillAdapter(config=self.config)
        self.openclaw = OpenClawSkillAdapter(config=self.config)

    def health(self) -> SkillRouterHealthResponse:
        providers = list(self.config.providers.values())
        enabled = [provider for provider in providers if provider.enabled]
        configured = [provider for provider in providers if provider.enabled and provider.configured]
        return SkillRouterHealthResponse(
            status="ok",
            appname=self.config.appname,
            environment=self.config.environment,
            defaultprovider=self.config.defaultprovider,
            failclosed=self.config.failclosed,
            telemetryenabled=self.config.telemetryenabled,
            providersconfigured=len(configured),
            providersenabled=len(enabled),
            sandboxenabled=self.config.security.enablesandbox,
            runtime={
                "adaptercount": len(self.runtime.adapters),
                "enabledproviders": list(self.config.enabledproviders),
                "auditlogpath": str(self.config.paths.auditlogpath) if self.config.paths.auditlogpath else None,
                "rulesdir": str(self.config.paths.rulesdir) if self.config.paths.rulesdir else None,
                "quarantinedir": str(self.config.paths.quarantinedir) if self.config.paths.quarantinedir else None,
                "outputdir": str(self.config.paths.outputdir) if self.config.paths.outputdir else None,
            },
        )

    def providers(self) -> SkillProviderRegistryResponse:
        items: list[SkillProviderDescriptor] = []
        for name, provider in sorted(self.config.providers.items(), key=lambda item: item[0]):
            items.append(
                SkillProviderDescriptor(
                    name=name,
                    enabled=provider.enabled,
                    configured=provider.configured,
                    default=name == self.config.defaultprovider,
                    model=provider.model,
                    endpoint=provider.endpoint,
                    timeoutseconds=provider.timeoutseconds,
                    connecttimeoutseconds=provider.connecttimeoutseconds,
                    maxretries=provider.maxretries,
                    metadata=dict(provider.metadata),
                )
            )
        return SkillProviderRegistryResponse(
            defaultprovider=self.config.defaultprovider,
            enabledproviders=list(self.config.enabledproviders),
            providers=items,
        )

    async def execute(self, request: SkillExecutionAPIRequest) -> SkillExecutionEnvelope:
        payload = request.model_dump(mode="json")

        async def handler(guardedpayload: dict[str, Any]) -> dict[str, Any]:
            result = self.runtime.execute(self._to_execution_request(guardedpayload))
            return self._result_payload(result)

        result = await self.middleware.dispatch(payload, handler)
        return self._envelope_from_result(result)

    async def execute_claude(self, request: dict[str, Any]) -> dict[str, Any]:
        normalized = adaptclauderequest(request)

        async def handler(guardedpayload: dict[str, Any]) -> dict[str, Any]:
            runtimepayload = self._skill_request_to_runtime_payload(guardedpayload, provider=SkillProvider.CLAUDE)
            result = self.runtime.execute(self._to_execution_request(runtimepayload))
            return self._result_payload(result)

        result = await self.middleware.dispatch(normalized, handler)
        return adaptclauderesponse(self._envelope_to_result_payload(result))

    async def execute_openclaw(self, request: dict[str, Any]) -> dict[str, Any]:
        normalized = adaptopenclawrequest(request)

        async def handler(guardedpayload: dict[str, Any]) -> dict[str, Any]:
            runtimepayload = self._skill_request_to_runtime_payload(guardedpayload, provider=SkillProvider.OPENCLAW)
            result = self.runtime.execute(self._to_execution_request(runtimepayload))
            return self._result_payload(result)

        result = await self.middleware.dispatch(normalized, handler)
        return adaptopenclawresponse(self._envelope_to_result_payload(result))

    def _to_execution_request(self, payload: dict[str, Any]) -> SkillExecutionRequest:
        try:
            return SkillExecutionRequest(
                provider=str(payload.get("provider") or self.config.defaultprovider),
                requestid=str(payload.get("requestid") or ""),
                traceid=str(payload.get("traceid") or ""),
                sessionid=self._optional_text(payload.get("sessionid")),
                organizationid=self._optional_text(payload.get("organizationid")),
                customerid=self._optional_text(payload.get("customerid")),
                actorid=self._optional_text(payload.get("actorid")),
                operation=str(payload.get("operation") or "execute"),
                action=str(payload.get("action") or payload.get("actiontype") or "execute"),
                target=str(payload.get("target") or "runtime"),
                content=str(payload.get("content") or ""),
                model=self._optional_text(payload.get("model")),
                systemprompt=self._optional_text(payload.get("systemprompt")),
                messages=list(payload.get("messages") or []),
                metadata=dict(payload.get("metadata") or {}),
                reviewrequired=bool(payload.get("reviewrequired", False)),
                sandboxenabled=self._coerce_bool(payload.get("sandboxenabled"), self.config.security.enablesandbox),
                networkallowed=self._coerce_bool(payload.get("networkallowed"), self.config.security.allownetwork),
                filesystemwriteallowed=self._coerce_bool(
                    payload.get("filesystemwriteallowed"),
                    self.config.security.allowfilesystemwrite,
                ),
                toolinvocationallowed=self._coerce_bool(
                    payload.get("toolinvocationallowed"),
                    self.config.security.allowtoolinvocation,
                ),
            )
        except Exception as exc:
            raise self._http_error(
                SkillValidationError(
                    "Invalid skill execution request.",
                    context=ErrorContext(
                        requestid=str(payload.get("requestid") or ""),
                        provider=_provider_value(payload.get("provider") or self.config.defaultprovider),
                        operation=str(payload.get("operation") or "execute"),
                    ),
                    details={"error": str(exc)},
                )
            ) from exc

    def _result_payload(self, result: SkillExecutionResult) -> dict[str, Any]:
        if hasattr(result, "asdict") and callable(result.asdict):
            payload = result.asdict()
            if isinstance(payload, dict):
                return payload
        if hasattr(result, "model_dump") and callable(result.model_dump):
            payload = result.model_dump(mode="json")
            if isinstance(payload, dict):
                return payload
        raise self._http_error(
            SkillConfigurationError(
                "Skill runtime returned an unsupported result payload.",
                details={"resulttype": type(result).__name__},
            )
        )

    def _envelope_from_result(self, result: dict[str, Any]) -> SkillExecutionEnvelope:
        decision = _decision_value(result.get("decision"))
        statuscode = int(result.get("statuscode") or self._status_for_decision(decision))
        return SkillExecutionEnvelope(
            requestid=str(result.get("requestid") or ""),
            traceid=str(result.get("traceid") or ""),
            provider=str(result.get("provider") or self.config.defaultprovider),
            decision=decision.value,
            summary=str(result.get("summary") or ""),
            allowed=bool(result.get("allowed", decision is SkillDecision.ALLOW)),
            blocked=bool(result.get("blocked", decision is SkillDecision.BLOCK)),
            reviewrequired=bool(result.get("reviewrequired", decision is SkillDecision.REVIEW)),
            statuscode=statuscode,
            result=result,
        )

    def _envelope_to_result_payload(self, result: dict[str, Any]) -> dict[str, Any]:
        if "result" in result and isinstance(result["result"], dict):
            return dict(result["result"])
        return dict(result)

    def _skill_request_to_runtime_payload(
        self,
        payload: dict[str, Any],
        *,
        provider: SkillProvider,
    ) -> dict[str, Any]:
        normalized = dict(payload)
        normalized["provider"] = provider.value
        normalized.setdefault("operation", str(payload.get("operation") or "execute"))
        normalized.setdefault("action", str(payload.get("action") or payload.get("actiontype") or "execute"))
        normalized.setdefault("target", str(payload.get("target") or "runtime"))
        normalized.setdefault("content", str(payload.get("content") or ""))
        normalized.setdefault("messages", list(payload.get("messages") or []))
        normalized.setdefault("metadata", dict(payload.get("metadata") or {}))
        return normalized

    def _http_error(self, error: IronClawSkillError) -> HTTPException:
        body = error.todict()
        return HTTPException(status_code=error.statuscode, detail=body)

    @staticmethod
    def _status_for_decision(decision: SkillDecision) -> int:
        if decision is SkillDecision.ALLOW:
            return status.HTTP_200_OK
        if decision is SkillDecision.REVIEW:
            return status.HTTP_202_ACCEPTED
        if decision is SkillDecision.BLOCK:
            return status.HTTP_403_FORBIDDEN
        return status.HTTP_500_INTERNAL_SERVER_ERROR

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        text = str(value or "").strip()
        return text or None

    @staticmethod
    def _coerce_bool(value: Any, default: bool) -> bool:
        if value is None:
            return default
        return bool(value)


router = _new_router()


def getrouter(*, config: IronClawSkillConfig | None = None) -> APIRouter:
    return _new_router(config=config)


def createrouter(*, config: IronClawSkillConfig | None = None) -> APIRouter:
    return _new_router(config=config)


class IronClawSkillRouter:
    """
    Backwards-compatible router wrapper used by the CLI.
    """

    def __init__(self, *, config: IronClawSkillConfig | None = None) -> None:
        self._state = _RouterState(config=config)

    def route(self, request: SkillExecutionRequest) -> SkillExecutionEnvelope:
        # Mirror the /execute path: wrap an API request, run through middleware + runtime.
        api_request = SkillExecutionAPIRequest(
            provider=request.provider.value if isinstance(request.provider, SkillProvider) else str(request.provider),
            operation=getattr(request, "operation", "execute"),
            action=getattr(request, "action", "execute"),
            target=getattr(request, "target", "runtime"),
            content=getattr(request, "content", "") or "",
            model=getattr(request, "model", None),
            systemprompt=getattr(request, "systemprompt", None),
            messages=list(getattr(request, "messages", [])),
            metadata=dict(getattr(request, "metadata", {})),
            requestid=getattr(request, "requestid", None),
            traceid=getattr(request, "traceid", None),
            sessionid=getattr(request, "sessionid", None),
            organizationid=getattr(request, "organizationid", None),
            customerid=getattr(request, "customerid", None),
            actorid=getattr(request, "actorid", None),
            reviewrequired=bool(getattr(request, "reviewrequired", False)),
            sandboxenabled=getattr(request, "sandboxenabled", None),
            networkallowed=getattr(request, "networkallowed", None),
            filesystemwriteallowed=getattr(request, "filesystemwriteallowed", None),
            toolinvocationallowed=getattr(request, "toolinvocationallowed", None),
        )
        # Reuse existing execution path
        return self._state._envelope_from_result(
            self._state._result_payload(self._state.runtime.execute(request))
        )


__all__ = [
    "IronClawSkillRouter",
    "SkillExecutionAPIRequest",
    "SkillExecutionEnvelope",
    "SkillProviderDescriptor",
    "SkillProviderRegistryResponse",
    "SkillRouterHealthResponse",
    "createrouter",
    "getrouter",
    "router",
]