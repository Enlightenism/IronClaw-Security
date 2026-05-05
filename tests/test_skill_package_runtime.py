from __future__ import annotations

from dataclasses import is_dataclass, replace
from typing import Any, Mapping, MutableMapping
from uuid import uuid4

import pytest

import ironclawskill
from ironclawskill.config import IronClawSkillConfig
from ironclawskill.context import (
    SkillRequestContext,
    SkillRuntimeContext,
    createrequestcontext,
    createruntimecontext,
)
from ironclawskill.contracts import (
    RiskLevel,
    SkillDecision,
    SkillExecutionRequest,
    SkillExecutionResult,
    SkillExecutionTarget,
    SkillInputArtifact,
    SkillMode,
    SkillOutputArtifact,
    SkillPolicyHint,
    SkillProvider,
    SkillReason,
    SkillUsage,
)
from ironclawskill.errors import (
    ErrorContext,
    IronClawSkillError,
    SkillConfigurationError,
    SkillPolicyBlockedError,
    SkillValidationError,
)
from ironclawskill.middleware import (
    IronClawSkillMiddleware,
    SkillHandler,
    buildmiddleware,
)
from ironclawskill.runtime import IronClawSkillRuntime


# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def base_config() -> IronClawSkillConfig:
    config = IronClawSkillConfig.load()
    assert isinstance(config.environment, str)
    assert isinstance(config.default_provider, str)
    assert config.default_provider in {
        SkillProvider.CLAUDE.value,
        SkillProvider.OPENCLAW.value,
    }
    return config


@pytest.fixture
def runtime(base_config: IronClawSkillConfig) -> IronClawSkillRuntime:
    instance = IronClawSkillRuntime(config=base_config)
    assert instance.config is base_config
    assert callable(getattr(instance, "execute", None))
    return instance


@pytest.fixture
def middleware(
    runtime: IronClawSkillRuntime,
    base_config: IronClawSkillConfig,
) -> IronClawSkillMiddleware:
    mw = buildmiddleware(runtime=runtime, config=base_config)
    assert isinstance(mw, IronClawSkillMiddleware)
    return mw


def _uuid() -> str:
    return uuid4().hex


def make_request_context(**overrides: Any) -> SkillRequestContext:
    ctx = createrequestcontext(
        sessionid=overrides.get("session_id", "sess-runtime"),
        organizationid=overrides.get("organization_id", "org-runtime"),
        customerid=overrides.get("customer_id", "cust-runtime"),
        actorid=overrides.get("actor_id", "actor-runtime"),
        environment=overrides.get("environment", "production"),
        region=overrides.get("region", "us-east-1"),
        sourceip=overrides.get("source_ip", "127.0.0.1"),
        useragent=overrides.get("user_agent", "pytest/ironclaw-skill-runtime"),
        route=overrides.get("route", "/runtime/test"),
        method=overrides.get("method", "POST"),
        tags=overrides.get("tags", ("runtime",)),
        labels=overrides.get("labels", {"layer": "runtime"}),
        metadata=overrides.get("metadata", {"pipeline": "tests"}),
    )
    assert is_dataclass(ctx)
    return ctx


def make_runtime_context(
    provider: SkillProvider,
    request_context: SkillRequestContext,
    **overrides: Any,
) -> SkillRuntimeContext:
    ctx = createruntimecontext(
        provider=provider.value,
        request=request_context,
        operation=overrides.get("operation", "execute"),
        capability=overrides.get("capability"),
        policyid=overrides.get("policy_id"),
        reviewrequired=overrides.get("review_required", False),
        sandboxenabled=overrides.get("sandbox_enabled", True),
        networkallowed=overrides.get("network_allowed", False),
        filesystemwriteallowed=overrides.get("filesystem_write_allowed", False),
        toolinvocationallowed=overrides.get("tool_invocation_allowed", False),
        metadata=overrides.get("metadata", {"layer": "runtime"}),
    )
    assert is_dataclass(ctx)
    return ctx


def make_target(**overrides: Any) -> SkillExecutionTarget:
    target = SkillExecutionTarget(
        targetid=overrides.get("targetid", "runtime"),
        targettype=overrides.get("targettype", "runtime"),
        name=overrides.get("name", "ironclaw-runtime"),
        version=overrides.get("version", "test-suite"),
    )
    assert is_dataclass(target)
    return target


def make_execution_request(
    provider: SkillProvider,
    prompt: str = "echo test",
    **overrides: Any,
) -> SkillExecutionRequest:
    actor = ironclawskill.SkillActor(
        actorid=overrides.get("actor_id", "actor-runtime"),
        actortype="user",
        displayname=overrides.get("display_name", "Runtime Tester"),
        organizationid=overrides.get("organization_id", "org-runtime"),
        roles=overrides.get("roles", ("tester",)),
    )
    target = make_target(**overrides.get("target_overrides", {}))
    context_snapshot = ironclawskill.SkillContextSnapshot(
        requestid=overrides.get("request_id", _uuid()),
        sessionid=overrides.get("session_id", "sess-runtime"),
        traceid=overrides.get("trace_id", _uuid()),
        correlationid=overrides.get("correlation_id", _uuid()),
        organizationid=overrides.get("organization_id", "org-runtime"),
        customerid=overrides.get("customer_id", "cust-runtime"),
        environment=overrides.get("environment", "production"),
        region=overrides.get("region", "us-east-1"),
        labels=overrides.get("labels", {"layer": "runtime"}),
        metadata=overrides.get("metadata", {"pipeline": "tests"}),
    )
    input_artifacts = (
        SkillInputArtifact(
            artifactid=_uuid(),
            kind="text",
            name="prompt",
            mimetype="text/plain",
            content=prompt,
            uri=None,
            sha256=None,
            sizebytes=len(prompt),
            metadata={"role": "user"},
        ),
    )
    policy = SkillPolicyHint(
        allownetwork=overrides.get("allow_network", False),
        allowfilesystemwrite=overrides.get("allow_filesystem_write", False),
        allowtoolinvocation=overrides.get("allow_tool_invocation", False),
        allowshellexecution=overrides.get("allow_shell_execution", False),
        maxoutputbytes=overrides.get("max_output_bytes"),
        maxruntimeseconds=overrides.get("max_runtime_seconds"),
        classification=overrides.get("classification"),
        requiredcontrols=overrides.get("required_controls", ()),
        metadata=overrides.get("policymetadata", {}),
    )
    request = SkillExecutionRequest(
        requestid=context_snapshot.requestid,
        provider=provider,
        mode=SkillMode.SYNC,
        operation=overrides.get("operation", "execute"),
        actor=actor,
        target=target,
        context=context_snapshot,
        prompt=prompt,
        systemprompt=overrides.get("system_prompt"),
        inputartifacts=input_artifacts,
        policy=policy,
        capabilities=overrides.get("capabilities", ("shell",)),
        tags=overrides.get("tags", ("runtime",)),
        metadata=overrides.get("metadata", {"pipeline": "tests"}),
    )
    assert is_dataclass(request)
    return request


def make_execution_result(
    request: SkillExecutionRequest,
    decision: SkillDecision = SkillDecision.ALLOW,
    risk: RiskLevel = RiskLevel.LOW,
    message: str | None = "ok",
    output_text: str | None = "execution-completed",
    **overrides: Any,
) -> SkillExecutionResult:
    usage = SkillUsage(
        inputtokens=overrides.get("input_tokens", 10),
        outputtokens=overrides.get("output_tokens", 5),
        totaltokens=overrides.get("total_tokens", 15),
        computeunits=overrides.get("compute_units", 1),
        billableunits=overrides.get("billable_units", 1),
        estimatedcostusd=overrides.get("estimated_cost_usd", 0.0),
        latencyms=overrides.get("latency_ms", 25),
    )
    output_artifacts = (
        SkillOutputArtifact(
            artifactid=_uuid(),
            kind="text",
            name="stdout",
            mimetype="text/plain",
            content=output_text or "",
            uri=None,
            sha256=None,
            sizebytes=len(output_text or ""),
            metadata={"channel": "stdout"},
        ),
    )
    events: tuple[ironclawskill.SkillExecutionEvent, ...] = (
        ironclawskill.SkillExecutionEvent(
            eventid=_uuid(),
            kind=ironclawskill.EventKind.EXECUTION,
            message="shell start",
        ),
        ironclawskill.SkillExecutionEvent(
            eventid=_uuid(),
            kind=ironclawskill.EventKind.EXECUTION,
            message="shell stop",
        ),
    )
    detections: tuple[ironclawskill.SkillDetection, ...] = overrides.get(
        "detections",
        (),
    )

    result = SkillExecutionResult(
        requestid=request.requestid,
        provider=request.provider,
        decision=decision,
        risk=risk,
        status=overrides.get("status", "completed"),
        message=message,
        outputtext=output_text,
        outputartifacts=output_artifacts,
        detections=detections,
        events=events,
        usage=usage,
        metadata=overrides.get("metadata", {"phase": "runtime"}),
    )
    assert is_dataclass(result)
    return result


# ---------------------------------------------------------------------------
# Runtime orchestration: happy path
# ---------------------------------------------------------------------------


async def _echo_handler(payload: Mapping[str, Any]) -> dict[str, Any]:
    request_context = payload.get("requestcontext")
    runtime_context = payload.get("runtimecontext")
    target_payload = payload.get("target")

    assert isinstance(request_context, SkillRequestContext)
    assert isinstance(runtime_context, SkillRuntimeContext)

    provider = ironclawskill.SkillProvider.OPENCLAW
    request_id = request_context.requestid or _uuid()
    trace_id = request_context.traceid or _uuid()

    return {
        "requestid": request_id,
        "traceid": trace_id,
        "provider": provider.value,
        "decision": SkillDecision.ALLOW.value,
        "risk": RiskLevel.LOW.value,
        "summary": "Execution allowed by test runtime.",
        "outputtext": "ok",
        "usage": {
            "inputtokens": 10,
            "outputtokens": 5,
            "totaltokens": 15,
            "latencyms": 12,
        },
        "outputartifacts": [
            {
                "artifactid": _uuid(),
                "name": "stdout",
                "mediatype": "text/plain",
                "content": "ok",
                "disposition": "inline",
                "metadata": {"channel": "stdout"},
            }
        ],
        "inputartifacts": [],
        "policyhints": [],
        "metadata": {
            "provider": provider.value,
            "operation": runtime_context.operation,
            "targetid": (
                target_payload.get("targetid")
                if isinstance(target_payload, Mapping)
                else None
            ),
        },
    }


@pytest.mark.asyncio
async def test_middleware_executes_happy_path(
    runtime: IronClawSkillRuntime,
    middleware: IronClawSkillMiddleware,
) -> None:
    request_context = make_request_context()
    provider = SkillProvider.OPENCLAW
    runtime_context = make_runtime_context(
        provider=provider,
        request_context=request_context,
    )
    target = make_target()

    payload: MutableMapping[str, Any] = {
        "provider": provider.value,
        "operation": "execute",
        "action": "execute",
        "content": "echo hello",
        "target": "runtime",
        "requestid": request_context.requestid or _uuid(),
        "traceid": request_context.traceid or _uuid(),
        "requestcontext": request_context,
        "runtimecontext": runtime_context,
        "targetpayload": {
            "targetid": target.targetid,
            "targettype": target.targettype,
            "name": target.name,
            "version": target.version,
        },
        "metadata": {"layer": "runtime"},
    }

    result_mapping = await middleware.dispatch(
        payload, handler=_echo_handler  # type: ignore[arg-type]
    )
    assert isinstance(result_mapping, dict)
    assert result_mapping.get("decision") == SkillDecision.ALLOW.value
    assert result_mapping.get("provider") == provider.value
    assert result_mapping.get("status") == "completed"
    assert result_mapping.get("summary")
    assert result_mapping.get("result")
    assert "requestid" in result_mapping
    assert "traceid" in result_mapping
    assert "risk" in result_mapping


# ---------------------------------------------------------------------------
# Runtime orchestration: policy enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_blocks_when_runtime_policy_conflicts_with_config(
    base_config: IronClawSkillConfig,
    runtime: IronClawSkillRuntime,
) -> None:
    locked_config = IronClawSkillConfig(
        app_name=base_config.app_name,
        environment=base_config.environment,
        default_provider=base_config.default_provider,
        fail_closed=base_config.fail_closed,
        telemetry_enabled=base_config.telemetry_enabled,
        debug=base_config.debug,
        paths=base_config.paths,
        security=replace(
            base_config.security,
            allow_network=False,
            allow_filesystem_write=base_config.security.allow_filesystem_write,
            allow_tool_invocation=base_config.security.allow_tool_invocation,
        ),
        providers=base_config.providers,
        metadata=base_config.metadata,
    )
    mw = buildmiddleware(runtime=runtime, config=locked_config)

    request_context = make_request_context()
    provider = SkillProvider.OPENCLAW
    runtime_context = make_runtime_context(
        provider=provider,
        request_context=request_context,
        network_allowed=True,
    )

    payload: MutableMapping[str, Any] = {
        "provider": provider.value,
        "operation": "execute",
        "action": "execute",
        "content": "curl https://example.test",
        "requestid": request_context.requestid or _uuid(),
        "traceid": request_context.traceid or _uuid(),
        "requestcontext": request_context,
        "runtimecontext": runtime_context,
        "metadata": {"layer": "runtime"},
    }

    async def handler(_: Mapping[str, Any]) -> Mapping[str, Any]:
        pytest.fail("Handler should not be called when policy blocks execution.")

    result_mapping = await mw.dispatch(
        payload, handler=handler  # type: ignore[arg-type]
    )
    assert isinstance(result_mapping, dict)
    assert result_mapping.get("decision") in {
        SkillDecision.ERROR.value,
        SkillDecision.BLOCK.value,
    }
    assert result_mapping.get("status") in {"blocked", "failed"}
    error = result_mapping.get("result") or {}
    assert isinstance(error, Mapping)
    assert error.get("risk") in {
        RiskLevel.HIGH.value,
        RiskLevel.CRITICAL.value,
    }


# ---------------------------------------------------------------------------
# Runtime orchestration: invalid request handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_rejects_invalid_request_shape(
    middleware: IronClawSkillMiddleware,
) -> None:
    payload: MutableMapping[str, Any] = {
        "provider": "openclaw",
        "content": "echo invalid",
    }

    async def handler(_: Mapping[str, Any]) -> Mapping[str, Any]:
        pytest.fail("Handler should not be called when request is invalid.")

    result_mapping = await middleware.dispatch(
        payload, handler=handler  # type: ignore[arg-type]
    )
    assert isinstance(result_mapping, dict)
    assert result_mapping.get("decision") == SkillDecision.ERROR.value
    assert result_mapping.get("status") == "failed"
    result = result_mapping.get("result") or {}
    assert isinstance(result, Mapping)
    error = result.get("error") or {}
    assert isinstance(error, Mapping)
    assert error.get("code") in {
        "skillvalidationerror",
        "skillconfigurationerror",
    }


# ---------------------------------------------------------------------------
# Runtime orchestration: error normalization
# ---------------------------------------------------------------------------


class _SentinelRuntimeError(IronClawSkillError):
    """Custom error type for verifying middleware error normalization."""

    statuscode = 599
    errorcode = "testruntimeerror"


@pytest.mark.asyncio
async def test_middleware_normalizes_ironclaw_skill_errors(
    middleware: IronClawSkillMiddleware,
) -> None:
    request_context = make_request_context()
    provider = SkillProvider.CLAUDE
    runtime_context = make_runtime_context(
        provider=provider,
        request_context=request_context,
    )

    payload: MutableMapping[str, Any] = {
        "provider": provider.value,
        "operation": "execute",
        "action": "execute",
        "content": "echo fail",
        "requestid": request_context.requestid or _uuid(),
        "traceid": request_context.traceid or _uuid(),
        "requestcontext": request_context,
        "runtimecontext": runtime_context,
        "metadata": {"layer": "runtime"},
    }

    async def handler(_: Mapping[str, Any]) -> Mapping[str, Any]:
        context = ErrorContext(
            requestid=request_context.requestid,
            provider=provider,
            operation=runtime_context.operation,
            risk=RiskLevel.HIGH,
            metadata={"phase": "dispatch"},
        )
        raise _SentinelRuntimeError("Injected runtime failure.", context=context)

    result_mapping = await middleware.dispatch(
        payload, handler=handler  # type: ignore[arg-type]
    )
    assert isinstance(result_mapping, dict)
    assert result_mapping.get("decision") == SkillDecision.ERROR.value
    assert result_mapping.get("status") == "failed"
    assert result_mapping.get("summary") == "Injected runtime failure."
    result = result_mapping.get("result") or {}
    assert isinstance(result, Mapping)
    err_meta = result.get("error") or {}
    assert isinstance(err_meta, Mapping)
    assert err_meta.get("code") == "testruntimeerror"
    assert err_meta.get("status") == 599
    assert err_meta.get("decision") == SkillDecision.ERROR.value
    assert err_meta.get("retryable") is False
    assert result.get("risk") in {
        RiskLevel.HIGH.value,
        RiskLevel.CRITICAL.value,
    }
    assert result.get("metadata", {}).get("phase") == "dispatch"