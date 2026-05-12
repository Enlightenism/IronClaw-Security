from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, is_dataclass, replace
from typing import Any
from uuid import uuid4

from .config import IronClawSkillConfig
from .context import SkillRequestContext, SkillRuntimeContext, createruntimecontext
from .contracts import (
    JsonValue,
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
    buildallowedresult,
    buildblockedresult,
    builderrorresult,
    buildreviewresult,
)
from .errors import (
    ErrorContext,
    IronClawSkillError,
    SkillConfigurationError,
    SkillPolicyBlockedError,
    SkillValidationError,
)
from .runtime import IronClawSkillRuntime

SkillHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def _new_id(prefix: str) -> str:
    return f"{prefix}{uuid4().hex[:12]}"


def _provider_value(value: Any) -> SkillProvider:
    if isinstance(value, SkillProvider):
        return value
    normalized = str(value or "").strip().lower()
    if normalized == SkillProvider.CLAUDE.value:
        return SkillProvider.CLAUDE
    if normalized == SkillProvider.OPENCLAW.value:
        return SkillProvider.OPENCLAW
    return SkillProvider.OPENCLAW


def _risk_value(value: Any) -> RiskLevel:
    if isinstance(value, RiskLevel):
        return value
    normalized = str(value or "").strip().lower()
    for item in RiskLevel:
        if item.value == normalized:
            return item
    return RiskLevel.MEDIUM


def _decision_value(value: Any) -> SkillDecision:
    if isinstance(value, SkillDecision):
        return value
    normalized = str(value or "").strip().lower()
    for item in SkillDecision:
        if item.value == normalized:
            return item
    return SkillDecision.ERROR


def _json_mapping(value: Mapping[str, Any] | None) -> dict[str, JsonValue]:
    return dict(value or {})


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        result: list[str] = []
        seen: set[str] = set()
        for item in value:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            result.append(text)
        return tuple(result)
    text = str(value).strip()
    return (text,) if text else ()


def _request_attr(requestcontext: Any, *names: str) -> Any:
    if requestcontext is None:
        return None
    for name in names:
        if hasattr(requestcontext, name):
            return getattr(requestcontext, name)
    return None


def _runtime_attr(runtimecontext: Any, *names: str) -> Any:
    if runtimecontext is None:
        return None
    for name in names:
        if hasattr(runtimecontext, name):
            return getattr(runtimecontext, name)
    return None


def _config_attr(config: IronClawSkillConfig, *names: str) -> Any:
    for name in names:
        if hasattr(config, name):
            return getattr(config, name)
    return None


def _security_attr(config: IronClawSkillConfig, *names: str) -> Any:
    security = getattr(config, "security", None)
    if security is None:
        return None
    for name in names:
        if hasattr(security, name):
            return getattr(security, name)
    return None


def _bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _result_asdict(result: SkillExecutionResult) -> dict[str, Any]:
    if hasattr(result, "asdict") and callable(result.asdict):
        payload = result.asdict()
        if isinstance(payload, dict):
            return payload
    if hasattr(result, "model_dump") and callable(result.model_dump):
        payload = result.model_dump(mode="json")
        if isinstance(payload, dict):
            return payload
    if is_dataclass(result):
        return asdict(result)
    raise TypeError("Skill execution result cannot be serialized to a mapping.")


def _promote_top_level_fields(
    raw: dict[str, Any],
    result: SkillExecutionResult,
    *,
    traceid: str | None = None,
) -> dict[str, Any]:
    if "traceid" not in raw:
        val = (
            traceid
            or raw.get("metadata", {}).get("traceid")
            or getattr(result, "traceid", None)
        )
        if val:
            raw["traceid"] = val

    if not raw.get("summary"):
        val = getattr(result, "summary", None) or getattr(result, "message", None)
        if isinstance(val, str) and val.strip():
            raw["summary"] = val.strip()

    if not raw.get("status"):
        decision = raw.get("decision")
        if isinstance(decision, SkillDecision):
            decision = decision.value
        if decision == SkillDecision.ALLOW.value:
            raw["status"] = "completed"
        elif decision == SkillDecision.BLOCK.value:
            raw["status"] = "blocked"
        elif decision == SkillDecision.ERROR.value:
            raw["status"] = "failed"
        elif decision == SkillDecision.REVIEW.value:
            raw["status"] = "review"

    nested = raw.get("result")
    if not isinstance(nested, dict):
        nested = {}
        raw["result"] = nested

    if not nested.get("risk"):
        risk = getattr(result, "risk", None)
        if risk is not None:
            nested["risk"] = risk.value if isinstance(risk, RiskLevel) else str(risk)

    nested_metadata = nested.get("metadata")
    if not isinstance(nested_metadata, dict):
        nested_metadata = {}

    result_metadata = getattr(result, "metadata", None)
    if isinstance(result_metadata, Mapping):
        for key, value in result_metadata.items():
            nested_metadata.setdefault(key, value)

    error_metadata = getattr(getattr(result, "error", None), "get", lambda *_: None)("metadata")
    if isinstance(error_metadata, Mapping):
        for key, value in error_metadata.items():
            nested_metadata.setdefault(key, value)

    if nested_metadata:
        nested["metadata"] = nested_metadata

    result_error = getattr(result, "error", None)
    if isinstance(result_error, Mapping) and result_error:
        error_dict = dict(result_error)
    else:
        error_dict = dict(nested.get("error") or {})

    if error_dict:
        nested_error = error_dict.get("error")
        if isinstance(nested_error, Mapping):
            flattened = dict(nested_error)
            for key, value in error_dict.items():
                if key != "error" and key not in flattened:
                    flattened[key] = value
            error_dict = flattened

        if not error_dict.get("code"):
            meta = getattr(result, "metadata", {}) or {}
            errorcode = meta.get("errorcode")
            if isinstance(errorcode, str) and errorcode.strip():
                error_dict["code"] = errorcode.strip()

        if "status" not in error_dict:
            meta = getattr(result, "metadata", {}) or {}
            statuscode = meta.get("statuscode")
            if statuscode is not None:
                error_dict["status"] = statuscode

        if "decision" not in error_dict:
            decision = (
                error_dict.get("decision")
                or raw.get("decision")
                or getattr(result, "decision", None)
            )
            if isinstance(decision, SkillDecision):
                decision = decision.value
            if decision is not None:
                error_dict["decision"] = decision

        nested["error"] = error_dict

    return raw


def _make_skill_reason(
    *,
    label: str,
    detail: str,
    metadata: Mapping[str, Any] | None = None,
) -> SkillReason:
    payload = dict(metadata or {})
    try:
        return SkillReason(
            source="runtime",
            label=label,
            details=detail,
            metadata=payload,
        )
    except TypeError:
        return SkillReason(
            label=label,
            detail=detail,
            metadata=payload,
        )


def _normalize_reason_item(item: Any) -> SkillReason:
    if isinstance(item, SkillReason):
        return item
    if isinstance(item, Mapping):
        label = str(item.get("label") or item.get("code") or "reason").strip() or "reason"
        detail = str(
            item.get("detail")
            or item.get("details")
            or item.get("message")
            or label
        ).strip() or label
        metadata = _json_mapping(item.get("metadata") if isinstance(item.get("metadata"), Mapping) else None)
        return _make_skill_reason(label=label, detail=detail, metadata=metadata)
    text = str(item or "").strip() or "reason"
    return _make_skill_reason(label=text, detail=text, metadata={})


def _normalize_reasons(value: Any) -> tuple[SkillReason, ...]:
    if not value:
        return ()
    items = value if isinstance(value, (list, tuple, set)) else (value,)
    result: list[SkillReason] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        reason = _normalize_reason_item(item)
        label = getattr(reason, "label", "reason")
        detail = getattr(reason, "detail", None) or getattr(reason, "details", None) or label
        key = (str(label), str(detail))
        if key in seen:
            continue
        seen.add(key)
        result.append(reason)
    return tuple(result)


def _normalize_usage(value: Any) -> SkillUsage | None:
    if isinstance(value, SkillUsage):
        return value
    if not isinstance(value, Mapping):
        return None
    try:
        return SkillUsage(
            inputtokens=int(value.get("inputtokens") or value.get("input_tokens") or 0),
            outputtokens=int(value.get("outputtokens") or value.get("output_tokens") or 0),
            totaltokens=int(value.get("totaltokens") or value.get("total_tokens") or 0),
            latencyms=int(value.get("latencyms") or value.get("latency_ms") or 0),
            meteredcost=str(value.get("meteredcost") or value.get("metered_cost") or 0),
            currency=str(value.get("currency") or "USD"),
        )
    except TypeError:
        return None


def _build_input_artifact_from_mapping(item: Mapping[str, Any]) -> SkillInputArtifact:
    artifactid = str(item.get("artifactid") or item.get("artifact_id") or _new_id("inart")).strip()
    kwargs = {
        "artifactid": artifactid,
        "name": str(item.get("name") or artifactid),
        "content": str(item.get("content") or ""),
        "source": str(item.get("source") or "middleware"),
        "metadata": _json_mapping(item.get("metadata") if isinstance(item.get("metadata"), Mapping) else None),
    }
    mediatype = str(item.get("mediatype") or item.get("media_type") or "application/octet-stream")
    mimetype = str(item.get("mimetype") or item.get("mime_type") or mediatype)
    kind = str(item.get("kind") or "text")
    try:
        return SkillInputArtifact(mediatype=mediatype, **kwargs)
    except TypeError:
        pass
    try:
        return SkillInputArtifact(mimetype=mimetype, kind=kind, **kwargs)
    except TypeError:
        pass
    try:
        return SkillInputArtifact(kind=kind, **kwargs)
    except TypeError:
        return SkillInputArtifact(**kwargs)


def _normalize_input_artifacts(value: Any) -> tuple[SkillInputArtifact, ...]:
    if not value:
        return ()
    items = value if isinstance(value, (list, tuple)) else (value,)
    result: list[SkillInputArtifact] = []
    for item in items:
        if isinstance(item, SkillInputArtifact):
            result.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        result.append(_build_input_artifact_from_mapping(item))
    return tuple(result)


def _build_output_artifact_from_mapping(item: Mapping[str, Any]) -> SkillOutputArtifact:
    artifactid = str(item.get("artifactid") or item.get("artifact_id") or _new_id("outart")).strip()
    kwargs = {
        "artifactid": artifactid,
        "name": str(item.get("name") or artifactid),
        "content": str(item.get("content") or ""),
        "metadata": _json_mapping(item.get("metadata") if isinstance(item.get("metadata"), Mapping) else None),
    }
    mediatype = str(item.get("mediatype") or item.get("media_type") or "application/octet-stream")
    mimetype = str(item.get("mimetype") or item.get("mime_type") or mediatype)
    kind = str(item.get("kind") or "text")
    uri = item.get("uri")
    if uri is not None:
        kwargs["uri"] = str(uri)
    try:
        return SkillOutputArtifact(mediatype=mediatype, disposition=str(item.get("disposition") or "inline"), **kwargs)
    except TypeError:
        pass
    try:
        return SkillOutputArtifact(mimetype=mimetype, kind=kind, **kwargs)
    except TypeError:
        pass
    try:
        return SkillOutputArtifact(kind=kind, **kwargs)
    except TypeError:
        return SkillOutputArtifact(**kwargs)


def _normalize_output_artifacts(value: Any) -> tuple[SkillOutputArtifact, ...]:
    if not value:
        return ()
    items = value if isinstance(value, (list, tuple)) else (value,)
    result: list[SkillOutputArtifact] = []
    for item in items:
        if isinstance(item, SkillOutputArtifact):
            result.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        result.append(_build_output_artifact_from_mapping(item))
    return tuple(result)


def _normalize_policy_hints(value: Any) -> tuple[SkillPolicyHint, ...]:
    if not value:
        return ()
    items = value if isinstance(value, (list, tuple)) else (value,)
    result: list[SkillPolicyHint] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        if isinstance(item, SkillPolicyHint):
            code = str(getattr(item, "code", "hint"))
            summary = str(getattr(item, "summary", code))
            key = (code, summary)
            if key not in seen:
                seen.add(key)
                result.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        code = str(item.get("code") or "hint").strip() or "hint"
        summary = str(item.get("summary") or item.get("detail") or code).strip() or code
        key = (code, summary)
        if key in seen:
            continue
        seen.add(key)
        try:
            result.append(
                SkillPolicyHint(
                    code=code,
                    summary=summary,
                    severity=_risk_value(item.get("severity") or item.get("risk")),
                    metadata=_json_mapping(item.get("metadata") if isinstance(item.get("metadata"), Mapping) else None),
                )
            )
        except TypeError:
            try:
                result.append(
                    SkillPolicyHint(
                        allownetwork=_bool_value(item.get("allownetwork") or item.get("allow_network"), False),
                        allowfilesystemwrite=_bool_value(item.get("allowfilesystemwrite") or item.get("allow_filesystem_write"), False),
                        allowtoolinvocation=_bool_value(item.get("allowtoolinvocation") or item.get("allow_tool_invocation"), False),
                        metadata=_json_mapping(item.get("metadata") if isinstance(item.get("metadata"), Mapping) else None),
                    )
                )
            except TypeError:
                continue
    return tuple(result)


def _best_summary(payload: Mapping[str, Any], fallback: str) -> str:
    for key in ("summary", "message", "detail", "outputtext", "output_text"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _extract_output_text(payload: Mapping[str, Any]) -> str:
    for key in ("outputtext", "output_text", "content", "response", "text", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _extract_raw_response(payload: Mapping[str, Any]) -> dict[str, JsonValue]:
    raw = payload.get("rawresponse") or payload.get("raw_response")
    if isinstance(raw, Mapping):
        return dict(raw)
    return dict(payload)


def _extract_result_metadata(
    payload: Mapping[str, Any],
    *,
    requestid: str,
    traceid: str,
    provider: SkillProvider,
    runtimecontext: SkillRuntimeContext,
) -> dict[str, JsonValue]:
    metadata = _json_mapping(payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else None)
    metadata.setdefault("requestid", requestid)
    metadata.setdefault("traceid", traceid)
    metadata.setdefault("provider", provider.value)
    metadata.setdefault("operation", _runtime_attr(runtimecontext, "operation"))
    metadata.setdefault("policyid", _runtime_attr(runtimecontext, "policyid"))
    metadata.setdefault("sandboxenabled", _runtime_attr(runtimecontext, "sandboxenabled"))
    metadata.setdefault("reviewrequired", _runtime_attr(runtimecontext, "reviewrequired"))
    return metadata


def _build_execution_request(
    *,
    requestid: str,
    provider: SkillProvider,
    runtimecontext: SkillRuntimeContext,
    requestcontext: SkillRequestContext,
    target: SkillExecutionTarget,
    mode: SkillMode,
    metadata: Mapping[str, JsonValue] | None = None,
    inputartifacts: tuple[SkillInputArtifact, ...] = (),
    policyhints: tuple[SkillPolicyHint, ...] = (),
) -> SkillExecutionRequest:
    operation = str(_runtime_attr(runtimecontext, "operation") or "execute")
    kwargs = {
        "requestid": requestid,
        "provider": provider,
        "mode": mode,
        "operation": operation,
        "target": target,
        "metadata": dict(metadata or {}),
        "inputartifacts": inputartifacts,
    }
    try:
        return SkillExecutionRequest(
            context=requestcontext,
            policy=getattr(runtimecontext, "policy", None),
            **kwargs,
        )
    except TypeError:
        pass
    try:
        return SkillExecutionRequest(
            requestid=requestid,
            traceid=str(_request_attr(requestcontext, "traceid", "trace_id") or ""),
            provider=provider,
            operation=operation,
            target=target,
            requestcontext=requestcontext,
            runtimecontext=runtimecontext,
            mode=mode,
            metadata=dict(metadata or {}),
            inputartifacts=inputartifacts,
            policyhints=policyhints,
        )
    except TypeError:
        return SkillExecutionRequest(**kwargs)


def _result_from_payload(
    payload: Mapping[str, Any],
    *,
    requestcontext: SkillRequestContext,
    runtimecontext: SkillRuntimeContext,
    target: SkillExecutionTarget,
    fallbackprovider: SkillProvider,
    fallbacksummary: str,
) -> SkillExecutionResult:
    decision = _decision_value(payload.get("decision") or payload.get("verdict"))
    provider = _provider_value(payload.get("provider") or fallbackprovider)
    requestid = str(
        payload.get("requestid")
        or payload.get("request_id")
        or _request_attr(requestcontext, "requestid", "request_id")
        or _new_id("req")
    )
    traceid = str(
        payload.get("traceid")
        or payload.get("trace_id")
        or _request_attr(requestcontext, "traceid", "trace_id")
        or _new_id("trace")
    )
    summary = _best_summary(payload, fallbacksummary)
    risk = _risk_value(payload.get("risk") or payload.get("risklevel") or payload.get("risk_level"))
    reasons = _normalize_reasons(payload.get("reasons"))
    usage = _normalize_usage(payload.get("usage"))
    outputtext = _extract_output_text(payload)
    rawresponse = _extract_raw_response(payload)
    metadata = _extract_result_metadata(
        payload,
        requestid=requestid,
        traceid=traceid,
        provider=provider,
        runtimecontext=runtimecontext,
    )
    inputartifacts = _normalize_input_artifacts(payload.get("inputartifacts") or payload.get("input_artifacts"))
    outputartifacts = _normalize_output_artifacts(payload.get("outputartifacts") or payload.get("output_artifacts"))
    policyhints = _normalize_policy_hints(payload.get("policyhints") or payload.get("policy_hints"))
    mode = SkillMode.ASYNC if _bool_value(payload.get("async"), False) else SkillMode.SYNC

    executionrequest = _build_execution_request(
        requestid=requestid,
        provider=provider,
        runtimecontext=runtimecontext,
        requestcontext=requestcontext,
        target=target,
        mode=mode,
        metadata=metadata,
        inputartifacts=inputartifacts,
        policyhints=policyhints,
    )

    if decision is SkillDecision.ALLOW:
        try:
            return buildallowedresult(
                request=executionrequest,
                outputtext=outputtext,
                outputartifacts=outputartifacts,
                usage=usage,
                metadata=metadata,
                summary=summary,
                rawresponse=rawresponse,
                reasons=reasons,
                risk=risk,
            )
        except TypeError:
            return buildallowedresult(
                request=executionrequest,
                outputtext=outputtext,
                outputartifacts=outputartifacts,
                usage=usage,
                metadata=metadata,
            )

    if decision is SkillDecision.REVIEW:
        try:
            return buildreviewresult(
                request=executionrequest,
                message=summary,
                risk=risk,
                detections=(),
                metadata=metadata,
                outputtext=outputtext,
                rawresponse=rawresponse,
                reasons=reasons,
            )
        except TypeError:
            return buildreviewresult(
                request=executionrequest,
                message=summary,
                risk=risk,
                metadata=metadata,
            )

    if decision is SkillDecision.BLOCK:
        try:
            return buildblockedresult(
                request=executionrequest,
                message=summary,
                risk=risk,
                detections=(),
                metadata=metadata,
                outputtext=outputtext,
                rawresponse=rawresponse,
                reasons=reasons,
            )
        except TypeError:
            return buildblockedresult(
                request=executionrequest,
                message=summary,
                risk=risk,
                metadata=metadata,
            )

    try:
        return builderrorresult(
            request=executionrequest,
            message=summary,
            risk=risk,
            metadata=metadata,
            outputtext=outputtext,
            rawresponse=rawresponse,
            reasons=reasons,
        )
    except TypeError:
        return builderrorresult(
            request=executionrequest,
            message=summary,
            risk=risk,
            metadata=metadata,
        )


class IronClawSkillMiddleware:
    def __init__(
        self,
        runtime: IronClawSkillRuntime | None = None,
        *,
        config: IronClawSkillConfig | None = None,
    ) -> None:
        self.runtime = runtime or IronClawSkillRuntime(config=config)
        self.config = config or self.runtime.config

    async def dispatch(
        self,
        payload: Mapping[str, Any],
        handler: SkillHandler,
    ) -> dict[str, Any]:
        request = dict(payload or {})
        requestcontext = self._build_request_context(request)
        provider = _provider_value(
            request.get("provider")
            or request.get("provider_name")
            or _config_attr(self.config, "defaultprovider", "default_provider")
        )
        traceid: str | None = None
        try:
            self._validate_request(request)
            runtimecontext = self._build_runtime_context(
                request,
                requestcontext=requestcontext,
                provider=provider,
            )
            target = self._build_target(request)
            self._enforce_runtime_config(
                runtimecontext=runtimecontext,
                provider=provider,
                request=request,
            )

            traceid = (
                _request_attr(requestcontext, "traceid", "trace_id")
                or (_runtime_attr(runtimecontext, "metadata") or {}).get("traceid")
                or _new_id("trace")
            )

            guardedrequest = dict(request)
            guardedrequest.setdefault(
                "requestid",
                _request_attr(requestcontext, "requestid", "request_id"),
            )
            guardedrequest.setdefault("traceid", traceid)
            guardedrequest.setdefault("runtimecontext", runtimecontext)
            guardedrequest.setdefault("requestcontext", requestcontext)
            guardedrequest.setdefault("targetpayload", self._target_payload(target))

            response = await handler(guardedrequest)
            if not isinstance(response, Mapping):
                raise SkillValidationError(
                    "Middleware handler returned a non-mapping response.",
                    context=self._error_context(
                        requestid=_request_attr(requestcontext, "requestid", "request_id"),
                        provider=provider,
                        operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    ),
                    details={"receivedtype": type(response).__name__},
                )

            result = _result_from_payload(
                response,
                requestcontext=requestcontext,
                runtimecontext=runtimecontext,
                target=target,
                fallbackprovider=provider,
                fallbacksummary="Request completed.",
            )
            raw = _result_asdict(result)
            return _promote_top_level_fields(raw, result, traceid=traceid)

        except IronClawSkillError as exc:
            runtimecontext = self._safe_runtime_context(
                request=request,
                requestcontext=requestcontext,
                provider=provider,
            )
            target = self._build_target(request)
            if traceid is None:
                traceid = (
                    _request_attr(requestcontext, "traceid", "trace_id")
                    or str((_runtime_attr(runtimecontext, "metadata") or {}).get("traceid") or _new_id("trace"))
                )
            wrapped = self._normalize_error(
                exc,
                requestid=_request_attr(requestcontext, "requestid", "request_id"),
                provider=provider,
                operation=_runtime_attr(runtimecontext, "operation") or "execute",
            )
            result = self._error_result(
                error=wrapped,
                requestcontext=requestcontext,
                runtimecontext=runtimecontext,
                target=target,
                provider=provider,
                traceid=traceid,
            )
            raw = _result_asdict(result)
            return _promote_top_level_fields(raw, result, traceid=traceid)

        except Exception as exc:
            runtimecontext = self._safe_runtime_context(
                request=request,
                requestcontext=requestcontext,
                provider=provider,
            )
            target = self._build_target(request)
            if traceid is None:
                traceid = (
                    _request_attr(requestcontext, "traceid", "trace_id")
                    or str((_runtime_attr(runtimecontext, "metadata") or {}).get("traceid") or _new_id("trace"))
                )
            wrapped = IronClawSkillError(
                "Unhandled middleware execution error.",
                context=self._error_context(
                    requestid=_request_attr(requestcontext, "requestid", "request_id"),
                    provider=provider,
                    operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    metadata={"exceptiontype": type(exc).__name__},
                ),
                details={"exception": str(exc)},
            )
            result = self._error_result(
                error=wrapped,
                requestcontext=requestcontext,
                runtimecontext=runtimecontext,
                target=target,
                provider=provider,
                traceid=traceid,
            )
            raw = _result_asdict(result)
            return _promote_top_level_fields(raw, result, traceid=traceid)

    def _validate_request(self, request: Mapping[str, Any]) -> None:
        operation = str(request.get("operation") or "").strip()
        if not operation:
            raise SkillValidationError("operation is required.")

        action = str(request.get("action") or request.get("actiontype") or "").strip()
        if not action:
            raise SkillValidationError("action is required.")

        content = request.get("content")
        messages = request.get("messages")
        if not isinstance(content, str) and not isinstance(messages, (list, tuple)):
            raise SkillValidationError("Request must include content or messages.")

        providername = str(
            request.get("provider")
            or _config_attr(self.config, "defaultprovider", "default_provider")
            or ""
        ).strip().lower()
        if providername not in {item.value for item in SkillProvider}:
            raise SkillValidationError(
                "provider must be one of: claude, openclaw.",
                details={"provider": providername},
            )

    def _build_request_context(self, request: Mapping[str, Any]) -> SkillRequestContext:
        existing = request.get("requestcontext")
        if isinstance(existing, SkillRequestContext):
            if _request_attr(existing, "requestid", "request_id"):
                return existing
            try:
                return replace(existing, requestid=_new_id("req"))
            except TypeError:
                return replace(existing, request_id=_new_id("req"))

        if isinstance(existing, Mapping):
            return self._instantiate_request_context(
                requestid=str(
                    existing.get("requestid")
                    or existing.get("request_id")
                    or request.get("requestid")
                    or request.get("request_id")
                    or _new_id("req")
                ),
                sessionid=self._optional_text(existing.get("sessionid") or request.get("sessionid")),
                traceid=self._optional_text(
                    existing.get("traceid") or existing.get("trace_id") or request.get("traceid") or request.get("trace_id")
                ),
                organizationid=self._optional_text(existing.get("organizationid") or request.get("organizationid")),
                customerid=self._optional_text(existing.get("customerid") or request.get("customerid")),
                actorid=self._optional_text(existing.get("actorid") or request.get("actorid")),
                environment=self._optional_text(existing.get("environment")) or self.config.environment,
                region=self._optional_text(existing.get("region")),
                sourceip=self._optional_text(existing.get("sourceip") or existing.get("source_ip")),
                useragent=self._optional_text(existing.get("useragent") or existing.get("user_agent")),
                route=self._optional_text(existing.get("route")),
                method=self._optional_text(existing.get("method")),
                tags=_string_tuple(existing.get("tags")),
                labels=dict(existing.get("labels") or {}),
                metadata=_json_mapping(existing.get("metadata") if isinstance(existing.get("metadata"), Mapping) else None),
            )

        return self._instantiate_request_context(
            requestid=str(request.get("requestid") or request.get("request_id") or _new_id("req")),
            sessionid=self._optional_text(request.get("sessionid")),
            traceid=self._optional_text(request.get("traceid") or request.get("trace_id")),
            organizationid=self._optional_text(request.get("organizationid")),
            customerid=self._optional_text(request.get("customerid")),
            actorid=self._optional_text(request.get("actorid")),
            environment=self.config.environment,
            region=self._optional_text(request.get("region")),
            sourceip=self._optional_text(request.get("sourceip") or request.get("source_ip")),
            useragent=self._optional_text(request.get("useragent") or request.get("user_agent")),
            route=self._optional_text(request.get("route")),
            method=self._optional_text(request.get("method")),
            tags=_string_tuple(request.get("tags")),
            labels=dict(request.get("labels") or {}),
            metadata=_json_mapping(request.get("metadata") if isinstance(request.get("metadata"), Mapping) else None),
        )

    def _instantiate_request_context(self, **values: Any) -> SkillRequestContext:
        try:
            return SkillRequestContext(**values)
        except TypeError:
            alias_values = dict(values)
            if "requestid" in alias_values:
                alias_values["request_id"] = alias_values.pop("requestid")
            if "traceid" in alias_values:
                alias_values["trace_id"] = alias_values.pop("traceid")
            if "sourceip" in alias_values:
                alias_values["source_ip"] = alias_values.pop("sourceip")
            if "useragent" in alias_values:
                alias_values["user_agent"] = alias_values.pop("useragent")
            return SkillRequestContext(**alias_values)

    def _create_runtime_context(
        self,
        *,
        provider: SkillProvider,
        requestcontext: SkillRequestContext,
        operation: str,
        capability: str | None,
        policyid: str | None,
        reviewrequired: bool,
        sandboxenabled: bool,
        networkallowed: bool,
        filesystemwriteallowed: bool,
        toolinvocationallowed: bool,
        metadata: Mapping[str, JsonValue],
    ) -> SkillRuntimeContext:
        try:
            return createruntimecontext(
                provider=provider.value,
                request=requestcontext,
                operation=operation,
                capability=capability,
                policyid=policyid,
                reviewrequired=reviewrequired,
                sandboxenabled=sandboxenabled,
                networkallowed=networkallowed,
                filesystemwriteallowed=filesystemwriteallowed,
                toolinvocationallowed=toolinvocationallowed,
                metadata=dict(metadata),
            )
        except TypeError:
            return createruntimecontext(
                provider=provider.value,
                request=requestcontext,
                operation=operation,
                capability=capability,
                policyid=policyid,
                reviewrequired=reviewrequired,
                sandboxenabled=sandboxenabled,
                networkallowed=networkallowed,
                filesystemwriteallowed=filesystemwriteallowed,
                toolinvocationallowed=toolinvocationallowed,
                metadata=dict(metadata),
            )

    def _build_runtime_context(
        self,
        request: Mapping[str, Any],
        *,
        requestcontext: SkillRequestContext,
        provider: SkillProvider,
    ) -> SkillRuntimeContext:
        existing = request.get("runtimecontext")
        operation = str(request.get("operation") or "execute").strip() or "execute"
        metadata = _json_mapping(request.get("metadata") if isinstance(request.get("metadata"), Mapping) else None)
        metadata.setdefault("traceid", _request_attr(requestcontext, "traceid", "trace_id") or _new_id("trace"))

        if isinstance(existing, SkillRuntimeContext):
            return existing

        if isinstance(existing, Mapping):
            return self._create_runtime_context(
                provider=provider,
                requestcontext=requestcontext,
                operation=self._optional_text(existing.get("operation")) or operation,
                capability=self._optional_text(existing.get("capability")),
                policyid=self._optional_text(existing.get("policyid") or existing.get("policy_id")),
                reviewrequired=_bool_value(existing.get("reviewrequired"), False),
                sandboxenabled=_bool_value(
                    existing.get("sandboxenabled"),
                    bool(_security_attr(self.config, "enablesandbox", "enable_sandbox")),
                ),
                networkallowed=_bool_value(
                    existing.get("networkallowed"),
                    bool(_security_attr(self.config, "allownetwork", "allow_network")),
                ),
                filesystemwriteallowed=_bool_value(
                    existing.get("filesystemwriteallowed"),
                    bool(_security_attr(self.config, "allowfilesystemwrite", "allow_filesystem_write")),
                ),
                toolinvocationallowed=_bool_value(
                    existing.get("toolinvocationallowed"),
                    bool(_security_attr(self.config, "allowtoolinvocation", "allow_tool_invocation")),
                ),
                metadata=_json_mapping(existing.get("metadata") if isinstance(existing.get("metadata"), Mapping) else metadata),
            )

        return self._create_runtime_context(
            provider=provider,
            requestcontext=requestcontext,
            operation=operation,
            capability=self._optional_text(request.get("capability")),
            policyid=self._optional_text(request.get("policyid") or request.get("policy_id")),
            reviewrequired=_bool_value(request.get("reviewrequired"), False),
            sandboxenabled=_bool_value(
                request.get("sandboxenabled"),
                bool(_security_attr(self.config, "enablesandbox", "enable_sandbox")),
            ),
            networkallowed=_bool_value(
                request.get("networkallowed"),
                bool(_security_attr(self.config, "allownetwork", "allow_network")),
            ),
            filesystemwriteallowed=_bool_value(
                request.get("filesystemwriteallowed"),
                bool(_security_attr(self.config, "allowfilesystemwrite", "allow_filesystem_write")),
            ),
            toolinvocationallowed=_bool_value(
                request.get("toolinvocationallowed"),
                bool(_security_attr(self.config, "allowtoolinvocation", "allow_tool_invocation")),
            ),
            metadata=metadata,
        )

    def _safe_runtime_context(
        self,
        *,
        request: Mapping[str, Any],
        requestcontext: SkillRequestContext,
        provider: SkillProvider,
    ) -> SkillRuntimeContext:
        try:
            return self._build_runtime_context(
                request,
                requestcontext=requestcontext,
                provider=provider,
            )
        except Exception:
            metadata = _json_mapping(request.get("metadata") if isinstance(request.get("metadata"), Mapping) else None)
            metadata.setdefault("traceid", _request_attr(requestcontext, "traceid", "trace_id") or _new_id("trace"))
            return self._create_runtime_context(
                provider=provider,
                requestcontext=requestcontext,
                operation=str(request.get("operation") or "execute").strip() or "execute",
                capability=self._optional_text(request.get("capability")),
                policyid=self._optional_text(request.get("policyid") or request.get("policy_id")),
                reviewrequired=False,
                sandboxenabled=bool(_security_attr(self.config, "enablesandbox", "enable_sandbox")),
                networkallowed=False,
                filesystemwriteallowed=False,
                toolinvocationallowed=False,
                metadata=metadata,
            )

    def _build_target(self, request: Mapping[str, Any]) -> SkillExecutionTarget:
        existing = request.get("targetpayload") or request.get("target")
        if isinstance(existing, SkillExecutionTarget):
            return existing

        if isinstance(existing, Mapping):
            targetid = str(existing.get("targetid") or existing.get("id") or "runtime").strip() or "runtime"
            targettype = str(existing.get("targettype") or existing.get("type") or "runtime").strip() or "runtime"
            return SkillExecutionTarget(
                targetid=targetid,
                targettype=targettype,
                name=self._optional_text(existing.get("name")),
                version=self._optional_text(existing.get("version")),
            )

        targetvalue = str(request.get("target") or "runtime").strip() or "runtime"
        return SkillExecutionTarget(
            targetid=targetvalue,
            targettype=str(request.get("targettype") or "runtime").strip() or "runtime",
            name=self._optional_text(request.get("targetname")),
            version=self._optional_text(request.get("targetversion")),
        )

    def _enforce_runtime_config(
        self,
        *,
        runtimecontext: SkillRuntimeContext,
        provider: SkillProvider,
        request: Mapping[str, Any],
    ) -> None:
        requireprovider = getattr(self.config, "requireprovider", None)
        if callable(requireprovider):
            try:
                requireprovider(provider.value)
            except KeyError as exc:
                raise SkillConfigurationError(
                    f"Unknown provider '{provider.value}'.",
                    context=self._error_context(
                        requestid=_request_attr(_runtime_attr(runtimecontext, "request"), "requestid", "request_id"),
                        provider=provider,
                        operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    ),
                ) from exc
            except ValueError as exc:
                raise SkillConfigurationError(
                    str(exc),
                    context=self._error_context(
                        requestid=_request_attr(_runtime_attr(runtimecontext, "request"), "requestid", "request_id"),
                        provider=provider,
                        operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    ),
                ) from exc

        if _runtime_attr(runtimecontext, "networkallowed", "network_allowed") and not _security_attr(self.config, "allownetwork", "allow_network"):
            raise SkillPolicyBlockedError(
                "Network access is not allowed by current IronClaw skill policy.",
                context=self._error_context(
                    requestid=_request_attr(_runtime_attr(runtimecontext, "request"), "requestid", "request_id"),
                    provider=provider,
                    operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    risk=RiskLevel.HIGH,
                ),
                details={"flag": "networkallowed"},
            )

        if _runtime_attr(runtimecontext, "filesystemwriteallowed", "filesystem_write_allowed") and not _security_attr(self.config, "allowfilesystemwrite", "allow_filesystem_write"):
            raise SkillPolicyBlockedError(
                "Filesystem write access is not allowed by current IronClaw skill policy.",
                context=self._error_context(
                    requestid=_request_attr(_runtime_attr(runtimecontext, "request"), "requestid", "request_id"),
                    provider=provider,
                    operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    risk=RiskLevel.HIGH,
                ),
                details={"flag": "filesystemwriteallowed"},
            )

        if _runtime_attr(runtimecontext, "toolinvocationallowed", "tool_invocation_allowed") and not _security_attr(self.config, "allowtoolinvocation", "allow_tool_invocation"):
            raise SkillPolicyBlockedError(
                "Tool invocation is not allowed by current IronClaw skill policy.",
                context=self._error_context(
                    requestid=_request_attr(_runtime_attr(runtimecontext, "request"), "requestid", "request_id"),
                    provider=provider,
                    operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    risk=RiskLevel.HIGH,
                ),
                details={"flag": "toolinvocationallowed"},
            )

        payloadbytes = len(str(request).encode("utf-8", errors="ignore"))
        maxpayloadbytes = _security_attr(self.config, "maxpayloadbytes", "max_payload_bytes")
        if maxpayloadbytes is not None and payloadbytes > maxpayloadbytes:
            raise SkillValidationError(
                "Request exceeds the maximum payload size.",
                context=self._error_context(
                    requestid=_request_attr(_runtime_attr(runtimecontext, "request"), "requestid", "request_id"),
                    provider=provider,
                    operation=_runtime_attr(runtimecontext, "operation") or "execute",
                    risk=RiskLevel.HIGH,
                ),
                details={
                    "payloadbytes": payloadbytes,
                    "maxpayloadbytes": maxpayloadbytes,
                },
            )

    def _normalize_error(
        self,
        error: IronClawSkillError,
        *,
        requestid: str,
        provider: SkillProvider,
        operation: str,
    ) -> IronClawSkillError:
        context = getattr(error, "context", None)
        if context is None:
            context = self._error_context(
                requestid=requestid,
                provider=provider,
                operation=operation,
            )

        mergedmetadata = dict(getattr(context, "metadata", {}) or {})
        mergedmetadata.setdefault("provider", provider.value)
        mergedmetadata.setdefault("operation", operation)

        normalizedcontext = self._error_context(
            requestid=getattr(context, "requestid", None) or getattr(context, "request_id", None) or requestid,
            provider=getattr(context, "provider", None) or provider,
            operation=getattr(context, "operation", None) or operation,
            risk=getattr(context, "risk", None),
            metadata=mergedmetadata,
        )

        return IronClawSkillError(
            error.message,
            statuscode=error.statuscode,
            errorcode=error.errorcode,
            decision=error.decision,
            retryable=error.retryable,
            context=normalizedcontext,
            details=error.details,
        )

    def _error_result(
        self,
        *,
        error: IronClawSkillError,
        requestcontext: SkillRequestContext,
        runtimecontext: SkillRuntimeContext,
        target: SkillExecutionTarget,
        provider: SkillProvider,
        traceid: str | None = None,
    ) -> SkillExecutionResult:
        summary = error.message
        risk = error.context.risk or RiskLevel.HIGH

        error_dict: dict[str, Any] = error.todict() if hasattr(error, "todict") else {}
        if not error_dict.get("code"):
            error_dict["code"] = error.errorcode
        if "status" not in error_dict:
            error_dict["status"] = error.statuscode
        if "decision" not in error_dict:
            decision = error.decision
            if isinstance(decision, SkillDecision):
                decision = decision.value
            error_dict["decision"] = decision

        metadata: dict[str, JsonValue] = dict(error.context.metadata or {})
        metadata.update(
            {
                "statuscode": error.statuscode,
                "errorcode": error.errorcode,
                "retryable": error.retryable,
            }
        )

        reasons = (
            _make_skill_reason(
                label=error.errorcode,
                detail=error.message,
                metadata=_json_mapping(error.details),
            ),
        )

        requestid = _request_attr(requestcontext, "requestid", "request_id") or _new_id("req")
        resolved_traceid = (
            traceid
            or _request_attr(requestcontext, "traceid", "trace_id")
            or str((_runtime_attr(runtimecontext, "metadata") or {}).get("traceid") or _new_id("trace"))
        )

        executionrequest = _build_execution_request(
            requestid=requestid,
            provider=provider,
            runtimecontext=runtimecontext,
            requestcontext=requestcontext,
            target=target,
            mode=SkillMode.SYNC,
            metadata=metadata,
        )

        try:
            return builderrorresult(
                request=executionrequest,
                message=summary,
                risk=risk,
                metadata=metadata,
                traceid=resolved_traceid,
                reasons=reasons,
                rawresponse=error_dict,
                error=error_dict,
            )
        except TypeError:
            return builderrorresult(
                request=executionrequest,
                message=summary,
                risk=risk,
                metadata=metadata,
                error=error_dict,
            )

    def _error_context(
        self,
        *,
        requestid: str | None,
        provider: SkillProvider,
        operation: str,
        risk: RiskLevel | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> ErrorContext:
        payload = dict(metadata or {})
        try:
            return ErrorContext(
                requestid=requestid,
                provider=provider,
                operation=operation,
                risk=risk,
                metadata=payload,
            )
        except TypeError:
            return ErrorContext(
                request_id=requestid,
                provider=provider,
                operation=operation,
                risk=risk,
                metadata=payload,
            )

    def _target_payload(self, target: SkillExecutionTarget) -> dict[str, JsonValue]:
        return {
            "targetid": getattr(target, "targetid", None),
            "targettype": getattr(target, "targettype", None),
            "name": getattr(target, "name", None),
            "version": getattr(target, "version", None),
        }

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        text = str(value or "").strip()
        return text or None


def buildmiddleware(
    runtime: IronClawSkillRuntime | None = None,
    *,
    config: IronClawSkillConfig | None = None,
) -> IronClawSkillMiddleware:
    return IronClawSkillMiddleware(runtime=runtime, config=config)


__all__ = ["IronClawSkillMiddleware", "SkillHandler", "buildmiddleware"]