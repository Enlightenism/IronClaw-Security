from __future__ import annotations

from typing import Any, Final, Literal

from pydantic import TypeAdapter, ValidationError

from ironclaw_skill.contracts import (
    SkillActionDecisionRequest,
    SkillActionInput,
    SkillActionPolicyRequest,
    SkillExecuteRequest,
    SkillExecutionInput,
    SkillPromptBundleInput,
    SkillReason,
    SkillRequest,
    SkillRequestContext,
    SkillResponseEnvelope,
    SkillScanInput,
    SkillScanRequest,
    build_skill_error_response,
    build_skill_success_response,
)

OPENCLAW_PLATFORM: Final = "openclaw"
REQUEST_ADAPTER: Final[TypeAdapter[SkillRequest]] = TypeAdapter(SkillRequest)


class OpenClawAdapterError(RuntimeError):
    """Raised when OpenClaw payload adaptation fails."""


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _normalize_context(raw: dict[str, Any] | None) -> SkillRequestContext:
    payload = raw or {}
    return SkillRequestContext(
        client_id=_normalize_optional_text(payload.get("client_id") or payload.get("agent_id")),
        session_id=_normalize_optional_text(payload.get("session_id") or payload.get("conversation_id")),
        user_id=_normalize_optional_text(payload.get("user_id")),
        tenant_id=_normalize_optional_text(payload.get("tenant_id") or payload.get("workspace_id")),
        request_id=_normalize_optional_text(payload.get("request_id") or payload.get("trace_id")),
        source_platform=OPENCLAW_PLATFORM,
        source_version=_normalize_optional_text(payload.get("source_version") or payload.get("agent_version")),
        tags=_coerce_tags(payload.get("tags")),
    )


def _extract_context(raw: dict[str, Any]) -> SkillRequestContext:
    return _normalize_context(raw.get("context"))


def _operation_from_raw(raw: dict[str, Any]) -> str:
    operation = _normalize_optional_text(raw.get("operation"))
    if operation:
        return operation.lower()

    tool_name = _normalize_optional_text(raw.get("tool_name"))
    if tool_name:
        normalized = tool_name.lower()
        if normalized in {"scan", "action_policy", "action_decision", "execute"}:
            return normalized

    mode = _normalize_optional_text(raw.get("mode"))
    if mode:
        normalized = mode.lower()
        if normalized in {"scan", "action_policy", "action_decision", "execute"}:
            return normalized

    return "scan"


def _build_bundle_input(raw: dict[str, Any]) -> SkillPromptBundleInput:
    bundle_payload = raw.get("bundle")
    if not isinstance(bundle_payload, dict):
        raise OpenClawAdapterError(
            "OpenClaw scan request with target_type=prompt_bundle must include a 'bundle' object.",
        )

    return SkillPromptBundleInput(
        user_prompt=_normalize_optional_text(bundle_payload.get("user_prompt") or bundle_payload.get("prompt")),
        retrieved_doc=_normalize_optional_text(bundle_payload.get("retrieved_doc") or bundle_payload.get("retrieval")),
        tool_output=_normalize_optional_text(bundle_payload.get("tool_output")),
        model_output=_normalize_optional_text(
            bundle_payload.get("model_output") or bundle_payload.get("assistant_output"),
        ),
    )


def _build_scan_request(raw: dict[str, Any]) -> SkillScanRequest:
    target_type = _normalize_optional_text(raw.get("target_type") or raw.get("content_type")) or "text"
    normalized_target_type = target_type.lower()
    if normalized_target_type == "bundle":
        normalized_target_type = "prompt_bundle"

    if normalized_target_type == "prompt_bundle":
        input_model = SkillScanInput(
            target_type="prompt_bundle",
            bundle=_build_bundle_input(raw),
            policy_mode=(_normalize_optional_text(raw.get("policy_mode")) or "review").lower(),
        )
    else:
        # Resolve target_value from any recognized field; fall back to "" so
        # SkillScanInput validation passes for payloads that omit content entirely
        # (e.g. an empty dict sent during a default-operation probe).
        resolved_target_value: str = (
            _normalize_optional_text(
                raw.get("target_value") or raw.get("content") or raw.get("input") or raw.get("text") or raw.get("url") or raw.get("file_path"),
            )
            or ""
        )
        input_model = SkillScanInput(
            target_type=normalized_target_type,  # type: ignore[arg-type]
            target_value=resolved_target_value,
            policy_mode=(_normalize_optional_text(raw.get("policy_mode")) or "review").lower(),
        )

    return SkillScanRequest(
        input=input_model,
        context=_extract_context(raw),
    )


def _build_action_input(raw: dict[str, Any]) -> SkillActionInput:
    return SkillActionInput(
        action_type=(_normalize_optional_text(raw.get("action_type") or raw.get("kind") or raw.get("tool_kind")) or "other").lower(),
        target=_normalize_optional_text(
            raw.get("target") or raw.get("command") or raw.get("path") or raw.get("endpoint") or raw.get("resource"),
        )
        or "unspecified",
        content=_normalize_optional_text(
            raw.get("content") or raw.get("payload") or raw.get("body") or raw.get("code"),
        ),
        policy_mode=(_normalize_optional_text(raw.get("policy_mode")) or "review").lower(),
        dry_run=bool(raw.get("dry_run", False)),
    )


def _build_action_policy_request(raw: dict[str, Any]) -> SkillActionPolicyRequest:
    return SkillActionPolicyRequest(
        input=_build_action_input(raw),
        context=_extract_context(raw),
    )


def _build_action_decision_request(raw: dict[str, Any]) -> SkillActionDecisionRequest:
    return SkillActionDecisionRequest(
        input=_build_action_input(raw),
        context=_extract_context(raw),
    )


def _build_execute_request(raw: dict[str, Any]) -> SkillExecuteRequest:
    return SkillExecuteRequest(
        input=SkillExecutionInput(
            action=_build_action_input(raw),
            require_confirmation=bool(raw.get("require_confirmation", False)),
            allow_side_effects=bool(raw.get("allow_side_effects", False)),
        ),
        context=_extract_context(raw),
    )


def adapt_openclaw_request(raw: dict[str, Any]) -> SkillRequest:
    if not isinstance(raw, dict):
        raise OpenClawAdapterError("OpenClaw request payload must be a JSON object.")

    operation = _operation_from_raw(raw)

    if operation == "scan":
        request = _build_scan_request(raw)
    elif operation == "action_policy":
        request = _build_action_policy_request(raw)
    elif operation == "action_decision":
        request = _build_action_decision_request(raw)
    elif operation == "execute":
        request = _build_execute_request(raw)
    else:
        raise OpenClawAdapterError(f"Unsupported OpenClaw operation: {operation}")

    try:
        return REQUEST_ADAPTER.validate_python(request.model_dump())
    except ValidationError as exc:
        raise OpenClawAdapterError(f"OpenClaw request validation failed: {exc}") from exc


def _reason_to_openclaw(reason: SkillReason) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": reason.source,
        "label": reason.label,
        "details": reason.details,
    }
    if reason.score is not None:
        payload["score"] = reason.score
    return payload


def adapt_openclaw_response(response: SkillResponseEnvelope) -> dict[str, Any]:
    payload = response.payload
    metadata = payload.metadata

    return {
        "success": response.ok,
        "operation": response.operation,
        "request_id": response.request_id,
        "error_code": response.error_code,
        "result": {
            "verdict": payload.verdict,
            "summary": payload.summary,
            "allowed": payload.allowed,
            "should_halt": payload.should_halt,
            "should_warn": payload.should_warn,
            "scan_id": metadata.scan_id,
            "decision_source": metadata.decision_source,
            "matched_patterns": metadata.matched_patterns,
            "risk_score": metadata.risk_score,
            "reasons": [_reason_to_openclaw(reason) for reason in payload.reasons],
            "raw_result": payload.raw_result,
        },
    }


def build_openclaw_error_response(
    *,
    operation: Literal["scan", "action_policy", "action_decision", "execute"],
    summary: str,
    error_code: str,
    request_id: str | None = None,
) -> dict[str, Any]:
    response = build_skill_error_response(
        operation=operation,
        summary=summary,
        error_code=error_code,
        request_id=request_id,
        reasons=[
            SkillReason(
                source="skill",
                label="OpenClaw adapter error",
                details=summary,
            ),
        ],
    )
    return adapt_openclaw_response(response)


def build_openclaw_success_response(
    *,
    operation: Literal["scan", "action_policy", "action_decision", "execute"],
    verdict: Literal["allow", "block"],
    summary: str,
    should_halt: bool = False,
    should_warn: bool = False,
    request_id: str | None = None,
    scan_id: str | None = None,
    decision_source: Literal["policy", "scan", "ai", "runtime", "combined", "unknown"] = "unknown",
    matched_patterns: list[str] | None = None,
    risk_score: int | None = None,
    reasons: list[SkillReason] | None = None,
    raw_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = build_skill_success_response(
        operation=operation,
        verdict=verdict,
        summary=summary,
        should_halt=should_halt,
        should_warn=should_warn,
        request_id=request_id,
        scan_id=scan_id,
        decision_source=decision_source,
        matched_patterns=matched_patterns,
        risk_score=risk_score,
        reasons=reasons,
        raw_result=raw_result,
    )
    return adapt_openclaw_response(response)


def openclaw_tool_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["scan", "action_policy", "action_decision", "execute"],
            },
            "tool_name": {
                "type": "string",
                "enum": ["scan", "action_policy", "action_decision", "execute"],
            },
            "mode": {
                "type": "string",
                "enum": ["scan", "action_policy", "action_decision", "execute"],
            },
            "target_type": {
                "type": "string",
                "enum": ["text", "url", "file_path", "prompt_bundle", "bundle"],
            },
            "content_type": {
                "type": "string",
                "enum": ["text", "url", "file_path", "prompt_bundle", "bundle"],
            },
            "target_value": {"type": "string"},
            "content": {"type": "string"},
            "input": {"type": "string"},
            "text": {"type": "string"},
            "url": {"type": "string"},
            "file_path": {"type": "string"},
            "prompt": {"type": "string"},
            "retrieval": {"type": "string"},
            "tool_output": {"type": "string"},
            "assistant_output": {"type": "string"},
            "bundle": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "user_prompt": {"type": "string"},
                    "prompt": {"type": "string"},
                    "retrieved_doc": {"type": "string"},
                    "retrieval": {"type": "string"},
                    "tool_output": {"type": "string"},
                    "model_output": {"type": "string"},
                    "assistant_output": {"type": "string"},
                },
            },
            "action_type": {
                "type": "string",
                "enum": [
                    "shell_command",
                    "python_code",
                    "tool_invocation",
                    "file_write",
                    "file_delete",
                    "network_request",
                    "system_change",
                    "other",
                ],
            },
            "kind": {
                "type": "string",
                "enum": [
                    "shell_command",
                    "python_code",
                    "tool_invocation",
                    "file_write",
                    "file_delete",
                    "network_request",
                    "system_change",
                    "other",
                ],
            },
            "tool_kind": {
                "type": "string",
                "enum": [
                    "shell_command",
                    "python_code",
                    "tool_invocation",
                    "file_write",
                    "file_delete",
                    "network_request",
                    "system_change",
                    "other",
                ],
            },
            "target": {"type": "string"},
            "command": {"type": "string"},
            "path": {"type": "string"},
            "endpoint": {"type": "string"},
            "resource": {"type": "string"},
            "payload": {"type": "string"},
            "body": {"type": "string"},
            "code": {"type": "string"},
            "policy_mode": {
                "type": "string",
                "enum": ["allow", "review", "block"],
            },
            "dry_run": {"type": "boolean"},
            "require_confirmation": {"type": "boolean"},
            "allow_side_effects": {"type": "boolean"},
            "context": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "client_id": {"type": "string"},
                    "agent_id": {"type": "string"},
                    "session_id": {"type": "string"},
                    "conversation_id": {"type": "string"},
                    "user_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "workspace_id": {"type": "string"},
                    "request_id": {"type": "string"},
                    "trace_id": {"type": "string"},
                    "source_version": {"type": "string"},
                    "agent_version": {"type": "string"},
                    "tags": {
                        "oneOf": [
                            {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            {
                                "type": "string",
                            },
                        ],
                    },
                },
            },
        },
        "required": [],
    }


__all__ = [
    "OpenClawAdapterError",
    "adapt_openclaw_request",
    "adapt_openclaw_response",
    "build_openclaw_error_response",
    "build_openclaw_success_response",
    "openclaw_tool_input_schema",
]
