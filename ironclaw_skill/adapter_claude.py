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

CLAUDE_PLATFORM: Final = "claude"
REQUEST_ADAPTER: Final[TypeAdapter[SkillRequest]] = TypeAdapter(SkillRequest)


class ClaudeAdapterError(RuntimeError):
    """Raised when Claude payload adaptation fails."""


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_context(raw: dict[str, Any] | None) -> SkillRequestContext:
    payload = raw or {}
    return SkillRequestContext(
        client_id=_normalize_optional_text(payload.get("client_id")),
        session_id=_normalize_optional_text(payload.get("session_id")),
        user_id=_normalize_optional_text(payload.get("user_id")),
        tenant_id=_normalize_optional_text(payload.get("tenant_id")),
        request_id=_normalize_optional_text(payload.get("request_id")),
        source_platform=CLAUDE_PLATFORM,
        source_version=_normalize_optional_text(payload.get("source_version")),
        tags=payload.get("tags", []) or [],
    )


def _extract_context(raw: dict[str, Any]) -> SkillRequestContext:
    return _normalize_context(raw.get("context"))


def _build_bundle_input(raw: dict[str, Any]) -> SkillPromptBundleInput:
    bundle_payload = raw.get("bundle")
    if not isinstance(bundle_payload, dict):
        raise ClaudeAdapterError(
            "Claude scan request with target_type=prompt_bundle must include a 'bundle' object.",
        )

    return SkillPromptBundleInput(
        user_prompt=_normalize_optional_text(bundle_payload.get("user_prompt")),
        retrieved_doc=_normalize_optional_text(bundle_payload.get("retrieved_doc")),
        tool_output=_normalize_optional_text(bundle_payload.get("tool_output")),
        model_output=_normalize_optional_text(bundle_payload.get("model_output")),
    )


def _build_scan_request(raw: dict[str, Any]) -> SkillScanRequest:
    target_type = str(raw.get("target_type", "text")).strip().lower()
    if target_type == "bundle":
        target_type = "prompt_bundle"

    if target_type == "prompt_bundle":
        input_model = SkillScanInput(
            target_type="prompt_bundle",
            bundle=_build_bundle_input(raw),
            policy_mode=str(raw.get("policy_mode", "review")).strip().lower(),
        )
    else:
        input_model = SkillScanInput(
            target_type=target_type,  # type: ignore[arg-type]
            target_value=_normalize_optional_text(raw.get("target_value") or raw.get("content")),
            policy_mode=str(raw.get("policy_mode", "review")).strip().lower(),
        )

    return SkillScanRequest(
        input=input_model,
        context=_extract_context(raw),
    )


def _build_action_input(raw: dict[str, Any]) -> SkillActionInput:
    return SkillActionInput(
        action_type=str(raw.get("action_type", "other")).strip().lower(),
        target=_normalize_optional_text(raw.get("target")) or "unspecified",
        content=_normalize_optional_text(raw.get("content")),
        policy_mode=str(raw.get("policy_mode", "review")).strip().lower(),
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


def adapt_claude_request(raw: dict[str, Any]) -> SkillRequest:
    if not isinstance(raw, dict):
        raise ClaudeAdapterError("Claude request payload must be a JSON object.")

    operation = str(raw.get("operation", "scan")).strip().lower()

    if operation == "scan":
        request = _build_scan_request(raw)
    elif operation == "action_policy":
        request = _build_action_policy_request(raw)
    elif operation == "action_decision":
        request = _build_action_decision_request(raw)
    elif operation == "execute":
        request = _build_execute_request(raw)
    else:
        raise ClaudeAdapterError(f"Unsupported Claude operation: {operation}")

    try:
        return REQUEST_ADAPTER.validate_python(request.model_dump())
    except ValidationError as exc:
        raise ClaudeAdapterError(f"Claude request validation failed: {exc}") from exc


def _reason_to_claude(reason: SkillReason) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": reason.source,
        "label": reason.label,
        "details": reason.details,
    }
    if reason.score is not None:
        payload["score"] = reason.score
    return payload


def adapt_claude_response(response: SkillResponseEnvelope) -> dict[str, Any]:
    payload = response.payload
    metadata = payload.metadata

    return {
        "ok": response.ok,
        "operation": response.operation,
        "request_id": response.request_id,
        "error_code": response.error_code,
        "verdict": payload.verdict,
        "summary": payload.summary,
        "should_halt": payload.should_halt,
        "should_warn": payload.should_warn,
        "allowed": payload.allowed,
        "scan_id": metadata.scan_id,
        "decision_source": metadata.decision_source,
        "matched_patterns": metadata.matched_patterns,
        "risk_score": metadata.risk_score,
        "reasons": [_reason_to_claude(reason) for reason in payload.reasons],
        "raw_result": payload.raw_result,
    }


def build_claude_error_response(
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
                label="Claude adapter error",
                details=summary,
            ),
        ],
    )
    return adapt_claude_response(response)


def build_claude_success_response(
    *,
    operation: Literal["scan", "action_policy", "action_decision", "execute"],
    verdict: Literal["allow", "review", "block"],
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
    return adapt_claude_response(response)


def claude_tool_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["scan", "action_policy", "action_decision", "execute"],
            },
            "target_type": {
                "type": "string",
                "enum": ["text", "url", "file_path", "prompt_bundle", "bundle"],
            },
            "target_value": {"type": "string"},
            "content": {"type": "string"},
            "user_prompt": {"type": "string"},
            "retrieved_doc": {"type": "string"},
            "tool_output": {"type": "string"},
            "model_output": {"type": "string"},
            "bundle": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "user_prompt": {"type": "string"},
                    "retrieved_doc": {"type": "string"},
                    "tool_output": {"type": "string"},
                    "model_output": {"type": "string"},
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
            "target": {"type": "string"},
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
                    "session_id": {"type": "string"},
                    "user_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "request_id": {"type": "string"},
                    "source_version": {"type": "string"},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
        "required": ["operation"],
    }


__all__ = [
    "ClaudeAdapterError",
    "adapt_claude_request",
    "adapt_claude_response",
    "build_claude_error_response",
    "build_claude_success_response",
    "claude_tool_input_schema",
]
