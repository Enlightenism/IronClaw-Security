from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from app.runtime.sandbox_router import SandboxLane, route_to_sandbox

HIGH_RISK_TOOL_NAMES = {
    "shell",
    "terminal",
    "subprocess",
    "powershell",
    "bash",
    "cmd",
    "python_exec",
    "code_interpreter",
    "file_write",
    "filesystem_write",
    "registry_edit",
    "package_install",
    "browser_open_external",
}

MEDIUM_RISK_TOOL_NAMES = {
    "http_fetch",
    "httpfetch",
    "web_request",
    "browser_open",
    "download_file",
    "read_file",
    "filesystem_read",
    "grep",
    "search",
}

HIGH_RISK_KEYWORDS = {
    "ignore previous instructions",
    "system prompt",
    "developer prompt",
    "hidden prompt",
    "exfiltrate",
    "credential",
    "token",
    "cookie",
    "ssh key",
    "private key",
    "download and execute",
    "powershell -enc",
    "curl | bash",
    "rm -rf",
}

MEDIUM_RISK_KEYWORDS = {
    "download",
    "install",
    "execute",
    "script",
    "command",
    "shell",
    "network",
    "fetch",
    "browser",
}


@dataclass(slots=True)
class ToolCallGuardDecision:
    allowed: bool
    response_status: str
    policy_verdict: str
    sandbox_lane: str
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    requires_review: bool
    tool_name: str
    target: str
    reason: str
    reasons: list[str] = field(default_factory=list)
    sanitized_payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _payload_value(payload: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _combined_text(payload: Mapping[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "action_type",
        "tool_name",
        "target",
        "content",
        "prompt",
        "input",
        "arguments",
        "command",
        "url",
        "reason",
        "summary",
    ):
        value = payload.get(key)
        if value is not None:
            parts.append(str(value))
    return " | ".join(parts).lower()


def _keyword_score(signal_text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in signal_text:
            score += 40
            reasons.append(f"high-risk keyword detected: {keyword}")

    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in signal_text:
            score += 10
            reasons.append(f"medium-risk keyword detected: {keyword}")

    return score, reasons


def _tool_score(tool_name: str) -> tuple[int, list[str]]:
    if tool_name in HIGH_RISK_TOOL_NAMES:
        return 60, [f"high-risk tool detected: {tool_name}"]
    if tool_name in MEDIUM_RISK_TOOL_NAMES:
        return 20, [f"medium-risk tool detected: {tool_name}"]
    return 0, []


def _sanitize_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    sanitized = dict(payload)

    for sensitive_key in (
        "authorization",
        "api_key",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "cookie",
    ):
        if sensitive_key in sanitized:
            sanitized[sensitive_key] = "[REDACTED]"

    return sanitized


def evaluate_tool_call(payload: Mapping[str, Any]) -> ToolCallGuardDecision:
    tool_name = _normalize_text(_payload_value(payload, "tool_name", "action_type"))
    target = str(_payload_value(payload, "target", "url", "command") or "")
    base_risk = _safe_int(_payload_value(payload, "risk_score", "score"), 0)

    signal_text = _combined_text(payload)
    tool_score, tool_reasons = _tool_score(tool_name)
    keyword_score, keyword_reasons = _keyword_score(signal_text)

    total_risk = min(100, base_risk + tool_score + keyword_score)
    reasons = [*tool_reasons, *keyword_reasons]

    route_payload = {
        "action_type": tool_name,
        "target": target,
        "content": signal_text,
        "risk_score": total_risk,
        "reasons": reasons,
        "policy_verdict": payload.get("policy_verdict"),
        "summary": payload.get("summary"),
        "reason": payload.get("reason"),
    }
    route_decision = route_to_sandbox(route_payload)

    if route_decision.lane == SandboxLane.HARD_BLOCK:
        response_status = "denied"
        policy_verdict = "deny"
        allowed = False
        halted_by_boundary = True
    elif route_decision.requires_review:
        response_status = "queued_for_review"
        policy_verdict = "warn"
        allowed = False
        halted_by_boundary = True
    else:
        response_status = "completed"
        policy_verdict = "allow"
        allowed = True
        halted_by_boundary = False

    if not reasons:
        reasons.append("tool call accepted under current low-risk policy")

    return ToolCallGuardDecision(
        allowed=allowed,
        response_status=response_status,
        policy_verdict=policy_verdict,
        sandbox_lane=route_decision.lane.value,
        risk_score=total_risk,
        should_execute=route_decision.should_execute and allowed,
        halted_by_boundary=halted_by_boundary,
        requires_review=route_decision.requires_review,
        tool_name=tool_name,
        target=target,
        reason=reasons[0],
        reasons=reasons,
        sanitized_payload=_sanitize_payload(payload),
        metadata={"source": "tool_call_guard"},
    )


def summarize_tool_call_guard(payload: Mapping[str, Any]) -> dict[str, Any]:
    return evaluate_tool_call(payload).to_dict()


__all__ = [
    "HIGH_RISK_KEYWORDS",
    "HIGH_RISK_TOOL_NAMES",
    "MEDIUM_RISK_KEYWORDS",
    "MEDIUM_RISK_TOOL_NAMES",
    "ToolCallGuardDecision",
    "evaluate_tool_call",
    "summarize_tool_call_guard",
]
