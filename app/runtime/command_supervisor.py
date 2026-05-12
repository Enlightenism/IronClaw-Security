from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from app.runtime.tool_call_guard import evaluate_tool_call

DANGEROUS_COMMAND_PATTERNS = {
    "rm -rf",
    "del /f /q",
    "format c:",
    "mkfs",
    "shutdown",
    "reboot",
    "net user",
    "reg add",
    "sc config",
    "powershell -enc",
    "curl | bash",
    "wget | sh",
    "Invoke-Expression",
    "Start-Process",
}

SENSITIVE_PATH_PATTERNS = {
    "/etc/",
    "/root/",
    "/home/",
    "c:\\windows",
    "c:\\users",
    "appdata\\",
    ".ssh",
    ".aws",
    ".env",
    "id_rsa",
    "known_hosts",
}

RESTRICTED_COMMANDS = {
    "powershell",
    "pwsh",
    "cmd",
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    "pip",
    "npm",
    "npx",
    "curl",
    "wget",
}


@dataclass(slots=True)
class CommandSupervisorDecision:
    allowed: bool
    response_status: str
    policy_verdict: str
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    requires_review: bool
    sandbox_lane: str
    command: str
    command_name: str
    target: str
    reason: str
    reasons: list[str] = field(default_factory=list)
    sanitized_command: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_value(payload: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _extract_command(payload: Mapping[str, Any]) -> str:
    return str(_get_value(payload, "command", "target", "content", "input") or "")


def _extract_command_name(command: str) -> str:
    stripped = command.strip()
    if not stripped:
        return ""
    return stripped.split()[0].lower()


def _score_command(command: str, command_name: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    command_lower = command.lower()

    if command_name in RESTRICTED_COMMANDS:
        score += 25
        reasons.append(f"restricted command detected: {command_name}")

    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if pattern.lower() in command_lower:
            score += 50
            reasons.append(f"dangerous command pattern detected: {pattern}")

    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.lower() in command_lower:
            score += 20
            reasons.append(f"sensitive path access detected: {pattern}")

    return score, reasons


def _sanitize_command(command: str) -> str:
    sanitized = command
    redactions = [
        "authorization=",
        "token=",
        "apikey=",
        "api_key=",
        "password=",
        "secret=",
    ]

    for marker in redactions:
        lower = sanitized.lower()
        index = lower.find(marker)
        if index >= 0:
            end_index = sanitized.find(" ", index)
            if end_index == -1:
                end_index = len(sanitized)
            sanitized = sanitized[:index] + marker + "[REDACTED]" + sanitized[end_index:]

    return sanitized


def evaluate_command(payload: Mapping[str, Any]) -> CommandSupervisorDecision:
    command = _extract_command(payload)
    command_name = _extract_command_name(command)
    base_risk = _safe_int(_get_value(payload, "risk_score", "score"), 0)

    command_score, reasons = _score_command(command, command_name)
    total_risk = min(100, base_risk + command_score)

    tool_payload = {
        "tool_name": "shell",
        "action_type": "toolcall",
        "target": command,
        "content": command,
        "risk_score": total_risk,
        "reason": payload.get("reason"),
        "summary": payload.get("summary"),
        "policy_verdict": payload.get("policy_verdict"),
    }
    tool_decision = evaluate_tool_call(tool_payload)

    if not reasons:
        reasons = list(tool_decision.reasons)

    if not reasons:
        reasons.append("command accepted under current supervision policy")

    return CommandSupervisorDecision(
        allowed=tool_decision.allowed,
        response_status=tool_decision.response_status,
        policy_verdict=tool_decision.policy_verdict,
        risk_score=tool_decision.risk_score,
        should_execute=tool_decision.should_execute,
        halted_by_boundary=tool_decision.halted_by_boundary,
        requires_review=tool_decision.requires_review,
        sandbox_lane=tool_decision.sandbox_lane,
        command=command,
        command_name=command_name,
        target=str(_get_value(payload, "target") or command),
        reason=reasons[0],
        reasons=reasons,
        sanitized_command=_sanitize_command(command),
        metadata={"source": "command_supervisor"},
    )


def summarize_command_supervisor(payload: Mapping[str, Any]) -> dict[str, Any]:
    return evaluate_command(payload).to_dict()


__all__ = [
    "DANGEROUS_COMMAND_PATTERNS",
    "SENSITIVE_PATH_PATTERNS",
    "RESTRICTED_COMMANDS",
    "CommandSupervisorDecision",
    "evaluate_command",
    "summarize_command_supervisor",
]