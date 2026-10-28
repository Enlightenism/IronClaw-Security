from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN


class SandboxLane(StrEnum):
    SAFE_READONLY = "safe_readonly"
    PROMPT_INJECTION = "prompt_injection"
    DOWNLOAD_REVIEW = "download_review"
    FILE_QUARANTINE = "file_quarantine"
    NETWORK_RESTRICTED = "network_restricted"
    TOOL_CALL_RESTRICTED = "tool_call_restricted"
    HUMAN_REVIEW = "human_review"
    HARD_BLOCK = "hard_block"


@dataclass(slots=True)
class SandboxRouteDecision:
    lane: SandboxLane
    should_execute: bool
    requires_review: bool
    isolate_output: bool
    allow_network: bool
    allow_tool_calls: bool
    allow_file_write: bool
    reason: str
    reasons: list[str] = field(default_factory=list)
    risk_score: int = 0
    policy_verdict: str = "allow"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _collect_signal_text(payload: Mapping[str, Any]) -> str:
    parts: list[str] = []

    for key in (
        "reason",
        "summary",
        "quarantine_reason",
        "action_type",
        "target",
        "target_type",
        "target_value",
        "content",
        "policy_verdict",
        "review_status",
    ):
        value = payload.get(key)
        if value:
            parts.append(str(value))

    for key in ("reasons", "failed_checks", "matched_patterns", "alerts", "tags"):
        for item in _as_list(payload.get(key)):
            if item:
                parts.append(str(item))

    return " | ".join(parts).lower()


def _extract_policy_verdict(payload: Mapping[str, Any]) -> str:
    for key in ("policy_verdict", "verdict"):
        if key in payload:
            verdict = _normalize_text(payload.get(key))
            if verdict != "allow":
                return verdict
    return "allow"


def _extract_risk_score(payload: Mapping[str, Any]) -> int:
    for key in ("risk_score", "score", "severity"):
        if key in payload:
            value = payload.get(key)
            if value is None:
                return 0
            if isinstance(value, bool):
                return RISK_THRESHOLD_BLOCK_MIN
            try:
                risk_score = int(value)
            except (TypeError, ValueError, OverflowError):
                return RISK_THRESHOLD_BLOCK_MIN
            if isinstance(value, float) and not value.is_integer():
                return RISK_THRESHOLD_BLOCK_MIN
            if risk_score < 0:
                return RISK_THRESHOLD_BLOCK_MIN
            return min(risk_score, 100)
    return 0


def route_to_sandbox(payload: Mapping[str, Any]) -> SandboxRouteDecision:
    risk_score = _extract_risk_score(payload)
    policy_verdict = _extract_policy_verdict(payload)
    signal_text = _collect_signal_text(payload)
    response_status = _normalize_text(payload.get("response_status"))
    review_status = _normalize_text(payload.get("review_status"))
    review_required = (
        bool(payload.get("review_required"))
        or bool(payload.get("should_review"))
        or bool(payload.get("shouldreview"))
        or policy_verdict in {"warn", "review", "needs_review"}
        or response_status in {"queued_for_review", "needs_review"}
        or review_status in {"pending", "required", "queued", "needs_review"}
    )
    quarantine_requested = bool(payload.get("quarantine_required")) or bool(payload.get("should_quarantine")) or bool(payload.get("shouldquarantine"))
    has_matched_signals = any(_as_list(payload.get(key)) for key in ("matched_patterns", "matchedpatterns", "matched_rules", "failed_checks", "alerts"))
    errors_detected = bool(payload.get("error")) or bool(payload.get("errors"))
    force_block = (
        policy_verdict != "allow"
        or has_matched_signals
        or quarantine_requested
        or bool(payload.get("should_block"))
        or bool(payload.get("shouldblock"))
        or bool(payload.get("should_warn"))
        or bool(payload.get("shouldwarn"))
        or response_status in {"denied", "blocked", "failed", "error"}
        or errors_detected
    )

    reasons: list[str] = []

    if force_block:
        reasons.append("hard block triggered by policy, matched signal, or error")
        return SandboxRouteDecision(
            lane=SandboxLane.HARD_BLOCK,
            should_execute=False,
            requires_review=review_required,
            isolate_output=True,
            allow_network=False,
            allow_tool_calls=False,
            allow_file_write=False,
            reason=reasons[0],
            reasons=reasons,
            risk_score=max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
            policy_verdict="block",
            metadata={"source": "sandbox_router"},
        )

    if "prompt injection" in signal_text or "jailbreak" in signal_text or "ignore previous instructions" in signal_text or "system prompt" in signal_text:
        reasons.append("prompt injection indicators detected")
        return SandboxRouteDecision(
            lane=SandboxLane.PROMPT_INJECTION,
            should_execute=False,
            requires_review=True,
            isolate_output=True,
            allow_network=False,
            allow_tool_calls=False,
            allow_file_write=False,
            reason=reasons[0],
            reasons=reasons,
            risk_score=max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
            policy_verdict="block",
            metadata={"source": "sandbox_router"},
        )

    if "quarantine" in signal_text or "malware" in signal_text or "payload" in signal_text or "executable" in signal_text or "macro" in signal_text:
        reasons.append("file or artifact should be isolated in quarantine lane")
        return SandboxRouteDecision(
            lane=SandboxLane.FILE_QUARANTINE,
            should_execute=False,
            requires_review=True,
            isolate_output=True,
            allow_network=False,
            allow_tool_calls=False,
            allow_file_write=False,
            reason=reasons[0],
            reasons=reasons,
            risk_score=max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
            policy_verdict="block",
            metadata={"source": "sandbox_router"},
        )

    if "download" in signal_text or "dependency" in signal_text or "package" in signal_text or "repository" in signal_text or "repo" in signal_text:
        reasons.append("downloaded or imported material requires restricted review lane")
        return SandboxRouteDecision(
            lane=SandboxLane.DOWNLOAD_REVIEW,
            should_execute=False,
            requires_review=True,
            isolate_output=True,
            allow_network=False,
            allow_tool_calls=False,
            allow_file_write=False,
            reason=reasons[0],
            reasons=reasons,
            risk_score=max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
            policy_verdict="block",
            metadata={"source": "sandbox_router"},
        )

    if "http" in signal_text or "network" in signal_text or "fetch" in signal_text or "url" in signal_text:
        reasons.append("network-linked action routed to restricted network lane")
        return SandboxRouteDecision(
            lane=SandboxLane.NETWORK_RESTRICTED,
            should_execute=False,
            requires_review=True,
            isolate_output=True,
            allow_network=False,
            allow_tool_calls=False,
            allow_file_write=False,
            reason=reasons[0],
            reasons=reasons,
            risk_score=max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
            policy_verdict="block",
            metadata={"source": "sandbox_router"},
        )

    if "toolcall" in signal_text or "tool call" in signal_text or "shell" in signal_text or "command" in signal_text or "subprocess" in signal_text:
        reasons.append("tool or command execution requires restricted tool-call lane")
        return SandboxRouteDecision(
            lane=SandboxLane.TOOL_CALL_RESTRICTED,
            should_execute=False,
            requires_review=True,
            isolate_output=True,
            allow_network=False,
            allow_tool_calls=False,
            allow_file_write=False,
            reason=reasons[0],
            reasons=reasons,
            risk_score=max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
            policy_verdict="block",
            metadata={"source": "sandbox_router"},
        )

    if review_required or risk_score > RISK_THRESHOLD_ALLOW_MAX:
        reasons.append("moderate risk routed for human review")
        return SandboxRouteDecision(
            lane=SandboxLane.HUMAN_REVIEW,
            should_execute=False,
            requires_review=True,
            isolate_output=True,
            allow_network=False,
            allow_tool_calls=False,
            allow_file_write=False,
            reason=reasons[0],
            reasons=reasons,
            risk_score=max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
            policy_verdict="block",
            metadata={"source": "sandbox_router"},
        )

    reasons.append("request qualifies for safe readonly handling")
    return SandboxRouteDecision(
        lane=SandboxLane.SAFE_READONLY,
        should_execute=True,
        requires_review=False,
        isolate_output=False,
        allow_network=False,
        allow_tool_calls=False,
        allow_file_write=False,
        reason=reasons[0],
        reasons=reasons,
        risk_score=risk_score,
        policy_verdict="allow",
        metadata={"source": "sandbox_router"},
    )


def summarize_sandbox_route(payload: Mapping[str, Any]) -> dict[str, Any]:
    return route_to_sandbox(payload).to_dict()


__all__ = [
    "SandboxLane",
    "SandboxRouteDecision",
    "route_to_sandbox",
    "summarize_sandbox_route",
]
