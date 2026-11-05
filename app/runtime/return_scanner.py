"""In-process return scan: guard checks, the text classifier, and the AI brain. Any suspicion blocks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.runtime.file_return_guard import FileReturnGuardDecision, evaluate_file_return
from app.runtime.network_guard import NetworkGuardDecision, evaluate_network_request
from app.runtime.tool_call_guard import ToolCallGuardDecision, evaluate_tool_call
from app.services.guard import guard_text
from app.services.guard_security_brain import build_guard_security_request, evaluate_guard_security_request

ALLOW_VERDICT = "allow"
BLOCK_VERDICT = "block"


@dataclass(frozen=True)
class ReturnScanResult:
    verdict: str
    risk_score: int
    reasons: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict != ALLOW_VERDICT


GuardDecision = ToolCallGuardDecision | NetworkGuardDecision | FileReturnGuardDecision


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [text for item in value.values() for text in _flatten_strings(item)]
    if isinstance(value, list | tuple):
        return [text for item in value for text in _flatten_strings(item)]
    return []


def _guard_blocks(decision: GuardDecision, *, must_release: bool = False) -> bool:
    if not decision.allowed or decision.policy_verdict != ALLOW_VERDICT or decision.halted_by_boundary or decision.requires_review:
        return True
    return must_release and not decision.should_release


def scan_return(
    payload: Mapping[str, Any],
    *,
    content: str,
    platform: str,
    action_type: str,
    target: str,
    client_id: str | None = None,
    session_id: str | None = None,
) -> ReturnScanResult:
    reasons: list[str] = []
    risk_scores: list[int] = []

    tool_decision = evaluate_tool_call(payload)
    risk_scores.append(tool_decision.risk_score)
    if _guard_blocks(tool_decision):
        reasons.append("tool_call_guard")
        reasons.extend(tool_decision.reasons)

    if "url" in payload:
        network_decision = evaluate_network_request(payload)
        risk_scores.append(network_decision.risk_score)
        if _guard_blocks(network_decision):
            reasons.append("network_guard")
            reasons.extend(network_decision.reasons)

    if "file_name" in payload or "file_path" in payload:
        file_decision = evaluate_file_return(payload)
        risk_scores.append(file_decision.risk_score)
        if _guard_blocks(file_decision, must_release=True):
            reasons.append("file_return_guard")
            reasons.extend(file_decision.reasons)

    text = "\n".join([content, *_flatten_strings(payload)])
    text_decision = guard_text("tool_output", text)
    if text_decision["verdict"] != ALLOW_VERDICT:
        reasons.append("text_classifier")
    risk_scores.append(text_decision["risk_score"])

    brain_request = build_guard_security_request(
        action_type=action_type,
        target=target,
        content=text,
        client_id=client_id,
        session_id=session_id,
        metadata={"platform": platform},
    )
    brain_decision = evaluate_guard_security_request(brain_request, mode="enforce")
    risk_scores.append(brain_decision.risk_score)
    if brain_decision.verdict != ALLOW_VERDICT:
        reasons.append("ai_brain")
        reasons.extend(brain_decision.signals)

    verdict = BLOCK_VERDICT if reasons else ALLOW_VERDICT
    return ReturnScanResult(verdict=verdict, risk_score=max(risk_scores), reasons=reasons)
