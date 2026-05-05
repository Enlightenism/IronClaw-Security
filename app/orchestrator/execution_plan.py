from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from app.orchestrator.orchestrator import OrchestrationDecision


ExecutionLane = Literal[
    "direct_allow",
    "review_required",
    "quarantine_isolation",
    "hard_block",
]

IsolationProfile = Literal[
    "none",
    "observation_only",
    "restricted_sandbox",
    "full_quarantine",
]

ApprovalMode = Literal[
    "none",
    "operator_confirm",
    "security_review",
]

EscalationReason = Literal[
    "clean_allow",
    "policy_review",
    "scan_warning",
    "quarantine_required",
    "block_required",
    "fallback_review",
]


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _clamp_risk(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0, min(100, parsed))


def _copy_str_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    return [str(value).strip() for value in values if str(value).strip()]


@dataclass(slots=True)
class ExecutionPlan:
    agent_id: str
    file_path: str
    verdict: str
    allowed: bool
    should_halt: bool
    should_warn: bool
    lane: ExecutionLane
    isolation_profile: IsolationProfile
    approval_mode: ApprovalMode
    escalation_reason: EscalationReason
    summary: str
    target: str
    action_type: str
    risk_score: int
    matched_patterns: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    decision_source: str = "guard_api"
    registry_threat_profile: str = "standard"
    registry_tags: list[str] = field(default_factory=list)
    requires_sandbox: bool = False
    requires_audit_log: bool = True
    requires_human_in_loop: bool = False
    scan_id: str | None = None
    client_id: str | None = None
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _lane_for_decision(decision: OrchestrationDecision) -> ExecutionLane:
    if decision.verdict == "block":
        return "hard_block"
    if decision.verdict == "quarantine":
        return "quarantine_isolation"
    if decision.verdict == "warn":
        return "review_required"
    return "direct_allow"


def _isolation_for_decision(decision: OrchestrationDecision) -> IsolationProfile:
    if decision.verdict == "block":
        return "full_quarantine"
    if decision.verdict == "quarantine":
        return "full_quarantine"
    if decision.verdict == "warn":
        if decision.registry_threat_profile in {"execution_capable", "security_critical"}:
            return "restricted_sandbox"
        return "observation_only"
    return "none"


def _approval_mode_for_decision(decision: OrchestrationDecision) -> ApprovalMode:
    if decision.verdict == "block":
        return "security_review"
    if decision.verdict == "quarantine":
        return "security_review"
    if decision.verdict == "warn":
        return "operator_confirm"
    return "none"


def _escalation_reason_for_decision(decision: OrchestrationDecision) -> EscalationReason:
    if decision.decision_source == "guard_api_fallback":
        return "fallback_review"
    if decision.verdict == "block":
        return "block_required"
    if decision.verdict == "quarantine":
        return "quarantine_required"
    if decision.verdict == "warn":
        if decision.risk_score > 0 or decision.matched_patterns:
            return "scan_warning"
        return "policy_review"
    return "clean_allow"


def _recommended_actions_for_decision(
    decision: OrchestrationDecision,
    *,
    lane: ExecutionLane,
    isolation_profile: IsolationProfile,
    approval_mode: ApprovalMode,
) -> list[str]:
    actions: list[str] = []

    if lane == "hard_block":
        actions.extend(
            [
                "Block execution immediately.",
                "Record the denial in audit logs.",
                "Escalate to security review.",
            ]
        )
    elif lane == "quarantine_isolation":
        actions.extend(
            [
                "Route execution into quarantine handling.",
                "Prevent direct execution outside the sandbox.",
                "Require security review before release.",
            ]
        )
    elif lane == "review_required":
        actions.extend(
            [
                "Hold for supervisor review before unrestricted execution.",
                "Capture audit evidence for operator review.",
            ]
        )
    else:
        actions.append("Allow execution with normal audit logging.")

    if isolation_profile == "restricted_sandbox":
        actions.append("Run only in a restricted sandbox.")
    elif isolation_profile == "full_quarantine":
        actions.append("Keep artifacts isolated in full quarantine.")

    if approval_mode == "operator_confirm":
        actions.append("Require explicit operator confirmation.")
    elif approval_mode == "security_review":
        actions.append("Require explicit security-team approval.")

    if decision.decision_source == "guard_api_fallback":
        actions.append("Re-run guard evaluation when guard API recovers.")

    return actions


def build_execution_plan(decision: OrchestrationDecision) -> ExecutionPlan:
    lane = _lane_for_decision(decision)
    isolation_profile = _isolation_for_decision(decision)
    approval_mode = _approval_mode_for_decision(decision)
    escalation_reason = _escalation_reason_for_decision(decision)

    requires_sandbox = lane in {"quarantine_isolation", "hard_block"} or (
        lane == "review_required"
        and isolation_profile in {"restricted_sandbox", "full_quarantine"}
    )

    requires_human_in_loop = approval_mode in {"operator_confirm", "security_review"}

    recommended_actions = _recommended_actions_for_decision(
        decision,
        lane=lane,
        isolation_profile=isolation_profile,
        approval_mode=approval_mode,
    )

    return ExecutionPlan(
        agent_id=_text(decision.agent_id),
        file_path=_text(decision.file_path),
        verdict=_text(decision.verdict, "allow"),
        allowed=bool(decision.allowed),
        should_halt=bool(decision.should_halt),
        should_warn=bool(decision.should_warn),
        lane=lane,
        isolation_profile=isolation_profile,
        approval_mode=approval_mode,
        escalation_reason=escalation_reason,
        summary=_text(decision.summary),
        target=_text(decision.target),
        action_type=_text(decision.action_type),
        risk_score=_clamp_risk(decision.risk_score),
        matched_patterns=_copy_str_list(decision.matched_patterns),
        recommended_actions=recommended_actions,
        decision_source=_text(decision.decision_source, "guard_api"),
        registry_threat_profile=_text(decision.registry_threat_profile, "standard"),
        registry_tags=_copy_str_list(decision.registry_tags),
        requires_sandbox=requires_sandbox,
        requires_audit_log=True,
        requires_human_in_loop=requires_human_in_loop,
        scan_id=_text(decision.scan_id) or None,
        client_id=_text(decision.client_id) or None,
        session_id=_text(decision.session_id) or None,
    )


if __name__ == "__main__":
    sample = OrchestrationDecision(
        agent_id="ic-agent-sample",
        file_path="app/services/scanner.py",
        action_type="tool_call",
        target="scanner",
        content="perform_scan(...)",
        allowed=False,
        verdict="quarantine",
        should_halt=True,
        should_warn=True,
        summary="Execution should be quarantined for isolated handling.",
        risk_score=55,
        matched_patterns=["heuristic_prompt_injection_score"],
        decision_source="guard_api",
        registry_tags=["python", "security", "scanner"],
        registry_threat_profile="security_critical",
        scan_id="sample-scan-id",
        client_id="sample-client",
        session_id="sample-session",
    )
    plan = build_execution_plan(sample)
    print(plan.to_dict())