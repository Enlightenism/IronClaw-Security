from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
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


def _is_valid_risk_score(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100


def _copy_str_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    return [str(value).strip() for value in values if str(value).strip()]


@dataclass(slots=True)
class ExecutionPlan:
    agent_id: str
    file_path: str
    verdict: Literal["allow", "block"]
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


def normalize_plan_verdict(plan: ExecutionPlan) -> Literal["allow", "block"]:
    risk_score = _clamp_risk(plan.risk_score, default=RISK_THRESHOLD_BLOCK_MIN)
    if (
        plan.verdict == "allow"
        and plan.allowed is True
        and plan.should_halt is False
        and plan.should_warn is False
        and isinstance(plan.matched_patterns, list)
        and not plan.matched_patterns
        and _is_valid_risk_score(plan.risk_score)
        and risk_score <= RISK_THRESHOLD_ALLOW_MAX
        and plan.decision_source in {"guard_api", "registry_only"}
    ):
        return "allow"
    return "block"


def normalized_plan_risk_score(plan: ExecutionPlan) -> int:
    risk_score = _clamp_risk(plan.risk_score, default=RISK_THRESHOLD_BLOCK_MIN)
    if normalize_plan_verdict(plan) == "block":
        return max(risk_score, RISK_THRESHOLD_BLOCK_MIN)
    return risk_score


def _decision_verdict(decision: OrchestrationDecision) -> Literal["allow", "block"]:
    risk_score = _clamp_risk(decision.risk_score, default=RISK_THRESHOLD_BLOCK_MIN)
    if (
        decision.verdict == "allow"
        and decision.allowed is True
        and decision.should_halt is False
        and decision.should_warn is False
        and isinstance(decision.matched_patterns, list)
        and not decision.matched_patterns
        and _is_valid_risk_score(decision.risk_score)
        and risk_score <= RISK_THRESHOLD_ALLOW_MAX
        and decision.decision_source in {"guard_api", "registry_only"}
    ):
        return "allow"
    return "block"


def _lane_for_decision(decision: OrchestrationDecision) -> ExecutionLane:
    return "direct_allow" if _decision_verdict(decision) == "allow" else "hard_block"


def _isolation_for_decision(decision: OrchestrationDecision) -> IsolationProfile:
    return "none" if _decision_verdict(decision) == "allow" else "full_quarantine"


def _approval_mode_for_decision(decision: OrchestrationDecision) -> ApprovalMode:
    return "none" if _decision_verdict(decision) == "allow" else "security_review"


def _escalation_reason_for_decision(decision: OrchestrationDecision) -> EscalationReason:
    if decision.decision_source == "guard_api_fallback":
        return "fallback_review"
    if _decision_verdict(decision) == "block":
        return "block_required"
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
            ],
        )
    elif lane == "quarantine_isolation":
        actions.extend(
            [
                "Route execution into quarantine handling.",
                "Prevent direct execution outside the sandbox.",
                "Require security review before release.",
            ],
        )
    elif lane == "review_required":
        actions.extend(
            [
                "Hold for supervisor review before unrestricted execution.",
                "Capture audit evidence for operator review.",
            ],
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
    verdict = _decision_verdict(decision)
    lane = _lane_for_decision(decision)
    isolation_profile = _isolation_for_decision(decision)
    approval_mode = _approval_mode_for_decision(decision)
    escalation_reason = _escalation_reason_for_decision(decision)
    risk_score = _clamp_risk(decision.risk_score, default=RISK_THRESHOLD_BLOCK_MIN)
    if verdict == "block":
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)

    requires_sandbox = lane in {"quarantine_isolation", "hard_block"} or (lane == "review_required" and isolation_profile in {"restricted_sandbox", "full_quarantine"})

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
        verdict=verdict,
        allowed=verdict == "allow",
        should_halt=verdict == "block",
        should_warn=False,
        lane=lane,
        isolation_profile=isolation_profile,
        approval_mode=approval_mode,
        escalation_reason=escalation_reason,
        summary=_text(decision.summary),
        target=_text(decision.target),
        action_type=_text(decision.action_type),
        risk_score=risk_score,
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
        verdict="block",
        should_halt=True,
        should_warn=False,
        summary="Execution is blocked and requires security review.",
        risk_score=RISK_THRESHOLD_BLOCK_MIN,
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
