from __future__ import annotations

from typing import Literal

from app.services.action_guard import (
    ActionGuardDecision,
    ActionType,
    VerdictType,
    analyze_action,
)
from app.services.action_policy import (
    ActionPolicyDecision,
    evaluate_action_policy,
)
from app.services.verdict_enforcer import EnforcedVerdict, enforce_verdict

FinalDecisionSource = Literal["policy", "scan", "policy_and_scan"]


def _resolve_final_verdict(
    policy_verdict: VerdictType,
    guard_verdict: VerdictType,
) -> VerdictType:
    return "allow" if policy_verdict == "allow" and guard_verdict == "allow" else "block"


def _decision_source(
    policy_decision: ActionPolicyDecision,
    guard_decision: ActionGuardDecision,
    final_verdict: VerdictType,
) -> FinalDecisionSource:
    policy_used = policy_decision["verdict"] == final_verdict
    scan_used = guard_decision["verdict"] == final_verdict

    if policy_used and scan_used:
        return "policy_and_scan"
    if policy_used:
        return "policy"
    return "scan"


def _build_summary(
    policy_decision: ActionPolicyDecision,
    guard_decision: ActionGuardDecision,
    decision_source: FinalDecisionSource,
) -> str:
    policy_summary = policy_decision["summary"].strip()
    guard_summary = guard_decision["summary"].strip()

    if decision_source == "policy_and_scan":
        if policy_summary == guard_summary:
            return policy_summary
        return f"{policy_summary} {guard_summary}".strip()

    if decision_source == "policy":
        return policy_summary

    return guard_summary


def evaluate_action_execution(
    action_type: ActionType,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
) -> EnforcedVerdict:
    policy_decision = evaluate_action_policy(
        action_type=action_type,
        target=target,
        client_id=client_id,
        session_id=session_id,
    )

    guard_decision = analyze_action(
        action_type=action_type,
        target=target,
        content=content,
        client_id=client_id,
        session_id=session_id,
        agent_id=agent_id,
    )

    final_verdict = _resolve_final_verdict(
        policy_decision["verdict"],
        guard_decision["verdict"],
    )

    decision_source = _decision_source(
        policy_decision=policy_decision,
        guard_decision=guard_decision,
        final_verdict=final_verdict,
    )

    summary = _build_summary(
        policy_decision=policy_decision,
        guard_decision=guard_decision,
        decision_source=decision_source,
    )

    reasons: list[dict[str, object]] = [
        *policy_decision["reasons"],
        *guard_decision["reasons"],
    ]

    return enforce_verdict(
        action_type=action_type,
        target=target,
        content=content,
        verdict=final_verdict,
        summary=summary,
        risk_score=guard_decision["risk_score"],
        should_halt=final_verdict == "block",
        should_warn=False,
        scan_id=guard_decision["scan_id"],
        matched_patterns=guard_decision["matched_patterns"],
        categories=guard_decision.get("categories", []),
        decision_source=decision_source,
        policy_mode=policy_decision["policy_mode"],
        client_id=client_id,
        session_id=session_id,
        agent_id=agent_id,
        reasons=reasons,
        drift_report=guard_decision.get("drift_report"),
        guard_decision=None,
    )
