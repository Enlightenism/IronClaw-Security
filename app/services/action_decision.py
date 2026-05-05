from __future__ import annotations

import json
import os
from typing import Any, Literal, TypedDict

from app.services.action_guard import (
    ActionGuardDecision,
    ActionType,
    VerdictType,
    analyze_action,
)
from app.services.action_policy import (
    ActionPolicyDecision,
    PolicyMode,
    evaluate_action_policy,
)

FinalDecisionSource = Literal["policy", "scan", "policy_and_scan"]


class ActionExecutionDecision(TypedDict):
    action_type: ActionType
    target: str
    content: str
    policy_mode: PolicyMode
    verdict: VerdictType
    summary: str
    risk_score: int
    matched_patterns: list[str]
    scan_id: str | None
    should_halt: bool
    should_warn: bool
    decision_source: FinalDecisionSource
    client_id: str | None
    session_id: str | None
    reasons: list[dict[str, object]]


def _verdict_rank(verdict: VerdictType) -> int:
    order: dict[VerdictType, int] = {
        "allow": 1,
        "warn": 2,
        "quarantine": 3,
        "block": 4,
    }
    return order[verdict]


def _resolve_final_verdict(
    policy_verdict: VerdictType,
    guard_verdict: VerdictType,
) -> VerdictType:
    return (
        policy_verdict
        if _verdict_rank(policy_verdict) >= _verdict_rank(guard_verdict)
        else guard_verdict
    )


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


def _should_halt(final_verdict: VerdictType) -> bool:
    return final_verdict in ("block", "quarantine")


def _should_warn(final_verdict: VerdictType) -> bool:
    return final_verdict in ("warn", "quarantine")


def _build_ai_reason(
    action_type: ActionType,
    target: str,
    content: str,
    policy_decision: ActionPolicyDecision,
    guard_decision: ActionGuardDecision,
) -> dict[str, object] | None:
    if os.getenv("USE_GROQ_AI_REASONS", "1") != "1":
        return None

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None

    try:
        from groq import Groq
    except ModuleNotFoundError:
        return None

    existing_reasons: list[dict[str, object]] = [
        *policy_decision["reasons"],
        *guard_decision["reasons"],
    ]

    system_prompt = (
        "You are a security reasoning engine. "
        "Return only valid JSON with keys: source, label, details, score. "
        "Use source='ai'. "
        "label must be short. "
        "details must be concise and useful. "
        "score must be a float from 0 to 1."
    )

    user_prompt = json.dumps(
        {
            "action_type": action_type,
            "target": target,
            "content": content,
            "policy_mode": policy_decision["policy_mode"],
            "policy_verdict": policy_decision["verdict"],
            "policy_summary": policy_decision["summary"],
            "guard_verdict": guard_decision["verdict"],
            "guard_summary": guard_decision["summary"],
            "risk_score": guard_decision["risk_score"],
            "matched_patterns": guard_decision["matched_patterns"],
            "existing_reasons": existing_reasons,
        }
    )

    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=os.getenv("GROQ_REASON_MODEL", "llama3-70b-8192"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )

        raw_content = response.choices[0].message.content or ""
        parsed: dict[str, Any] = json.loads(raw_content)

        label = str(parsed.get("label", "")).strip() or "AI assessment"
        details = str(parsed.get("details", "")).strip()
        score_raw = parsed.get("score")

        try:
            score = float(score_raw) if score_raw is not None else None
        except (TypeError, ValueError):
            score = None

        return {
            "source": "ai",
            "label": label,
            "details": details,
            "score": score,
        }
    except Exception:
        return None


def evaluate_action_execution(
    action_type: ActionType,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
) -> ActionExecutionDecision:
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

    ai_reason = _build_ai_reason(
        action_type=action_type,
        target=target,
        content=content,
        policy_decision=policy_decision,
        guard_decision=guard_decision,
    )
    if ai_reason is not None:
        reasons.append(ai_reason)

    return {
        "action_type": action_type,
        "target": target,
        "content": content,
        "policy_mode": policy_decision["policy_mode"],
        "verdict": final_verdict,
        "summary": summary,
        "risk_score": guard_decision["risk_score"],
        "matched_patterns": guard_decision["matched_patterns"],
        "scan_id": guard_decision["scan_id"],
        "should_halt": _should_halt(final_verdict),
        "should_warn": _should_warn(final_verdict),
        "decision_source": decision_source,
        "client_id": client_id,
        "session_id": session_id,
        "reasons": reasons,
    }