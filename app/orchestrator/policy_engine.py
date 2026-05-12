from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatch
from typing import Any
from uuid import uuid4

from app.orchestrator.execution_plan import ExecutionPlan

PolicyEffect = str
PolicyMode = str
PolicyDecision = str


@dataclass(frozen=True)
class PolicyContext:
    agent_id: str
    file_path: str
    action_type: str
    target: str
    risk_score: int
    lane: str
    verdict: str
    matched_patterns: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_execution_plan(
        cls,
        plan: ExecutionPlan,
        *,
        agent_id: str,
        file_path: str,
        action_type: str,
        target: str,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyContext:
        return cls(
            agent_id=agent_id,
            file_path=file_path,
            action_type=action_type,
            target=target,
            risk_score=plan.risk_score,
            lane=plan.lane,
            verdict=plan.verdict,
            matched_patterns=list(plan.matched_patterns),
            metadata=metadata or {},
        )


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    name: str
    description: str
    effect: PolicyEffect
    enabled: bool = True
    priority: int = 100
    action_types: tuple[str, ...] = ()
    file_patterns: tuple[str, ...] = ()
    target_patterns: tuple[str, ...] = ()
    lanes: tuple[str, ...] = ()
    verdicts: tuple[str, ...] = ()
    min_risk_score: int | None = None
    requires_pattern_match: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PolicyMatch:
    rule_id: str
    rule_name: str
    effect: PolicyEffect
    priority: int
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PolicyEvaluation:
    evaluation_id: str
    decision: PolicyDecision
    mode: PolicyMode
    allowed: bool
    final_effect: PolicyEffect
    context: PolicyContext
    matched_rules: list[PolicyMatch]
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return {
            "evaluation_id": self.evaluation_id,
            "decision": self.decision,
            "mode": self.mode,
            "allowed": self.allowed,
            "final_effect": self.final_effect,
            "context": asdict(self.context),
            "matched_rules": [match.to_dict() for match in self.matched_rules],
            "created_at": self.created_at,
        }


def _match_any(value: str, patterns: Iterable[str]) -> bool:
    normalized = tuple(patterns)
    if not normalized:
        return True
    return any(fnmatch(value, pattern) for pattern in normalized)


def _patterns_present(
    required_patterns: Iterable[str],
    matched_patterns: Iterable[str],
) -> bool:
    required = tuple(required_patterns)
    if not required:
        return True
    observed = {pattern.lower() for pattern in matched_patterns}
    return any(pattern.lower() in observed for pattern in required)


def _rule_matches(rule: PolicyRule, context: PolicyContext) -> tuple[bool, str]:
    if not rule.enabled:
        return False, "rule disabled"

    if rule.action_types and context.action_type not in rule.action_types:
        return False, "action type mismatch"

    if not _match_any(context.file_path, rule.file_patterns):
        return False, "file path mismatch"

    if not _match_any(context.target, rule.target_patterns):
        return False, "target mismatch"

    if rule.lanes and context.lane not in rule.lanes:
        return False, "lane mismatch"

    if rule.verdicts and context.verdict not in rule.verdicts:
        return False, "verdict mismatch"

    if rule.min_risk_score is not None and context.risk_score < rule.min_risk_score:
        return False, "risk score below threshold"

    if not _patterns_present(rule.requires_pattern_match, context.matched_patterns):
        return False, "required pattern not present"

    return True, "rule matched"


def build_default_policy_rules() -> list[PolicyRule]:
    return [
        PolicyRule(
            rule_id="pol-allow-read",
            name="Allow low-risk reads",
            description="Allows read-oriented activity when the execution plan is safe.",
            effect="allow",
            priority=10,
            action_types=("read", "inspect", "scan"),
            verdicts=("allow",),
            min_risk_score=0,
        ),
        PolicyRule(
            rule_id="pol-review-warn",
            name="Escalate warned actions",
            description="Escalates warning plans into supervisor review.",
            effect="review",
            priority=40,
            verdicts=("warn",),
            min_risk_score=40,
        ),
        PolicyRule(
            rule_id="pol-quarantine-sensitive",
            name="Quarantine sensitive code paths",
            description="Quarantines risky execution in auth, secrets, policy, and config areas.",
            effect="quarantine",
            priority=80,
            file_patterns=("*/auth/*", "*/secrets/*", "*/policy_*", "*/config/*", "*.env"),
            min_risk_score=60,
        ),
        PolicyRule(
            rule_id="pol-block-malware-patterns",
            name="Block malware-class patterns",
            description="Blocks execution when high-risk patterns indicate malware-like behavior.",
            effect="block",
            priority=100,
            verdicts=("block", "quarantine"),
            min_risk_score=80,
            requires_pattern_match=(
                "command_execution",
                "credential_access",
                "persistence",
                "exfiltration",
                "privilege_escalation",
            ),
        ),
        PolicyRule(
            rule_id="pol-review-write-runtime",
            name="Review runtime write actions",
            description="Routes write-like runtime actions for review when risk is non-trivial.",
            effect="review",
            priority=50,
            action_types=("write", "modify", "tool_call", "execute"),
            min_risk_score=35,
        ),
    ]


def resolve_policy_effect(matches: list[PolicyMatch]) -> PolicyEffect:
    if not matches:
        return "allow"

    strongest = max(matches, key=lambda item: item.priority)
    return strongest.effect


def effect_to_decision(effect: PolicyEffect, mode: PolicyMode) -> tuple[PolicyDecision, bool]:
    if mode == "monitor":
        return "monitor", True
    if effect == "allow":
        return "allow", True
    if effect == "review":
        return "review", True
    if effect == "quarantine":
        return "quarantine", False
    if effect == "block":
        return "block", False
    return "allow", True


def evaluate_policy(
    context: PolicyContext,
    rules: list[PolicyRule] | None = None,
    *,
    mode: PolicyMode = "enforce",
) -> PolicyEvaluation:
    active_rules = sorted(
        rules or build_default_policy_rules(),
        key=lambda rule: rule.priority,
        reverse=True,
    )

    matches: list[PolicyMatch] = []
    for rule in active_rules:
        matched, reason = _rule_matches(rule, context)
        if matched:
            matches.append(
                PolicyMatch(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    effect=rule.effect,
                    priority=rule.priority,
                    reason=reason,
                )
            )

    final_effect = resolve_policy_effect(matches)
    decision, allowed = effect_to_decision(final_effect, mode)

    return PolicyEvaluation(
        evaluation_id=f"pe-{uuid4().hex[:12]}",
        decision=decision,
        mode=mode,
        allowed=allowed,
        final_effect=final_effect,
        context=context,
        matched_rules=matches,
    )


def apply_policy_to_plan(
    plan: ExecutionPlan,
    *,
    agent_id: str,
    file_path: str,
    action_type: str,
    target: str,
    rules: list[PolicyRule] | None = None,
    mode: PolicyMode = "enforce",
    metadata: dict[str, Any] | None = None,
) -> tuple[ExecutionPlan, PolicyEvaluation]:
    context = PolicyContext.from_execution_plan(
        plan,
        agent_id=agent_id,
        file_path=file_path,
        action_type=action_type,
        target=target,
        metadata=metadata,
    )
    evaluation = evaluate_policy(context, rules, mode=mode)

    if mode == "monitor":
        return plan, evaluation

    if evaluation.final_effect == "review":
        updated_plan = ExecutionPlan(
            agent_id=plan.agent_id,
            file_path=plan.file_path,
            verdict="warn",
            allowed=plan.allowed,
            should_halt=plan.should_halt,
            should_warn=True,
            lane=plan.lane,
            isolation_profile=plan.isolation_profile,
            approval_mode=plan.approval_mode,
            escalation_reason=plan.escalation_reason,
            summary=f"{plan.summary} | Policy requires supervisor review.",
            target=plan.target,
            action_type=plan.action_type,
            risk_score=max(plan.risk_score, 50),
            matched_patterns=plan.matched_patterns,
            recommended_actions=plan.recommended_actions,
            decision_source=plan.decision_source,
            registry_threat_profile=plan.registry_threat_profile,
            registry_tags=plan.registry_tags,
            requires_sandbox=plan.requires_sandbox,
            requires_audit_log=plan.requires_audit_log,
            requires_human_in_loop=True,
            scan_id=plan.scan_id,
            client_id=plan.client_id,
            session_id=plan.session_id,
        )
        return updated_plan, evaluation

    if evaluation.final_effect == "quarantine":
        updated_plan = ExecutionPlan(
            agent_id=plan.agent_id,
            file_path=plan.file_path,
            verdict="quarantine",
            allowed=False,
            should_halt=True,
            should_warn=True,
            lane="quarantine_isolation",
            isolation_profile="full_quarantine",
            approval_mode="security_review",
            escalation_reason=plan.escalation_reason,
            summary=f"{plan.summary} | Policy forced quarantine.",
            target=plan.target,
            action_type=plan.action_type,
            risk_score=max(plan.risk_score, 75),
            matched_patterns=plan.matched_patterns,
            recommended_actions=plan.recommended_actions,
            decision_source=plan.decision_source,
            registry_threat_profile=plan.registry_threat_profile,
            registry_tags=plan.registry_tags,
            requires_sandbox=True,
            requires_audit_log=plan.requires_audit_log,
            requires_human_in_loop=True,
            scan_id=plan.scan_id,
            client_id=plan.client_id,
            session_id=plan.session_id,
        )
        return updated_plan, evaluation

    if evaluation.final_effect == "block":
        updated_plan = ExecutionPlan(
            agent_id=plan.agent_id,
            file_path=plan.file_path,
            verdict="block",
            allowed=False,
            should_halt=True,
            should_warn=True,
            lane="hard_block",
            isolation_profile="full_quarantine",
            approval_mode="security_review",
            escalation_reason=plan.escalation_reason,
            summary=f"{plan.summary} | Policy blocked execution.",
            target=plan.target,
            action_type=plan.action_type,
            risk_score=max(plan.risk_score, 90),
            matched_patterns=plan.matched_patterns,
            recommended_actions=plan.recommended_actions,
            decision_source=plan.decision_source,
            registry_threat_profile=plan.registry_threat_profile,
            registry_tags=plan.registry_tags,
            requires_sandbox=True,
            requires_audit_log=plan.requires_audit_log,
            requires_human_in_loop=True,
            scan_id=plan.scan_id,
            client_id=plan.client_id,
            session_id=plan.session_id,
        )
        return updated_plan, evaluation

    return plan, evaluation


if __name__ == "__main__":
    import json

    sample_plan = ExecutionPlan(
        agent_id="agent-scanner",
        file_path="app/auth/secrets_manager.py",
        verdict="warn",
        allowed=True,
        should_halt=False,
        should_warn=True,
        lane="review_required",
        isolation_profile="restricted_sandbox",
        approval_mode="operator_confirm",
        escalation_reason="scan_warning",
        summary="Potentially unsafe tool call detected.",
        target="app/auth/secrets_manager.py",
        action_type="tool_call",
        risk_score=68,
        matched_patterns=["credential_access"],
        recommended_actions=["inspect", "review"],
        decision_source="guard_api",
        registry_threat_profile="security_critical",
        registry_tags=["python", "security"],
        requires_sandbox=True,
        requires_audit_log=True,
        requires_human_in_loop=True,
        scan_id="scan-demo-001",
        client_id="agent-scanner",
        session_id="session-demo-001",
    )

    updated_plan, evaluation = apply_policy_to_plan(
        sample_plan,
        agent_id="agent-scanner",
        file_path="app/auth/secrets_manager.py",
        action_type="tool_call",
        target="app/auth/secrets_manager.py",
    )

    print(
        json.dumps(
            {
                "updated_plan": updated_plan.to_dict(),
                "policy_evaluation": evaluation.to_dict(),
            },
            ensure_ascii=False,
            indent=2,
        )
    )