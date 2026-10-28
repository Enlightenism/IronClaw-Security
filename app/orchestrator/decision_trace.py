from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.orchestrator.execution_plan import (
    ExecutionPlan,
    normalize_plan_verdict,
    normalized_plan_risk_score,
)
from app.orchestrator.policy_engine import PolicyEvaluation
from app.orchestrator.runtime_session import RuntimeSession
from app.orchestrator.supervisor import SessionExecutionRecord, SupervisorEscalation

TraceOutcome = Literal["allowed", "blocked"]


@dataclass(frozen=True)
class TraceActor:
    agent_id: str
    session_id: str
    file_path: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TraceAction:
    action_type: str
    target: str
    content_preview: str
    content_length: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TraceEvidence:
    matched_rules: list[dict[str, Any]] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    escalations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DecisionTrace:
    trace_id: str
    created_at: str
    outcome: TraceOutcome
    actor: TraceActor
    action: TraceAction
    execution_plan: dict[str, Any]
    policy_evaluation: dict[str, Any] | None
    evidence: TraceEvidence
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "created_at": self.created_at,
            "outcome": self.outcome,
            "actor": self.actor.to_dict(),
            "action": self.action.to_dict(),
            "execution_plan": self.execution_plan,
            "policy_evaluation": self.policy_evaluation,
            "evidence": self.evidence.to_dict(),
            "summary": self.summary,
            "metadata": self.metadata,
        }


def _content_preview(content: str, limit: int = 120) -> str:
    normalized = " ".join(content.split())
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[:limit].rstrip()}..."


def _trace_outcome(plan: ExecutionPlan) -> TraceOutcome:
    return "allowed" if normalize_plan_verdict(plan) == "allow" else "blocked"


def _matching_escalations(
    escalations: list[SupervisorEscalation] | None,
    *,
    session_id: str,
    agent_id: str,
    file_path: str,
) -> list[SupervisorEscalation]:
    if not escalations:
        return []

    return [item for item in escalations if item.session_id == session_id or (item.agent_id == agent_id and item.file_path == file_path)]


def build_decision_trace(
    *,
    session: RuntimeSession,
    action_type: str,
    target: str,
    content: str,
    execution_plan: ExecutionPlan,
    policy_evaluation: PolicyEvaluation | None = None,
    escalations: list[SupervisorEscalation] | None = None,
    metadata: dict[str, Any] | None = None,
) -> DecisionTrace:
    matched_escalations = _matching_escalations(
        escalations,
        session_id=session.session_id,
        agent_id=session.agent_id,
        file_path=session.file_path,
    )

    evidence = TraceEvidence(
        matched_rules=[
            {
                **match.to_dict(),
                "effect": "allow" if match.effect == "allow" else "block",
            }
            for match in (policy_evaluation.matched_rules if policy_evaluation else [])
        ],
        matched_patterns=list(execution_plan.matched_patterns),
        recommended_actions=list(execution_plan.recommended_actions),
        escalations=[item.to_dict() for item in matched_escalations],
    )

    normalized_verdict = normalize_plan_verdict(execution_plan)
    normalized_risk_score = normalized_plan_risk_score(execution_plan)
    execution_plan_data = execution_plan.to_dict()
    execution_plan_data.update(
        verdict=normalized_verdict,
        allowed=normalized_verdict == "allow",
        should_halt=normalized_verdict == "block",
        should_warn=False,
        risk_score=normalized_risk_score,
    )

    policy_evaluation_data = None
    policy_verdict = None
    if policy_evaluation is not None:
        policy_context = policy_evaluation.context
        context_is_allow = policy_context.verdict == "allow" and policy_context.risk_score <= RISK_THRESHOLD_ALLOW_MAX and not policy_context.matched_patterns
        policy_verdict = "allow" if policy_evaluation.final_effect == "allow" and policy_evaluation.decision == "allow" and policy_evaluation.allowed and context_is_allow else "block"
        policy_evaluation_data = policy_evaluation.to_dict()
        policy_evaluation_data.update(
            decision=policy_verdict,
            final_effect=policy_verdict,
            allowed=policy_verdict == "allow",
        )
        context_data = policy_evaluation_data.get("context")
        if isinstance(context_data, dict):
            context_data["verdict"] = "allow" if context_is_allow else "block"
            if not context_is_allow:
                context_data["risk_score"] = max(
                    int(context_data.get("risk_score", 0)),
                    RISK_THRESHOLD_BLOCK_MIN,
                )

    outcome = _trace_outcome(execution_plan)
    summary_parts = [
        f"Agent {session.agent_id} executed {action_type} on {target}.",
        f"Final verdict: {normalized_verdict}.",
        f"Lane: {execution_plan.lane}.",
        f"Risk score: {normalized_risk_score}.",
    ]
    if policy_evaluation is not None:
        summary_parts.append(
            f"Policy decision: {policy_verdict}.",
        )
    if matched_escalations:
        summary_parts.append(f"Escalations: {len(matched_escalations)}.")
    summary_parts.append(execution_plan.summary)

    return DecisionTrace(
        trace_id=f"dt-{uuid4().hex[:16]}",
        created_at=datetime.now(UTC).isoformat(),
        outcome=outcome,
        actor=TraceActor(
            agent_id=session.agent_id,
            session_id=session.session_id,
            file_path=session.file_path,
        ),
        action=TraceAction(
            action_type=action_type,
            target=target,
            content_preview=_content_preview(content),
            content_length=len(content),
        ),
        execution_plan=execution_plan_data,
        policy_evaluation=policy_evaluation_data,
        evidence=evidence,
        summary=" ".join(summary_parts),
        metadata=metadata or {},
    )


def build_trace_from_execution_record(
    record: SessionExecutionRecord,
    *,
    action_type: str,
    target: str,
    content: str,
    policy_evaluation: PolicyEvaluation | None = None,
    escalations: list[SupervisorEscalation] | None = None,
    metadata: dict[str, Any] | None = None,
) -> DecisionTrace:
    return build_decision_trace(
        session=record.session,
        action_type=action_type,
        target=target,
        content=content,
        execution_plan=record.execution_plan,
        policy_evaluation=policy_evaluation,
        escalations=escalations,
        metadata=metadata,
    )


def save_decision_trace(trace: DecisionTrace, output_path: str | Path) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(trace.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def append_decision_trace_jsonl(trace: DecisionTrace, output_path: str | Path) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(trace.to_dict(), ensure_ascii=False) + "\n")
    return path


if __name__ == "__main__":
    from app.orchestrator.coordination_state import initialize_coordination_state
    from app.orchestrator.dependency_graph import build_dependency_graph
    from app.orchestrator.orchestrator import IronClawOrchestrator
    from app.orchestrator.policy_engine import apply_policy_to_plan
    from app.orchestrator.supervisor import (
        SessionExecutionRequest,
        initialize_supervisor,
        run_supervised_request,
    )

    root = Path().resolve()
    orchestrator = IronClawOrchestrator(project_root=root)
    graph = build_dependency_graph(root)
    coordination_snapshot = initialize_coordination_state(orchestrator.registry, graph)
    supervisor = initialize_supervisor(orchestrator)

    request = SessionExecutionRequest(
        file_path="app/services/scanner.py",
        action_type="tool_call",
        target="app/services/scanner.py",
        content="export_credentials()",
        use_guard_api=False,
    )

    supervisor, coordination_snapshot, record = run_supervised_request(
        orchestrator,
        coordination_snapshot,
        supervisor,
        request,
    )

    hardened_plan, evaluation = apply_policy_to_plan(
        record.execution_plan,
        agent_id=record.session.agent_id,
        file_path=record.session.file_path,
        action_type=request.action_type,
        target=request.target,
    )

    trace = build_decision_trace(
        session=record.session,
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        execution_plan=hardened_plan,
        policy_evaluation=evaluation,
        escalations=supervisor.escalations,
        metadata={"source": "manual-demo"},
    )

    print(json.dumps(trace.to_dict(), ensure_ascii=False, indent=2))
