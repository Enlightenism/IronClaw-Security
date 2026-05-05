from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.orchestrator.case_file import CaseFile
from app.orchestrator.human_review_queue import ReviewDecisionRecord
from app.orchestrator.remediation_gate import GateReviewOutcome
from app.orchestrator.supervisor import SupervisorEscalation


PlaybookStatus = str
PlaybookTrigger = str
ActionKind = str


@dataclass
class PlaybookAction:
    action_id: str
    kind: ActionKind
    label: str
    status: str
    summary: str
    automated: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookExecution:
    execution_id: str
    playbook_name: str
    trigger: PlaybookTrigger
    case_id: str
    target: str
    status: PlaybookStatus
    started_at: str
    updated_at: str
    rationale: str
    actions: list[PlaybookAction] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "playbook_name": self.playbook_name,
            "trigger": self.trigger,
            "case_id": self.case_id,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "rationale": self.rationale,
            "actions": [action.to_dict() for action in self.actions],
            "tags": self.tags,
        }


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _make_action(
    *,
    kind: ActionKind,
    label: str,
    status: str,
    summary: str,
    automated: bool = True,
    metadata: dict[str, Any] | None = None,
) -> PlaybookAction:
    return PlaybookAction(
        action_id=f"act-{uuid4().hex[:12]}",
        kind=kind,
        label=label,
        status=status,
        summary=summary,
        automated=automated,
        metadata=metadata or {},
    )


def _base_execution(
    *,
    playbook_name: str,
    trigger: PlaybookTrigger,
    case_file: CaseFile,
    rationale: str,
    tags: list[str] | None = None,
) -> PlaybookExecution:
    now = _utcnow()
    return PlaybookExecution(
        execution_id=f"pbx-{uuid4().hex[:16]}",
        playbook_name=playbook_name,
        trigger=trigger,
        case_id=case_file.case_id,
        target=case_file.target,
        status="running",
        started_at=now,
        updated_at=now,
        rationale=rationale,
        actions=[],
        tags=tags or [],
    )


def _finalize_execution(
    execution: PlaybookExecution,
    *,
    actions: list[PlaybookAction],
    status: PlaybookStatus,
) -> PlaybookExecution:
    return PlaybookExecution(
        execution_id=execution.execution_id,
        playbook_name=execution.playbook_name,
        trigger=execution.trigger,
        case_id=execution.case_id,
        target=execution.target,
        status=status,
        started_at=execution.started_at,
        updated_at=_utcnow(),
        rationale=execution.rationale,
        actions=actions,
        tags=execution.tags,
    )


def _review_decision_actions(case_file: CaseFile, decision: ReviewDecisionRecord) -> list[PlaybookAction]:
    if decision.decision == "approve":
        return [
            _make_action(
                kind="release_target",
                label="Release target",
                status="completed",
                summary=f"Approved item for target {case_file.target} released from controlled review.",
                metadata={"reviewer": decision.reviewer, "decision_id": decision.decision_id},
            ),
            _make_action(
                kind="record_audit_note",
                label="Record audit note",
                status="completed",
                summary="Approval recorded for downstream audit and reporting.",
                metadata={"packet_id": decision.packet_id},
            ),
        ]

    if decision.decision == "reject":
        return [
            _make_action(
                kind="deny_target",
                label="Deny target",
                status="completed",
                summary=f"Rejected item for target {case_file.target} remains blocked or quarantined.",
                metadata={"reviewer": decision.reviewer, "decision_id": decision.decision_id},
            ),
            _make_action(
                kind="preserve_evidence",
                label="Preserve evidence",
                status="completed",
                summary="Evidence preserved for later forensic review.",
                metadata={"case_id": case_file.case_id},
            ),
        ]

    if decision.decision == "escalate":
        return [
            _make_action(
                kind="notify_supervisor",
                label="Notify supervisor",
                status="completed",
                summary="Supervisor escalation requested from human review decision.",
                automated=False,
                metadata={"reviewer": decision.reviewer},
            ),
            _make_action(
                kind="hold_execution",
                label="Hold execution",
                status="completed",
                summary="Execution remains paused pending elevated review.",
            ),
        ]

    return [
        _make_action(
            kind="defer_case",
            label="Defer case",
            status="completed",
            summary="Decision deferred and case kept open for additional context.",
            automated=False,
            metadata={"reviewer": decision.reviewer},
        )
    ]


def run_review_decision_playbook(
    case_file: CaseFile,
    decision: ReviewDecisionRecord,
) -> PlaybookExecution:
    execution = _base_execution(
        playbook_name="human-review-resolution",
        trigger="review_decision",
        case_file=case_file,
        rationale=f"Apply post-review handling for decision {decision.decision}.",
        tags=["review", decision.decision, case_file.severity],
    )
    actions = _review_decision_actions(case_file, decision)
    final_status = "completed" if decision.decision != "escalate" else "awaiting_manual_action"
    return _finalize_execution(execution, actions=actions, status=final_status)


def _gate_outcome_actions(case_file: CaseFile, outcome: GateReviewOutcome) -> list[PlaybookAction]:
    decision = outcome.decision

    if decision == "approve":
        return [
            _make_action(
                kind="commit_remediation",
                label="Commit remediation",
                status="completed",
                summary="Approved remediation path marked ready for execution.",
                metadata={"request_id": outcome.request_id, "action": outcome.action},
            ),
            _make_action(
                kind="notify_case_owner",
                label="Notify case owner",
                status="completed",
                summary="Case owner notified that remediation was approved.",
            ),
        ]

    if decision == "reject":
        return [
            _make_action(
                kind="rollback_or_block",
                label="Rollback or block",
                status="completed",
                summary="Rejected remediation path blocked from execution.",
                metadata={"request_id": outcome.request_id},
            ),
            _make_action(
                kind="raise_followup_task",
                label="Raise follow-up task",
                status="completed",
                summary="Follow-up work item created for safer alternative handling.",
                automated=False,
            ),
        ]

    if decision == "isolate":
        return [
            _make_action(
                kind="isolate_target",
                label="Isolate target",
                status="completed",
                summary=f"Target {case_file.target} marked for isolation workflow.",
                metadata={"action": outcome.action},
            ),
            _make_action(
                kind="preserve_case_state",
                label="Preserve case state",
                status="completed",
                summary="Case state preserved before isolation changes propagate.",
            ),
        ]

    if decision == "escalate":
        return [
            _make_action(
                kind="notify_incident_commander",
                label="Notify incident commander",
                status="completed",
                summary="Escalated gate outcome forwarded for higher-level review.",
                automated=False,
            ),
            _make_action(
                kind="freeze_automation",
                label="Freeze automation",
                status="completed",
                summary="Automated remediation paused until manual authorization is granted.",
            ),
        ]

    return [
        _make_action(
            kind="queue_manual_review",
            label="Queue manual review",
            status="completed",
            summary="Outcome requires further analyst validation before action.",
            automated=False,
        )
    ]


def run_gate_outcome_playbook(
    case_file: CaseFile,
    outcome: GateReviewOutcome,
) -> PlaybookExecution:
    execution = _base_execution(
        playbook_name="remediation-gate-resolution",
        trigger="gate_outcome",
        case_file=case_file,
        rationale=f"Apply response steps for gate decision {outcome.decision}.",
        tags=["gate", outcome.decision, case_file.status],
    )
    actions = _gate_outcome_actions(case_file, outcome)
    final_status = "awaiting_manual_action" if outcome.decision in {"escalate", "review"} else "completed"
    return _finalize_execution(execution, actions=actions, status=final_status)


def run_supervisor_escalation_playbook(
    case_file: CaseFile,
    escalation: SupervisorEscalation,
) -> PlaybookExecution:
    execution = _base_execution(
        playbook_name="supervisor-escalation-response",
        trigger="supervisor_escalation",
        case_file=case_file,
        rationale=f"Escalation level {escalation.level} requires coordinated response handling.",
        tags=["supervisor", escalation.level, escalation.verdict],
    )

    actions = [
        _make_action(
            kind="freeze_related_execution",
            label="Freeze related execution",
            status="completed",
            summary=f"Execution for session {escalation.session_id} frozen pending review.",
            metadata={"agent_id": escalation.agent_id},
        ),
        _make_action(
            kind="open_priority_investigation",
            label="Open priority investigation",
            status="completed",
            summary="Priority investigation path opened from supervisor escalation.",
            automated=False,
            metadata={"escalation_id": escalation.escalation_id},
        ),
    ]

    if escalation.level in {"high", "critical"}:
        actions.append(
            _make_action(
                kind="notify_security_lead",
                label="Notify security lead",
                status="completed",
                summary="Security lead notified due to elevated escalation severity.",
                automated=False,
                metadata={"risk_score": escalation.risk_score},
            )
        )

    return _finalize_execution(execution, actions=actions, status="awaiting_manual_action")


def select_playbook_for_case(
    case_file: CaseFile,
    *,
    review_decision: ReviewDecisionRecord | None = None,
    gate_outcome: GateReviewOutcome | None = None,
    supervisor_escalation: SupervisorEscalation | None = None,
) -> PlaybookExecution:
    provided = [
        review_decision is not None,
        gate_outcome is not None,
        supervisor_escalation is not None,
    ]
    if sum(provided) != 1:
        raise ValueError("Provide exactly one trigger object to select a playbook.")

    if review_decision is not None:
        return run_review_decision_playbook(case_file, review_decision)
    if gate_outcome is not None:
        return run_gate_outcome_playbook(case_file, gate_outcome)
    return run_supervisor_escalation_playbook(case_file, supervisor_escalation)  # type: ignore[arg-type]


def summarize_playbook_execution(execution: PlaybookExecution) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for action in execution.actions:
        counts[action.kind] = counts.get(action.kind, 0) + 1

    return {
        "execution_id": execution.execution_id,
        "playbook_name": execution.playbook_name,
        "trigger": execution.trigger,
        "status": execution.status,
        "action_count": len(execution.actions),
        "action_kind_counts": counts,
        "tags": execution.tags,
    }


if __name__ == "__main__":
    demo_case = CaseFile(
        case_id="case-demo",
        title="High-risk prompt review",
        target="prompt://inbound",
        status="escalated",
        severity="high",
        risk_score=85,
        created_at=_utcnow(),
        updated_at=_utcnow(),
        summary="High-risk prompt content requires controlled handling.",
    )

    demo_execution = run_supervisor_escalation_playbook(
        demo_case,
        SupervisorEscalation(
            escalation_id="esc-demo",
            session_id="sess-demo",
            agent_id="agent-supervisor",
            file_path="prompts/inbound.txt",
            level="high",
            reason="Escalated heuristic prompt-injection risk requires review.",
            verdict="quarantine",
            risk_score=85,
        ),
    )

    print(demo_execution.to_dict())