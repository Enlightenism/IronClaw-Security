from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.orchestrator.audit_ledger import AuditLedgerEntry
from app.orchestrator.decision_trace import DecisionTrace
from app.orchestrator.human_review_queue import ReviewDecisionRecord, ReviewPacket
from app.orchestrator.remediation_gate import GateReviewOutcome
from app.orchestrator.supervisor import SupervisorEscalation

CaseStatus = str
EvidenceKind = str


@dataclass
class EvidenceItem:
    evidence_id: str
    kind: EvidenceKind
    source_id: str
    title: str
    summary: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseTimelineEvent:
    event_id: str
    event_type: str
    timestamp: str
    actor: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseFile:
    case_id: str
    title: str
    target: str
    status: CaseStatus
    severity: str
    risk_score: int
    created_at: str
    updated_at: str
    summary: str
    source_packet_id: str | None = None
    owner: str | None = None
    evidence: list[EvidenceItem] = field(default_factory=list)
    timeline: list[CaseTimelineEvent] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    related_ids: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "target": self.target,
            "status": self.status,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "summary": self.summary,
            "source_packet_id": self.source_packet_id,
            "owner": self.owner,
            "evidence": [item.to_dict() for item in self.evidence],
            "timeline": [item.to_dict() for item in self.timeline],
            "tags": self.tags,
            "related_ids": self.related_ids,
        }


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _severity_from_risk(risk_score: int) -> str:
    if risk_score >= 90:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def _timeline_event(
    *,
    event_type: str,
    actor: str,
    summary: str,
    timestamp: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CaseTimelineEvent:
    return CaseTimelineEvent(
        event_id=f"cte-{uuid4().hex[:12]}",
        event_type=event_type,
        timestamp=timestamp or _utcnow(),
        actor=actor,
        summary=summary,
        metadata=metadata or {},
    )


def _evidence_item(
    *,
    kind: EvidenceKind,
    source_id: str,
    title: str,
    summary: str,
    metadata: dict[str, Any] | None = None,
) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=f"evd-{uuid4().hex[:12]}",
        kind=kind,
        source_id=source_id,
        title=title,
        summary=summary,
        metadata=metadata or {},
    )


def create_case_file_from_packet(packet: ReviewPacket) -> CaseFile:
    now = _utcnow()
    severity = _severity_from_risk(packet.risk_score)

    evidence = [
        _evidence_item(
            kind="review_packet",
            source_id=packet.packet_id,
            title=f"Review packet for {packet.target}",
            summary=packet.summary,
            metadata={
                "priority": packet.priority,
                "status": packet.status,
                "assignee": packet.assignee,
                "due_at": packet.due_at,
                **packet.metadata,
            },
        ),
    ]

    timeline = [
        _timeline_event(
            event_type="case_created",
            actor="system",
            summary=f"Case opened from review packet {packet.packet_id}.",
            timestamp=packet.created_at,
            metadata={"source_type": packet.source_type},
        ),
    ]

    return CaseFile(
        case_id=f"case-{uuid4().hex[:16]}",
        title=f"{severity.upper()} review for {packet.target}",
        target=packet.target,
        status="open",
        severity=severity,
        risk_score=packet.risk_score,
        created_at=now,
        updated_at=now,
        summary=packet.summary,
        source_packet_id=packet.packet_id,
        owner=packet.assignee,
        evidence=evidence,
        timeline=timeline,
        tags=[packet.source_type, severity],
        related_ids={"packet_id": packet.packet_id, "source_id": packet.source_id},
    )


def attach_decision_trace(case_file: CaseFile, trace: DecisionTrace) -> CaseFile:
    plan = trace.execution_plan
    evidence = [
        *case_file.evidence,
        _evidence_item(
            kind="decision_trace",
            source_id=trace.trace_id,
            title=f"Decision trace {trace.trace_id}",
            summary=f"{trace.action_type} on {trace.target} produced verdict {plan.verdict}.",
            metadata={
                "session_id": trace.session_id,
                "action_type": trace.action_type,
                "verdict": plan.verdict,
                "risk_score": plan.risk_score,
                "matched_patterns": getattr(plan, "matched_patterns", []),
            },
        ),
    ]
    timeline = [
        *case_file.timeline,
        _timeline_event(
            event_type="decision_trace_attached",
            actor="system",
            summary=f"Attached decision trace {trace.trace_id}.",
            metadata={"verdict": plan.verdict, "risk_score": plan.risk_score},
        ),
    ]

    return CaseFile(
        case_id=case_file.case_id,
        title=case_file.title,
        target=case_file.target,
        status=case_file.status,
        severity=max(
            case_file.severity,
            _severity_from_risk(plan.risk_score),
            key=lambda s: ["low", "medium", "high", "critical"].index(s),
        ),
        risk_score=max(case_file.risk_score, plan.risk_score),
        created_at=case_file.created_at,
        updated_at=_utcnow(),
        summary=case_file.summary,
        source_packet_id=case_file.source_packet_id,
        owner=case_file.owner,
        evidence=evidence,
        timeline=timeline,
        tags=sorted(set([*case_file.tags, trace.action_type, plan.verdict])),
        related_ids={**case_file.related_ids, "trace_id": trace.trace_id},
    )


def attach_escalation(case_file: CaseFile, escalation: SupervisorEscalation) -> CaseFile:
    evidence = [
        *case_file.evidence,
        _evidence_item(
            kind="supervisor_escalation",
            source_id=escalation.escalation_id,
            title=f"Supervisor escalation {escalation.level}",
            summary=escalation.reason,
            metadata={
                "session_id": escalation.session_id,
                "agent_id": escalation.agent_id,
                "verdict": escalation.verdict,
                "risk_score": escalation.risk_score,
            },
        ),
    ]
    timeline = [
        *case_file.timeline,
        _timeline_event(
            event_type="escalation_attached",
            actor="supervisor",
            summary=f"Supervisor escalation {escalation.escalation_id} attached.",
            metadata={"level": escalation.level, "verdict": escalation.verdict},
        ),
    ]

    return CaseFile(
        case_id=case_file.case_id,
        title=case_file.title,
        target=case_file.target,
        status="escalated" if escalation.level in {"high", "critical"} else case_file.status,
        severity=max(
            case_file.severity,
            _severity_from_risk(escalation.risk_score),
            key=lambda s: ["low", "medium", "high", "critical"].index(s),
        ),
        risk_score=max(case_file.risk_score, escalation.risk_score),
        created_at=case_file.created_at,
        updated_at=_utcnow(),
        summary=case_file.summary,
        source_packet_id=case_file.source_packet_id,
        owner=case_file.owner,
        evidence=evidence,
        timeline=timeline,
        tags=sorted(set([*case_file.tags, "escalation", escalation.level])),
        related_ids={**case_file.related_ids, "escalation_id": escalation.escalation_id},
    )


def attach_gate_outcome(case_file: CaseFile, outcome: GateReviewOutcome) -> CaseFile:
    evidence = [
        *case_file.evidence,
        _evidence_item(
            kind="gate_outcome",
            source_id=outcome.outcome_id,
            title=f"Gate outcome {outcome.decision}",
            summary=outcome.rationale,
            metadata={
                "request_id": outcome.request_id,
                "decision": outcome.decision,
                "status": outcome.status,
                "action": outcome.action,
            },
        ),
    ]

    status_map = {
        "approve": "approved",
        "reject": "rejected",
        "review": "in_review",
        "escalate": "escalated",
        "isolate": "isolated",
    }

    timeline = [
        *case_file.timeline,
        _timeline_event(
            event_type="gate_outcome_attached",
            actor="remediation_gate",
            summary=f"Gate outcome {outcome.decision} recorded for request {outcome.request_id}.",
            metadata={"status": outcome.status, "action": outcome.action},
        ),
    ]

    return CaseFile(
        case_id=case_file.case_id,
        title=case_file.title,
        target=case_file.target,
        status=status_map.get(outcome.decision, case_file.status),
        severity=case_file.severity,
        risk_score=case_file.risk_score,
        created_at=case_file.created_at,
        updated_at=_utcnow(),
        summary=case_file.summary,
        source_packet_id=case_file.source_packet_id,
        owner=case_file.owner,
        evidence=evidence,
        timeline=timeline,
        tags=sorted(set([*case_file.tags, outcome.decision])),
        related_ids={**case_file.related_ids, "gate_outcome_id": outcome.outcome_id},
    )


def attach_review_decision(case_file: CaseFile, decision: ReviewDecisionRecord) -> CaseFile:
    evidence = [
        *case_file.evidence,
        _evidence_item(
            kind="review_decision",
            source_id=decision.decision_id,
            title=f"Review decision {decision.decision}",
            summary=decision.rationale,
            metadata={"reviewer": decision.reviewer, "packet_id": decision.packet_id},
        ),
    ]

    status_map = {
        "approve": "approved",
        "reject": "rejected",
        "escalate": "escalated",
        "defer": "open",
    }

    timeline = [
        *case_file.timeline,
        _timeline_event(
            event_type="review_decision_attached",
            actor=decision.reviewer,
            summary=f"Reviewer recorded decision {decision.decision}.",
            timestamp=decision.created_at,
            metadata={"decision_id": decision.decision_id},
        ),
    ]

    return CaseFile(
        case_id=case_file.case_id,
        title=case_file.title,
        target=case_file.target,
        status=status_map.get(decision.decision, case_file.status),
        severity=case_file.severity,
        risk_score=case_file.risk_score,
        created_at=case_file.created_at,
        updated_at=_utcnow(),
        summary=case_file.summary,
        source_packet_id=case_file.source_packet_id,
        owner=decision.reviewer,
        evidence=evidence,
        timeline=timeline,
        tags=sorted(set([*case_file.tags, decision.decision])),
        related_ids={**case_file.related_ids, "decision_id": decision.decision_id},
    )


def attach_audit_entries(case_file: CaseFile, entries: list[AuditLedgerEntry]) -> CaseFile:
    relevant_entries = [entry for entry in entries if entry.target == case_file.target or entry.source in case_file.related_ids.values() or entry.target in case_file.related_ids.values()]

    added_evidence = [
        _evidence_item(
            kind="audit_entry",
            source_id=entry.entry_id,
            title=f"Audit entry {entry.event_type}",
            summary=f"{entry.decision} decision with risk score {entry.risk_score}.",
            metadata={
                "event_type": entry.event_type,
                "timestamp": entry.timestamp,
                "target": entry.target,
                "details": entry.details,
            },
        )
        for entry in relevant_entries
    ]

    if not added_evidence:
        return case_file

    timeline = [
        *case_file.timeline,
        _timeline_event(
            event_type="audit_entries_attached",
            actor="audit_ledger",
            summary=f"Attached {len(added_evidence)} audit entries.",
            metadata={"entry_count": len(added_evidence)},
        ),
    ]

    return CaseFile(
        case_id=case_file.case_id,
        title=case_file.title,
        target=case_file.target,
        status=case_file.status,
        severity=case_file.severity,
        risk_score=case_file.risk_score,
        created_at=case_file.created_at,
        updated_at=_utcnow(),
        summary=case_file.summary,
        source_packet_id=case_file.source_packet_id,
        owner=case_file.owner,
        evidence=[*case_file.evidence, *added_evidence],
        timeline=timeline,
        tags=case_file.tags,
        related_ids=case_file.related_ids,
    )


def summarize_case_file(case_file: CaseFile) -> dict[str, Any]:
    evidence_counts: dict[str, int] = {}
    for item in case_file.evidence:
        evidence_counts[item.kind] = evidence_counts.get(item.kind, 0) + 1

    return {
        "case_id": case_file.case_id,
        "status": case_file.status,
        "severity": case_file.severity,
        "risk_score": case_file.risk_score,
        "owner": case_file.owner,
        "evidence_count": len(case_file.evidence),
        "timeline_count": len(case_file.timeline),
        "evidence_counts": evidence_counts,
        "related_ids": case_file.related_ids,
    }


if __name__ == "__main__":
    packet = ReviewPacket(
        packet_id="pkt-demo",
        source_type="decision_trace",
        source_id="trace-demo",
        target="app/services/scanner.py",
        summary="Potential prompt-injection attempt requires investigation.",
        risk_score=85,
        priority="high",
        status="pending",
    )
    case_file = create_case_file_from_packet(packet)
    print(case_file.to_dict())
