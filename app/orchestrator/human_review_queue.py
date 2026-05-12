from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import uuid4

from app.orchestrator.decision_trace import DecisionTrace
from app.orchestrator.remediation_gate import GateReviewOutcome
from app.orchestrator.supervisor import SupervisorEscalation

ReviewPriority = Literal["low", "medium", "high", "critical"]
ReviewStatus = Literal["pending", "in_review", "approved", "rejected", "escalated", "expired"]
ReviewDecision = Literal["approve", "reject", "escalate", "defer"]


@dataclass
class ReviewPacket:
    packet_id: str
    source_type: str
    source_id: str
    target: str
    summary: str
    risk_score: int
    priority: ReviewPriority
    status: ReviewStatus
    assignee: str | None = None
    due_at: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewDecisionRecord:
    decision_id: str
    packet_id: str
    reviewer: str
    decision: ReviewDecision
    rationale: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewQueueSnapshot:
    queue_id: str
    packets: list[ReviewPacket] = field(default_factory=list)
    decisions: list[ReviewDecisionRecord] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "queue_id": self.queue_id,
            "packets": [packet.to_dict() for packet in self.packets],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def initialize_review_queue() -> ReviewQueueSnapshot:
    return ReviewQueueSnapshot(queue_id=f"rq-{uuid4().hex[:16]}")


def _priority_from_risk(risk_score: int) -> ReviewPriority:
    if risk_score >= 90:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def _default_due_at(priority: ReviewPriority) -> str:
    now = datetime.now(UTC)
    if priority == "critical":
        due = now + timedelta(minutes=15)
    elif priority == "high":
        due = now + timedelta(hours=1)
    elif priority == "medium":
        due = now + timedelta(hours=4)
    else:
        due = now + timedelta(days=1)
    return due.isoformat()


def _queue_sort_key(packet: ReviewPacket) -> tuple[int, int, str]:
    priority_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }
    status_order = {
        "pending": 0,
        "in_review": 1,
        "escalated": 2,
        "approved": 3,
        "rejected": 4,
        "expired": 5,
    }
    return (
        status_order.get(packet.status, 99),
        priority_order.get(packet.priority, 99),
        packet.created_at,
    )


def _normalize_packets(packets: list[ReviewPacket]) -> list[ReviewPacket]:
    return sorted(packets, key=_queue_sort_key)


def enqueue_escalation(
    queue: ReviewQueueSnapshot,
    escalation: SupervisorEscalation,
) -> tuple[ReviewQueueSnapshot, ReviewPacket]:
    packet = ReviewPacket(
        packet_id=f"pkt-{uuid4().hex[:12]}",
        source_type="supervisor_escalation",
        source_id=escalation.escalation_id,
        target=escalation.file_path,
        summary=escalation.reason,
        risk_score=escalation.risk_score,
        priority=_priority_from_risk(escalation.risk_score),
        status="pending",
        due_at=_default_due_at(_priority_from_risk(escalation.risk_score)),
        metadata={
            "session_id": escalation.session_id,
            "agent_id": escalation.agent_id,
            "level": escalation.level,
            "verdict": escalation.verdict,
        },
    )

    updated_packets = _normalize_packets([*queue.packets, packet])
    updated_queue = ReviewQueueSnapshot(
        queue_id=queue.queue_id,
        packets=updated_packets,
        decisions=queue.decisions,
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )
    return updated_queue, packet


def enqueue_trace_review(
    queue: ReviewQueueSnapshot,
    trace: DecisionTrace,
) -> tuple[ReviewQueueSnapshot, ReviewPacket]:
    plan = trace.execution_plan
    packet = ReviewPacket(
        packet_id=f"pkt-{uuid4().hex[:12]}",
        source_type="decision_trace",
        source_id=trace.trace_id,
        target=trace.target,
        summary=f"Trace review requested for {trace.action_type} with verdict {plan.verdict}.",
        risk_score=plan.risk_score,
        priority=_priority_from_risk(plan.risk_score),
        status="pending",
        due_at=_default_due_at(_priority_from_risk(plan.risk_score)),
        metadata={
            "session_id": trace.session_id,
            "action_type": trace.action_type,
            "verdict": plan.verdict,
            "matched_patterns": getattr(plan, "matched_patterns", []),
        },
    )

    updated_packets = _normalize_packets([*queue.packets, packet])
    updated_queue = ReviewQueueSnapshot(
        queue_id=queue.queue_id,
        packets=updated_packets,
        decisions=queue.decisions,
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )
    return updated_queue, packet


def assign_packet(
    queue: ReviewQueueSnapshot,
    *,
    packet_id: str,
    reviewer: str,
) -> ReviewQueueSnapshot:
    updated_packets: list[ReviewPacket] = []
    for packet in queue.packets:
        if packet.packet_id == packet_id:
            updated_packets.append(
                ReviewPacket(
                    packet_id=packet.packet_id,
                    source_type=packet.source_type,
                    source_id=packet.source_id,
                    target=packet.target,
                    summary=packet.summary,
                    risk_score=packet.risk_score,
                    priority=packet.priority,
                    status="in_review" if packet.status == "pending" else packet.status,
                    assignee=reviewer,
                    due_at=packet.due_at,
                    created_at=packet.created_at,
                    updated_at=datetime.now(UTC).isoformat(),
                    metadata=packet.metadata,
                )
            )
        else:
            updated_packets.append(packet)

    return ReviewQueueSnapshot(
        queue_id=queue.queue_id,
        packets=_normalize_packets(updated_packets),
        decisions=queue.decisions,
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )


def apply_review_decision(
    queue: ReviewQueueSnapshot,
    *,
    packet_id: str,
    reviewer: str,
    decision: ReviewDecision,
    rationale: str,
) -> tuple[ReviewQueueSnapshot, ReviewDecisionRecord]:
    status_map: dict[ReviewDecision, ReviewStatus] = {
        "approve": "approved",
        "reject": "rejected",
        "escalate": "escalated",
        "defer": "pending",
    }

    updated_packets: list[ReviewPacket] = []
    matched_packet: ReviewPacket | None = None

    for packet in queue.packets:
        if packet.packet_id == packet_id:
            matched_packet = packet
            updated_packets.append(
                ReviewPacket(
                    packet_id=packet.packet_id,
                    source_type=packet.source_type,
                    source_id=packet.source_id,
                    target=packet.target,
                    summary=packet.summary,
                    risk_score=packet.risk_score,
                    priority=packet.priority,
                    status=status_map[decision],
                    assignee=reviewer,
                    due_at=packet.due_at,
                    created_at=packet.created_at,
                    updated_at=datetime.now(UTC).isoformat(),
                    metadata={
                        **packet.metadata,
                        "last_decision": decision,
                        "last_rationale": rationale,
                    },
                )
            )
        else:
            updated_packets.append(packet)

    if matched_packet is None:
        raise ValueError(f"Packet not found: {packet_id}")

    record = ReviewDecisionRecord(
        decision_id=f"rdec-{uuid4().hex[:12]}",
        packet_id=packet_id,
        reviewer=reviewer,
        decision=decision,
        rationale=rationale,
    )

    updated_queue = ReviewQueueSnapshot(
        queue_id=queue.queue_id,
        packets=_normalize_packets(updated_packets),
        decisions=[*queue.decisions, record],
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )
    return updated_queue, record


def expire_overdue_packets(queue: ReviewQueueSnapshot, *, now: str | None = None) -> ReviewQueueSnapshot:
    reference = datetime.fromisoformat(now) if now else datetime.now(UTC)
    updated_packets: list[ReviewPacket] = []

    for packet in queue.packets:
        if (
            packet.status in {"pending", "in_review"}
            and packet.due_at is not None
            and datetime.fromisoformat(packet.due_at) < reference
        ):
            updated_packets.append(
                ReviewPacket(
                    packet_id=packet.packet_id,
                    source_type=packet.source_type,
                    source_id=packet.source_id,
                    target=packet.target,
                    summary=packet.summary,
                    risk_score=packet.risk_score,
                    priority=packet.priority,
                    status="expired",
                    assignee=packet.assignee,
                    due_at=packet.due_at,
                    created_at=packet.created_at,
                    updated_at=datetime.now(UTC).isoformat(),
                    metadata=packet.metadata,
                )
            )
        else:
            updated_packets.append(packet)

    return ReviewQueueSnapshot(
        queue_id=queue.queue_id,
        packets=_normalize_packets(updated_packets),
        decisions=queue.decisions,
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )


def ingest_gate_outcome(
    queue: ReviewQueueSnapshot,
    outcome: GateReviewOutcome,
) -> ReviewQueueSnapshot:
    status_by_decision: dict[str, ReviewStatus] = {
        "approve": "approved",
        "reject": "rejected",
        "escalate": "escalated",
        "review": "in_review",
        "isolate": "escalated",
    }

    updated_packets: list[ReviewPacket] = []
    for packet in queue.packets:
        if packet.source_id == outcome.outcome_id or packet.metadata.get("request_id") == outcome.request_id:
            updated_packets.append(
                ReviewPacket(
                    packet_id=packet.packet_id,
                    source_type=packet.source_type,
                    source_id=packet.source_id,
                    target=packet.target,
                    summary=packet.summary,
                    risk_score=packet.risk_score,
                    priority=packet.priority,
                    status=status_by_decision.get(outcome.decision, packet.status),
                    assignee=packet.assignee,
                    due_at=packet.due_at,
                    created_at=packet.created_at,
                    updated_at=datetime.now(UTC).isoformat(),
                    metadata={
                        **packet.metadata,
                        "gate_outcome_id": outcome.outcome_id,
                        "gate_decision": outcome.decision,
                        "gate_status": outcome.status,
                    },
                )
            )
        else:
            updated_packets.append(packet)

    return ReviewQueueSnapshot(
        queue_id=queue.queue_id,
        packets=_normalize_packets(updated_packets),
        decisions=queue.decisions,
        created_at=queue.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )


def summarize_review_queue(queue: ReviewQueueSnapshot) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    priority_counts: dict[str, int] = {}

    for packet in queue.packets:
        status_counts[packet.status] = status_counts.get(packet.status, 0) + 1
        priority_counts[packet.priority] = priority_counts.get(packet.priority, 0) + 1

    return {
        "queue_id": queue.queue_id,
        "packet_count": len(queue.packets),
        "decision_count": len(queue.decisions),
        "status_counts": status_counts,
        "priority_counts": priority_counts,
        "assigned_count": sum(1 for packet in queue.packets if packet.assignee),
        "pending_count": status_counts.get("pending", 0),
        "expired_count": status_counts.get("expired", 0),
    }


if __name__ == "__main__":
    queue = initialize_review_queue()
    print(queue.to_dict())