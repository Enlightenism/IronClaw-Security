from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.orchestrator.decision_trace import DecisionTrace
from app.orchestrator.remediation_gate import GateReviewOutcome, RemediationGateReport
from app.orchestrator.replay_controller import ReplayReport
from app.orchestrator.supervisor import SupervisorEscalation


LedgerEventType = str


@dataclass(frozen=True)
class AuditLedgerEntry:
    entry_id: str
    timestamp: str
    event_type: LedgerEventType
    source: str
    target: str
    decision: str
    risk_score: int
    details: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""
    entry_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _stable_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_audit_entry(
    *,
    event_type: LedgerEventType,
    source: str,
    target: str,
    decision: str,
    risk_score: int,
    details: dict[str, Any] | None = None,
    previous_hash: str = "",
) -> AuditLedgerEntry:
    base_payload = {
        "entry_id": f"led-{uuid4().hex[:16]}",
        "timestamp": _utcnow(),
        "event_type": event_type,
        "source": source,
        "target": target,
        "decision": decision,
        "risk_score": risk_score,
        "details": details or {},
        "previous_hash": previous_hash,
    }
    entry_hash = _stable_hash(base_payload)
    return AuditLedgerEntry(**base_payload, entry_hash=entry_hash)


def append_audit_entry(
    output_path: str | Path,
    entry: AuditLedgerEntry,
) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
    return path


def load_audit_entries(input_path: str | Path) -> list[AuditLedgerEntry]:
    path = Path(input_path).expanduser().resolve()
    if not path.exists():
        return []

    entries: list[AuditLedgerEntry] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            entries.append(AuditLedgerEntry(**json.loads(line)))
    return entries


def verify_audit_chain(entries: list[AuditLedgerEntry]) -> dict[str, Any]:
    valid = True
    broken_index: int | None = None
    expected_previous = ""

    for index, entry in enumerate(entries):
        payload = {
            "entry_id": entry.entry_id,
            "timestamp": entry.timestamp,
            "event_type": entry.event_type,
            "source": entry.source,
            "target": entry.target,
            "decision": entry.decision,
            "risk_score": entry.risk_score,
            "details": entry.details,
            "previous_hash": entry.previous_hash,
        }
        recomputed_hash = _stable_hash(payload)

        if entry.previous_hash != expected_previous or entry.entry_hash != recomputed_hash:
            valid = False
            broken_index = index
            break

        expected_previous = entry.entry_hash

    return {
        "valid": valid,
        "entry_count": len(entries),
        "broken_index": broken_index,
        "last_hash": expected_previous if valid else None,
    }


def _last_hash(entries: list[AuditLedgerEntry]) -> str:
    return entries[-1].entry_hash if entries else ""


def record_decision_trace(
    existing_entries: list[AuditLedgerEntry],
    trace: DecisionTrace,
) -> AuditLedgerEntry:
    plan = trace.execution_plan
    return build_audit_entry(
        event_type="decision-trace",
        source=f"trace:{trace.trace_id}",
        target=trace.target,
        decision=plan.verdict,
        risk_score=plan.risk_score,
        details={
            "session_id": trace.session_id,
            "action_type": trace.action_type,
            "matched_patterns": getattr(plan, "matched_patterns", []),
        },
        previous_hash=_last_hash(existing_entries),
    )


def record_escalation(
    existing_entries: list[AuditLedgerEntry],
    escalation: SupervisorEscalation,
) -> AuditLedgerEntry:
    return build_audit_entry(
        event_type="supervisor-escalation",
        source=f"escalation:{escalation.escalation_id}",
        target=escalation.file_path,
        decision=escalation.verdict,
        risk_score=escalation.risk_score,
        details={
            "level": escalation.level,
            "reason": escalation.reason,
            "session_id": escalation.session_id,
            "agent_id": escalation.agent_id,
        },
        previous_hash=_last_hash(existing_entries),
    )


def record_gate_outcome(
    existing_entries: list[AuditLedgerEntry],
    outcome: GateReviewOutcome,
) -> AuditLedgerEntry:
    score = 0
    if outcome.decision == "reject":
        score = 100
    elif outcome.decision == "isolate":
        score = 70
    elif outcome.decision == "review":
        score = 50

    return build_audit_entry(
        event_type="remediation-outcome",
        source=f"gate-outcome:{outcome.outcome_id}",
        target=outcome.request_id,
        decision=outcome.decision,
        risk_score=score,
        details={
            "status": outcome.status,
            "action": outcome.action,
            "rationale": outcome.rationale,
        },
        previous_hash=_last_hash(existing_entries),
    )


def record_replay_report(
    existing_entries: list[AuditLedgerEntry],
    report: ReplayReport,
) -> AuditLedgerEntry:
    return build_audit_entry(
        event_type="replay-report",
        source=f"replay:{report.replay_id}",
        target=report.checkpoint_id,
        decision=report.status,
        risk_score=max(report.blocked_trace_count * 25, report.quarantined_trace_count * 15),
        details={
            "mode": report.mode,
            "replayed_trace_count": report.replayed_trace_count,
            "blocked_trace_count": report.blocked_trace_count,
            "quarantined_trace_count": report.quarantined_trace_count,
            "warning_trace_count": report.warning_trace_count,
            "allow_trace_count": report.allow_trace_count,
        },
        previous_hash=_last_hash(existing_entries),
    )


def record_gate_report(
    existing_entries: list[AuditLedgerEntry],
    report: RemediationGateReport,
) -> AuditLedgerEntry:
    risk_score = max(report.rejected_count * 25, report.quarantined_count * 20, report.manual_review_count * 10)
    return build_audit_entry(
        event_type="gate-report",
        source=f"gate:{report.gate_id}",
        target="remediation-gate",
        decision="completed",
        risk_score=risk_score,
        details={
            "request_count": report.request_count,
            "approved_count": report.approved_count,
            "rejected_count": report.rejected_count,
            "quarantined_count": report.quarantined_count,
            "manual_review_count": report.manual_review_count,
        },
        previous_hash=_last_hash(existing_entries),
    )


def summarize_audit_entries(entries: list[AuditLedgerEntry]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.event_type] = counts.get(entry.event_type, 0) + 1

    verification = verify_audit_chain(entries)

    return {
        "entry_count": len(entries),
        "event_type_counts": counts,
        "verification": verification,
    }


if __name__ == "__main__":
    sample_entries: list[AuditLedgerEntry] = []

    first = build_audit_entry(
        event_type="decision-trace",
        source="trace:demo-1",
        target="app/services/scanner.py",
        decision="block",
        risk_score=100,
        details={"reason": "Credential exposure attempt"},
        previous_hash=_last_hash(sample_entries),
    )
    sample_entries.append(first)

    second = build_audit_entry(
        event_type="remediation-outcome",
        source="gate-outcome:demo-1",
        target="req-demo-1",
        decision="reject",
        risk_score=100,
        details={"status": "closed", "action": "deny"},
        previous_hash=_last_hash(sample_entries),
    )
    sample_entries.append(second)

    print(json.dumps(summarize_audit_entries(sample_entries), ensure_ascii=False, indent=2))