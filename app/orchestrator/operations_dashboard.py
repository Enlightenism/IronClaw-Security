from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.orchestrator.audit_ledger import AuditLedgerEntry, summarize_audit_entries
from app.orchestrator.checkpoint_store import CheckpointBundle
from app.orchestrator.remediation_gate import RemediationGateReport
from app.orchestrator.replay_controller import ReplayReport
from app.orchestrator.supervisor import SupervisorSnapshot, summarize_supervisor

DashboardStatus = str


@dataclass
class MetricCard:
    key: str
    label: str
    value: int | float | str
    tone: str = "neutral"
    hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DashboardSection:
    section_id: str
    title: str
    metrics: list[MetricCard] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "title": self.title,
            "metrics": [metric.to_dict() for metric in self.metrics],
            "rows": self.rows,
        }


@dataclass
class OperationsDashboardSnapshot:
    dashboard_id: str
    status: DashboardStatus
    generated_at: str
    sections: list[DashboardSection] = field(default_factory=list)
    headline_metrics: list[MetricCard] = field(default_factory=list)
    health_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dashboard_id": self.dashboard_id,
            "status": self.status,
            "generated_at": self.generated_at,
            "sections": [section.to_dict() for section in self.sections],
            "headline_metrics": [metric.to_dict() for metric in self.headline_metrics],
            "health_summary": self.health_summary,
        }


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _checkpoint_status_counts(checkpoints: list[CheckpointBundle]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for checkpoint in checkpoints:
        status = checkpoint.manifest.status
        counts[status] = counts.get(status, 0) + 1
    return counts


def _checkpoint_rows(checkpoints: list[CheckpointBundle]) -> list[dict[str, Any]]:
    recent = sorted(checkpoints, key=lambda item: item.manifest.created_at, reverse=True)[:10]
    return [
        {
            "checkpoint_id": checkpoint.manifest.checkpoint_id,
            "label": checkpoint.manifest.label,
            "status": checkpoint.manifest.status,
            "session_count": checkpoint.manifest.session_count,
            "trace_count": checkpoint.manifest.trace_count,
            "created_at": checkpoint.manifest.created_at,
        }
        for checkpoint in recent
    ]


def _replay_section(replay_reports: list[ReplayReport]) -> DashboardSection:
    latest = replay_reports[-1] if replay_reports else None
    aggregate = {
        "replayed": sum(item.replayed_trace_count for item in replay_reports),
        "blocked": sum(item.blocked_trace_count for item in replay_reports),
        "quarantined": sum(item.quarantined_trace_count for item in replay_reports),
        "warnings": sum(item.warning_trace_count for item in replay_reports),
        "allowed": sum(item.allow_trace_count for item in replay_reports),
    }

    rows = [
        {
            "replay_id": item.replay_id,
            "checkpoint_id": item.checkpoint_id,
            "mode": item.mode,
            "status": item.status,
            "replayed_trace_count": item.replayed_trace_count,
            "blocked_trace_count": item.blocked_trace_count,
            "quarantined_trace_count": item.quarantined_trace_count,
            "created_at": item.created_at,
        }
        for item in replay_reports[-10:]
    ]

    return DashboardSection(
        section_id="replay-activity",
        title="Replay Activity",
        metrics=[
            MetricCard("replay-total", "Replay traces", aggregate["replayed"], "neutral"),
            MetricCard("replay-blocked", "Replay blocked", aggregate["blocked"], "critical"),
            MetricCard("replay-quarantined", "Replay quarantined", aggregate["quarantined"], "warning"),
            MetricCard(
                "replay-latest-status",
                "Latest replay status",
                latest.status if latest else "none",
                "neutral",
            ),
        ],
        rows=rows,
    )


def _gate_section(gate_reports: list[RemediationGateReport]) -> DashboardSection:
    latest = gate_reports[-1] if gate_reports else None
    totals = {
        "requests": sum(item.request_count for item in gate_reports),
        "approved": sum(item.approved_count for item in gate_reports),
        "rejected": sum(item.rejected_count for item in gate_reports),
        "quarantined": sum(item.quarantined_count for item in gate_reports),
        "manual_review": sum(item.manual_review_count for item in gate_reports),
    }

    rows = [
        {
            "gate_id": item.gate_id,
            "request_count": item.request_count,
            "approved_count": item.approved_count,
            "rejected_count": item.rejected_count,
            "quarantined_count": item.quarantined_count,
            "manual_review_count": item.manual_review_count,
            "generated_at": item.generated_at,
        }
        for item in gate_reports[-10:]
    ]

    return DashboardSection(
        section_id="remediation-gate",
        title="Remediation Gate",
        metrics=[
            MetricCard("gate-requests", "Gate requests", totals["requests"], "neutral"),
            MetricCard("gate-approved", "Approved", totals["approved"], "success"),
            MetricCard("gate-rejected", "Rejected", totals["rejected"], "critical"),
            MetricCard("gate-manual", "Manual review", totals["manual_review"], "warning"),
            MetricCard(
                "gate-latest",
                "Latest gate",
                latest.gate_id if latest else "none",
                "neutral",
            ),
        ],
        rows=rows,
    )


def _checkpoint_section(checkpoints: list[CheckpointBundle]) -> DashboardSection:
    counts = _checkpoint_status_counts(checkpoints)
    return DashboardSection(
        section_id="checkpoints",
        title="Checkpoint State",
        metrics=[
            MetricCard("checkpoints-total", "Total checkpoints", len(checkpoints), "neutral"),
            MetricCard("checkpoints-open", "Open", counts.get("open", 0), "warning"),
            MetricCard("checkpoints-closed", "Closed", counts.get("closed", 0), "success"),
            MetricCard("checkpoints-created", "Created", counts.get("created", 0), "neutral"),
        ],
        rows=_checkpoint_rows(checkpoints),
    )


def _audit_section(entries: list[AuditLedgerEntry]) -> DashboardSection:
    summary = summarize_audit_entries(entries)
    verification = summary.get("verification", {})
    return DashboardSection(
        section_id="audit-ledger",
        title="Audit Ledger",
        metrics=[
            MetricCard("audit-total", "Ledger entries", summary.get("entry_count", 0), "neutral"),
            MetricCard(
                "audit-valid",
                "Chain valid",
                "yes" if verification.get("valid") else "no",
                "success" if verification.get("valid") else "critical",
            ),
            MetricCard(
                "audit-broken-index",
                "Broken index",
                verification.get("broken_index") if verification.get("broken_index") is not None else "-",
                "neutral",
            ),
        ],
        rows=[
            {
                "event_type": entry.event_type,
                "decision": entry.decision,
                "risk_score": entry.risk_score,
                "target": entry.target,
                "timestamp": entry.timestamp,
            }
            for entry in entries[-12:]
        ],
    )


def _headline_metrics(
    supervisor: SupervisorSnapshot,
    checkpoints: list[CheckpointBundle],
    replay_reports: list[ReplayReport],
    gate_reports: list[RemediationGateReport],
    audit_entries: list[AuditLedgerEntry],
) -> list[MetricCard]:
    supervisor_summary = summarize_supervisor(supervisor)
    latest_replay = replay_reports[-1] if replay_reports else None
    latest_gate = gate_reports[-1] if gate_reports else None
    audit_summary = summarize_audit_entries(audit_entries)

    return [
        MetricCard("headline-status", "Supervisor status", supervisor.status, "neutral"),
        MetricCard(
            "headline-escalations",
            "Escalations",
            supervisor_summary.get("escalation_count", 0),
            "critical" if supervisor_summary.get("critical_escalations", 0) else "warning",
        ),
        MetricCard("headline-sessions", "Active sessions", len(supervisor.active_sessions), "neutral"),
        MetricCard("headline-checkpoints", "Checkpoints", len(checkpoints), "neutral"),
        MetricCard(
            "headline-last-replay",
            "Last replay",
            latest_replay.status if latest_replay else "none",
            "neutral",
        ),
        MetricCard(
            "headline-last-gate",
            "Last gate",
            latest_gate.gate_id if latest_gate else "none",
            "neutral",
        ),
        MetricCard(
            "headline-ledger",
            "Ledger integrity",
            "healthy" if audit_summary["verification"]["valid"] else "broken",
            "success" if audit_summary["verification"]["valid"] else "critical",
        ),
    ]


def _health_summary(
    supervisor: SupervisorSnapshot,
    replay_reports: list[ReplayReport],
    gate_reports: list[RemediationGateReport],
    audit_entries: list[AuditLedgerEntry],
) -> dict[str, Any]:
    supervisor_summary = summarize_supervisor(supervisor)
    audit_summary = summarize_audit_entries(audit_entries)

    health_score = 100
    health_score -= supervisor_summary.get("critical_escalations", 0) * 20
    health_score -= supervisor_summary.get("high_escalations", 0) * 10
    health_score -= sum(item.blocked_trace_count for item in replay_reports) * 5
    health_score -= sum(item.rejected_count for item in gate_reports) * 4
    if not audit_summary["verification"]["valid"]:
        health_score -= 50

    health_score = max(0, health_score)

    if health_score >= 85:
        posture = "stable"
    elif health_score >= 60:
        posture = "watch"
    else:
        posture = "critical"

    return {
        "score": health_score,
        "posture": posture,
        "generated_at": _utcnow(),
        "supervisor_status": supervisor.status,
        "audit_valid": audit_summary["verification"]["valid"],
    }


def build_operations_dashboard(
    *,
    supervisor: SupervisorSnapshot,
    checkpoints: list[CheckpointBundle],
    replay_reports: list[ReplayReport],
    gate_reports: list[RemediationGateReport],
    audit_entries: list[AuditLedgerEntry],
) -> OperationsDashboardSnapshot:
    sections = [
        _checkpoint_section(checkpoints),
        _replay_section(replay_reports),
        _gate_section(gate_reports),
        _audit_section(audit_entries),
    ]

    health_summary = _health_summary(
        supervisor=supervisor,
        replay_reports=replay_reports,
        gate_reports=gate_reports,
        audit_entries=audit_entries,
    )

    status = "healthy"
    if health_summary["posture"] == "watch":
        status = "degraded"
    elif health_summary["posture"] == "critical":
        status = "critical"

    return OperationsDashboardSnapshot(
        dashboard_id=f"ops-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
        status=status,
        generated_at=_utcnow(),
        sections=sections,
        headline_metrics=_headline_metrics(
            supervisor=supervisor,
            checkpoints=checkpoints,
            replay_reports=replay_reports,
            gate_reports=gate_reports,
            audit_entries=audit_entries,
        ),
        health_summary=health_summary,
    )


if __name__ == "__main__":
    from app.orchestrator.supervisor import initialize_supervisor

    supervisor = initialize_supervisor.__annotations__  # type: ignore[assignment]
    print(supervisor)
