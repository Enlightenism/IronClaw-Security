from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.schemas.telemetry import TelemetryEventSummary
from app.services.securityorchestrator import SecurityOrchestrator, initializesecurityorchestrator


@dataclass(slots=True)
class MetricsSummaryViewModel:
    total_events: int
    allow_count: int
    review_count: int
    blocked_count: int
    quarantine_count: int
    latest_event_at: str | None
    telemetry_path: str

    @classmethod
    def from_summary(cls, summary: dict[str, Any]) -> MetricsSummaryViewModel:
        return cls(
            total_events=int(summary.get("eventcount", 0)),
            allow_count=int(summary.get("allowcount", 0)),
            review_count=int(summary.get("reviewcount", 0)),
            blocked_count=int(summary.get("blockedcount", 0)),
            quarantine_count=int(summary.get("quarantinecount", 0)),
            latest_event_at=summary.get("latesteventat"),
            telemetry_path=str(summary.get("telemetrypath", "")),
        )


def get_metrics_summary_viewmodel(
    *,
    orchestrator: SecurityOrchestrator | None = None,
    limit: int = 250,
) -> MetricsSummaryViewModel:
    runtime_orchestrator = orchestrator or initializesecurityorchestrator()
    summary = runtime_orchestrator.replay_summary(limit=limit)
    return MetricsSummaryViewModel.from_summary(summary)


def get_recent_runtime_events(
    *,
    orchestrator: SecurityOrchestrator | None = None,
    limit: int = 50,
) -> list[TelemetryEventSummary]:
    runtime_orchestrator = orchestrator or initializesecurityorchestrator()
    events = list(runtime_orchestrator.iter_events(limit=limit))

    results: list[TelemetryEventSummary] = []
    for event in events:
        results.append(
            TelemetryEventSummary(
                event_id=event.eventid,
                occurred_at=event.occurredat,
                actor_id=event.actorid,
                session_id=event.sessionid,
                action_type=event.actiontype,
                target=event.target,
                execution_state=event.executionstate,
                policy_verdict=event.policyverdict,
                response_action=event.responseaction,
                adjusted_risk_score=event.adjustedriskscore,
                review_required=event.reviewrequired,
                quarantine=event.quarantine,
            ),
        )

    return results
