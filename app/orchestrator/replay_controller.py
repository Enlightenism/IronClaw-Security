from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.orchestrator.checkpoint_store import (
    CheckpointBundle,
    load_checkpoint_bundle,
    summarize_checkpoint,
)
from app.orchestrator.decision_trace import DecisionTrace
from app.orchestrator.runtime_session import RuntimeSession
from app.orchestrator.supervisor import SupervisorSnapshot


ReplayMode = str
ReplayStatus = str


@dataclass(frozen=True)
class ReplayStep:
    step_id: str
    trace_id: str
    session_id: str
    action_type: str
    target: str
    verdict: str
    risk_score: int
    replay_outcome: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReplayReport:
    replay_id: str
    checkpoint_id: str
    mode: ReplayMode
    status: ReplayStatus
    created_at: str
    restored_supervisor_status: str
    restored_session_count: int
    replayed_trace_count: int
    blocked_trace_count: int
    quarantined_trace_count: int
    warning_trace_count: int
    allow_trace_count: int
    steps: list[ReplayStep] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "replay_id": self.replay_id,
            "checkpoint_id": self.checkpoint_id,
            "mode": self.mode,
            "status": self.status,
            "created_at": self.created_at,
            "restored_supervisor_status": self.restored_supervisor_status,
            "restored_session_count": self.restored_session_count,
            "replayed_trace_count": self.replayed_trace_count,
            "blocked_trace_count": self.blocked_trace_count,
            "quarantined_trace_count": self.quarantined_trace_count,
            "warning_trace_count": self.warning_trace_count,
            "allow_trace_count": self.allow_trace_count,
            "steps": [step.to_dict() for step in self.steps],
            "notes": self.notes,
        }


@dataclass(frozen=True)
class RestoredRuntimeState:
    checkpoint: CheckpointBundle
    supervisor: SupervisorSnapshot
    sessions: list[RuntimeSession]
    traces: list[DecisionTrace]

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint": self.checkpoint.to_dict(),
            "supervisor": self.supervisor.to_dict(),
            "sessions": [session.to_dict() for session in self.sessions],
            "traces": [trace.to_dict() for trace in self.traces],
        }


def _parse_supervisor(payload: dict[str, Any]) -> SupervisorSnapshot:
    return SupervisorSnapshot(
        supervisor_id=payload["supervisor_id"],
        project_root=payload["project_root"],
        status=payload["status"],
        created_at=payload["created_at"],
        updated_at=payload["updated_at"],
        active_sessions=payload.get("active_sessions", {}),
        execution_history=payload.get("execution_history", []),
        escalations=payload.get("escalations", []),
    )


def _parse_session(payload: dict[str, Any]) -> RuntimeSession:
    return RuntimeSession(**payload)


def _parse_trace(payload: dict[str, Any]) -> DecisionTrace:
    return DecisionTrace(**payload)


def restore_runtime_state(checkpoint_path: str | Path) -> RestoredRuntimeState:
    checkpoint = load_checkpoint_bundle(checkpoint_path)

    supervisor = _parse_supervisor(checkpoint.supervisor)
    sessions = [_parse_session(item) for item in checkpoint.sessions]
    traces = [_parse_trace(item) for item in checkpoint.traces]

    return RestoredRuntimeState(
        checkpoint=checkpoint,
        supervisor=supervisor,
        sessions=sessions,
        traces=traces,
    )


def _derive_replay_outcome(verdict: str) -> str:
    if verdict == "block":
        return "halted"
    if verdict == "quarantine":
        return "isolated"
    if verdict == "warn":
        return "review-required"
    return "continued"


def _build_replay_step(trace: DecisionTrace) -> ReplayStep:
    execution_plan = trace.execution_plan
    return ReplayStep(
        step_id=f"step-{uuid4().hex[:12]}",
        trace_id=trace.trace_id,
        session_id=trace.session_id,
        action_type=trace.action_type,
        target=trace.target,
        verdict=execution_plan.verdict,
        risk_score=execution_plan.risk_score,
        replay_outcome=_derive_replay_outcome(execution_plan.verdict),
    )


def replay_checkpoint(
    checkpoint_path: str | Path,
    *,
    mode: ReplayMode = "dry-run",
) -> ReplayReport:
    restored = restore_runtime_state(checkpoint_path)
    steps = [_build_replay_step(trace) for trace in restored.traces]

    blocked = sum(1 for step in steps if step.verdict == "block")
    quarantined = sum(1 for step in steps if step.verdict == "quarantine")
    warnings = sum(1 for step in steps if step.verdict == "warn")
    allowed = sum(1 for step in steps if step.verdict == "allow")

    notes = [
        f"Checkpoint label: {restored.checkpoint.manifest.label}",
        f"Replay mode: {mode}",
        f"Restored supervisor status: {restored.supervisor.status}",
    ]

    if blocked:
        notes.append("Replay encountered blocked traces that would halt live execution.")
    if quarantined:
        notes.append("Replay encountered quarantined traces that would require isolation.")
    if not restored.traces:
        notes.append("Checkpoint contained no decision traces; replay completed as restore-only.")

    status: ReplayStatus = "completed"
    if blocked:
        status = "completed-with-blocks"
    elif quarantined:
        status = "completed-with-quarantine"
    elif warnings:
        status = "completed-with-warnings"

    return ReplayReport(
        replay_id=f"rpl-{uuid4().hex[:16]}",
        checkpoint_id=restored.checkpoint.manifest.checkpoint_id,
        mode=mode,
        status=status,
        created_at=datetime.now(UTC).isoformat(),
        restored_supervisor_status=restored.supervisor.status,
        restored_session_count=len(restored.sessions),
        replayed_trace_count=len(steps),
        blocked_trace_count=blocked,
        quarantined_trace_count=quarantined,
        warning_trace_count=warnings,
        allow_trace_count=allowed,
        steps=steps,
        notes=notes,
    )


def summarize_replay(report: ReplayReport) -> dict[str, Any]:
    return {
        "replay_id": report.replay_id,
        "checkpoint_id": report.checkpoint_id,
        "status": report.status,
        "mode": report.mode,
        "restored_supervisor_status": report.restored_supervisor_status,
        "restored_session_count": report.restored_session_count,
        "replayed_trace_count": report.replayed_trace_count,
        "blocked_trace_count": report.blocked_trace_count,
        "quarantined_trace_count": report.quarantined_trace_count,
        "warning_trace_count": report.warning_trace_count,
        "allow_trace_count": report.allow_trace_count,
    }


if __name__ == "__main__":
    import json

    sample_path = Path("artifacts/runtime-checkpoint.json")

    if sample_path.exists():
        restored = restore_runtime_state(sample_path)
        report = replay_checkpoint(sample_path, mode="dry-run")
        print(
            json.dumps(
                {
                    "checkpoint": summarize_checkpoint(restored.checkpoint),
                    "replay": summarize_replay(report),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(
            json.dumps(
                {
                    "message": "Create artifacts/runtime-checkpoint.json before running replay_controller directly."
                },
                ensure_ascii=False,
                indent=2,
            )
        )