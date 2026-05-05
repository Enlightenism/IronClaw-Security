from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.orchestrator.decision_trace import DecisionTrace
from app.orchestrator.runtime_session import RuntimeSession
from app.orchestrator.supervisor import SupervisorSnapshot, summarize_supervisor


CheckpointStatus = str


@dataclass(frozen=True)
class CheckpointManifest:
    checkpoint_id: str
    created_at: str
    status: CheckpointStatus
    project_root: str
    supervisor_id: str
    session_count: int
    execution_count: int
    escalation_count: int
    trace_count: int
    label: str
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class CheckpointBundle:
    manifest: CheckpointManifest
    supervisor: dict[str, Any]
    sessions: list[dict[str, Any]]
    traces: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "manifest": self.manifest.to_dict(),
            "supervisor": self.supervisor,
            "sessions": self.sessions,
            "traces": self.traces,
            "metadata": self.metadata,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def build_checkpoint_bundle(
    supervisor: SupervisorSnapshot,
    *,
    sessions: list[RuntimeSession] | None = None,
    traces: list[DecisionTrace] | None = None,
    label: str = "runtime-checkpoint",
    notes: str = "",
    metadata: dict[str, Any] | None = None,
) -> CheckpointBundle:
    resolved_sessions = sessions or list(supervisor.active_sessions.values())
    resolved_traces = traces or []

    manifest = CheckpointManifest(
        checkpoint_id=f"ckpt-{uuid4().hex[:16]}",
        created_at=_now(),
        status="created",
        project_root=supervisor.project_root,
        supervisor_id=supervisor.supervisor_id,
        session_count=len(resolved_sessions),
        execution_count=len(supervisor.execution_history),
        escalation_count=len(supervisor.escalations),
        trace_count=len(resolved_traces),
        label=label,
        notes=notes,
    )

    return CheckpointBundle(
        manifest=manifest,
        supervisor=supervisor.to_dict(),
        sessions=[session.to_dict() for session in resolved_sessions],
        traces=[trace.to_dict() for trace in resolved_traces],
        metadata=metadata or {},
    )


def save_checkpoint_bundle(
    checkpoint: CheckpointBundle,
    output_path: str | Path,
) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(checkpoint.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def append_checkpoint_manifest_jsonl(
    checkpoint: CheckpointBundle,
    output_path: str | Path,
) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(checkpoint.manifest.to_dict(), ensure_ascii=False) + "\n")
    return path


def load_checkpoint_bundle(input_path: str | Path) -> CheckpointBundle:
    path = Path(input_path).expanduser().resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))

    manifest = CheckpointManifest(**payload["manifest"])
    supervisor = payload["supervisor"]
    sessions = payload.get("sessions", [])
    traces = payload.get("traces", [])
    metadata = payload.get("metadata", {})

    return CheckpointBundle(
        manifest=manifest,
        supervisor=supervisor,
        sessions=sessions,
        traces=traces,
        metadata=metadata,
    )


def summarize_checkpoint(checkpoint: CheckpointBundle) -> dict[str, Any]:
    supervisor_summary: dict[str, Any] = {}
    supervisor_payload = checkpoint.supervisor

    if isinstance(supervisor_payload, dict):
        try:
            active_sessions = supervisor_payload.get("active_sessions", {})
            execution_history = supervisor_payload.get("execution_history", [])
            escalations = supervisor_payload.get("escalations", [])

            reconstructed = SupervisorSnapshot(
                supervisor_id=supervisor_payload["supervisor_id"],
                project_root=supervisor_payload["project_root"],
                status=supervisor_payload["status"],
                created_at=supervisor_payload["created_at"],
                updated_at=supervisor_payload["updated_at"],
                active_sessions=active_sessions,
                execution_history=execution_history,
                escalations=escalations,
            )
            supervisor_summary = summarize_supervisor(reconstructed)
        except Exception:
            supervisor_summary = {
                "status": supervisor_payload.get("status"),
                "active_session_count": len(supervisor_payload.get("active_sessions", {})),
                "execution_count": len(supervisor_payload.get("execution_history", [])),
                "escalation_count": len(supervisor_payload.get("escalations", [])),
            }

    return {
        "checkpoint_id": checkpoint.manifest.checkpoint_id,
        "label": checkpoint.manifest.label,
        "status": checkpoint.manifest.status,
        "created_at": checkpoint.manifest.created_at,
        "session_count": checkpoint.manifest.session_count,
        "execution_count": checkpoint.manifest.execution_count,
        "escalation_count": checkpoint.manifest.escalation_count,
        "trace_count": checkpoint.manifest.trace_count,
        "supervisor": supervisor_summary,
    }


if __name__ == "__main__":
    from app.orchestrator.coordination_state import initialize_coordination_state
    from app.orchestrator.decision_trace import build_decision_trace
    from app.orchestrator.dependency_graph import build_dependency_graph
    from app.orchestrator.orchestrator import IronClawOrchestrator
    from app.orchestrator.policy_engine import apply_policy_to_plan
    from app.orchestrator.supervisor import (
        SessionExecutionRequest,
        initialize_supervisor,
        run_supervised_request,
    )

    root = Path(".").resolve()
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
        metadata={"source": "checkpoint-demo"},
    )

    checkpoint = build_checkpoint_bundle(
        supervisor,
        sessions=list(supervisor.active_sessions.values()),
        traces=[trace],
        label="post-supervised-execution",
        notes="Checkpoint created after supervised execution and trace generation.",
        metadata={"mode": "demo"},
    )

    print(json.dumps(summarize_checkpoint(checkpoint), ensure_ascii=False, indent=2))