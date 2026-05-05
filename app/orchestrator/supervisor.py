from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from app.orchestrator.coordination_state import CoordinationSnapshot
from app.orchestrator.execution_plan import ExecutionPlan
from app.orchestrator.orchestrator import IronClawOrchestrator
from app.orchestrator.runtime_session import (
    RuntimeSession,
    create_runtime_session,
    execute_routed_task_in_session,
)

SupervisorStatus = str
EscalationLevel = str


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


@dataclass(slots=True)
class SupervisorEscalation:
    escalation_id: str
    session_id: str
    agent_id: str | None
    file_path: str
    level: EscalationLevel
    reason: str
    verdict: str
    risk_score: int
    created_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SessionExecutionRequest:
    file_path: str
    action_type: str
    target: str
    content: str = ""
    use_guard_api: bool = True
    agent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "use_guard_api": self.use_guard_api,
            "agent_id": self.agent_id,
        }


@dataclass(slots=True)
class SessionExecutionRecord:
    session: RuntimeSession
    execution_plan: ExecutionPlan
    status: str

    def to_dict(self) -> dict[str, Any]:
        session_dict = (
            self.session.as_dict()  # RuntimeSession follows dataclass-style container pattern [web:124]
            if hasattr(self.session, "as_dict")
            else self.session.to_dict()
            if hasattr(self.session, "to_dict")
            else {}
        )
        plan_dict = (
            self.execution_plan.as_dict()
            if hasattr(self.execution_plan, "as_dict")
            else self.execution_plan.to_dict()
            if hasattr(self.execution_plan, "to_dict")
            else {}
        )
        return {
            "session": session_dict,
            "execution_plan": plan_dict,
            "status": self.status,
        }


@dataclass(slots=True)
class SupervisorSnapshot:
    supervisor_id: str
    project_root: str
    status: SupervisorStatus
    created_at: str
    updated_at: str
    active_sessions: dict[str, RuntimeSession] = field(default_factory=dict)
    execution_history: list[SessionExecutionRecord] = field(default_factory=list)
    escalations: list[SupervisorEscalation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "supervisor_id": self.supervisor_id,
            "project_root": self.project_root,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "active_sessions": {
                key: (
                    value.as_dict()
                    if hasattr(value, "as_dict")
                    else value.to_dict()
                    if hasattr(value, "to_dict")
                    else {}
                )
                for key, value in self.active_sessions.items()
            },
            "execution_history": [record.to_dict() for record in self.execution_history],
            "escalations": [item.to_dict() for item in self.escalations],
        }


def initialize_supervisor(orchestrator: IronClawOrchestrator) -> SupervisorSnapshot:
    now = _utc_now_iso()
    return SupervisorSnapshot(
        supervisor_id=f"sup-{uuid4().hex[:16]}",
        project_root=str(Path(orchestrator.project_root).resolve()),
        status="ready",
        created_at=now,
        updated_at=now,
    )


def _session_key(file_path: str, agent_id: str | None = None) -> str:
    return f"{agent_id or 'auto'}::{file_path}"


def _escalation_level_for_plan(plan: ExecutionPlan) -> EscalationLevel | None:
    verdict = getattr(plan, "verdict", None)
    risk_score = int(getattr(plan, "risk_score", 0) or 0)
    if verdict == "block":
        return "critical"
    if verdict == "quarantine":
        return "high"
    if verdict == "warn" and risk_score >= 70:
        return "medium"
    return None


def _escalation_reason(plan: ExecutionPlan) -> str:
    verdict = getattr(plan, "verdict", None)
    if verdict == "block":
        return "Supervisor detected a blocked execution plan requiring immediate halt."
    if verdict == "quarantine":
        return "Supervisor detected a quarantined plan requiring controlled isolation."
    return "Supervisor detected elevated risk requiring review."


def _status_from_history(
    history: Iterable[SessionExecutionRecord],
    escalations: Iterable[SupervisorEscalation],
) -> SupervisorStatus:
    escalations_list = list(escalations)
    history_list = list(history)

    if any(item.level == "critical" for item in escalations_list):
        return "critical"
    if any(item.level == "high" for item in escalations_list):
        return "elevated"
    if any(
        getattr(record.execution_plan, "verdict", None) == "warn"
        for record in history_list
    ):
        return "monitoring"
    if history_list:
        return "active"
    return "ready"


def get_or_create_session(
    orchestrator: IronClawOrchestrator,
    supervisor: SupervisorSnapshot,
    *,
    file_path: str,
    agent_id: str | None = None,
) -> tuple[SupervisorSnapshot, RuntimeSession]:
    key = _session_key(file_path, agent_id)

    if key in supervisor.active_sessions:
        return supervisor, supervisor.active_sessions[key]

    session = create_runtime_session(
        orchestrator,
        file_path=file_path,
        agent_id=agent_id,
    )

    updated_sessions = dict(supervisor.active_sessions)
    updated_sessions[key] = session

    updated_supervisor = SupervisorSnapshot(
        supervisor_id=supervisor.supervisor_id,
        project_root=supervisor.project_root,
        status=supervisor.status,
        created_at=supervisor.created_at,
        updated_at=_utc_now_iso(),
        active_sessions=updated_sessions,
        execution_history=supervisor.execution_history,
        escalations=supervisor.escalations,
    )
    return updated_supervisor, session


def run_supervised_request(
    orchestrator: IronClawOrchestrator,
    coordination_snapshot: CoordinationSnapshot,
    supervisor: SupervisorSnapshot,
    request: SessionExecutionRequest,
) -> tuple[SupervisorSnapshot, CoordinationSnapshot, SessionExecutionRecord]:
    supervisor, session = get_or_create_session(
        orchestrator,
        supervisor,
        file_path=request.file_path,
        agent_id=request.agent_id,
    )

    updated_session, updated_coordination_snapshot, routed_result = execute_routed_task_in_session(
        orchestrator,
        coordination_snapshot,
        session,
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        use_guard_api=request.use_guard_api,
    )

    key = _session_key(request.file_path, request.agent_id)
    updated_sessions = dict(supervisor.active_sessions)
    updated_sessions[key] = updated_session

    record = SessionExecutionRecord(
        session=updated_session,
        execution_plan=routed_result.execution_plan,
        status=getattr(updated_session, "status", "unknown"),
    )

    updated_history = [*supervisor.execution_history, record]
    updated_escalations = list(supervisor.escalations)

    escalation_level = _escalation_level_for_plan(routed_result.execution_plan)
    if escalation_level is not None:
        updated_escalations.append(
            SupervisorEscalation(
                escalation_id=f"esc-{uuid4().hex[:12]}",
                session_id=getattr(updated_session, "session_id", ""),
                agent_id=getattr(updated_session, "agent_id", None),
                file_path=getattr(updated_session, "file_path", request.file_path),
                level=escalation_level,
                reason=_escalation_reason(routed_result.execution_plan),
                verdict=getattr(routed_result.execution_plan, "verdict", "unknown"),
                risk_score=int(getattr(routed_result.execution_plan, "risk_score", 0) or 0),
            )
        )

    updated_supervisor = SupervisorSnapshot(
        supervisor_id=supervisor.supervisor_id,
        project_root=supervisor.project_root,
        status=_status_from_history(updated_history, updated_escalations),
        created_at=supervisor.created_at,
        updated_at=_utc_now_iso(),
        active_sessions=updated_sessions,
        execution_history=updated_history,
        escalations=updated_escalations,
    )

    return updated_supervisor, updated_coordination_snapshot, record


def summarize_supervisor(supervisor: SupervisorSnapshot) -> dict[str, Any]:
    return {
        "supervisor_id": supervisor.supervisor_id,
        "status": supervisor.status,
        "active_session_count": len(supervisor.active_sessions),
        "execution_count": len(supervisor.execution_history),
        "escalation_count": len(supervisor.escalations),
        "critical_escalations": sum(
            1 for item in supervisor.escalations if item.level == "critical"
        ),
        "high_escalations": sum(
            1 for item in supervisor.escalations if item.level == "high"
        ),
        "medium_escalations": sum(
            1 for item in supervisor.escalations if item.level == "medium"
        ),
    }


if __name__ == "__main__":
    import json

    from app.orchestrator.coordination_state import initialize_coordination_state
    from app.orchestrator.dependency_graph import build_dependency_graph

    root = Path(".").resolve()
    orchestrator = IronClawOrchestrator(project_root=root)
    graph = build_dependency_graph(root)
    coordination_snapshot = initialize_coordination_state(orchestrator.registry, graph)
    supervisor = initialize_supervisor(orchestrator)

    supervisor, coordination_snapshot, record = run_supervised_request(
        orchestrator,
        coordination_snapshot,
        supervisor,
        SessionExecutionRequest(
            file_path="app/services/scanner.py",
            action_type="tool_call",
            target="app/services/scanner.py",
            content="perform_scan('text', payload)",
            use_guard_api=False,
        ),
    )

    print(
        json.dumps(
            {
                "record": record.to_dict(),
                "summary": summarize_supervisor(supervisor),
            },
            ensure_ascii=False,
            indent=2,
        )
    )