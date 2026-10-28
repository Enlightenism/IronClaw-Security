from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Literal
from uuid import uuid4

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.orchestrator.agent_profile import AgentProfile, build_agent_profile
from app.orchestrator.coordination_state import (
    CoordinationEvent,
    CoordinationSnapshot,
    apply_execution_plan,
)
from app.orchestrator.execution_plan import (
    ExecutionPlan,
    normalize_plan_verdict,
    normalized_plan_risk_score,
)
from app.orchestrator.orchestrator import IronClawOrchestrator
from app.orchestrator.task_router import RoutedTaskResult, route_and_plan

RuntimeSessionStatus = str


@dataclass
class RuntimeSessionEvent:
    event_id: str
    session_id: str
    agent_id: str
    file_path: str
    action_type: str
    target: str
    verdict: Literal["allow", "block"]
    lane: str
    summary: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    risk_score: int = 0
    matched_patterns: list[str] = field(default_factory=list)
    scan_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuntimeSession:
    session_id: str
    agent_id: str
    file_path: str
    profile: AgentProfile
    status: RuntimeSessionStatus
    created_at: str
    updated_at: str
    current_plan: ExecutionPlan | None = None
    event_log: list[RuntimeSessionEvent] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "file_path": self.file_path,
            "profile": self.profile.to_dict(),
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "current_plan": self.current_plan.to_dict() if self.current_plan else None,
            "event_log": [event.to_dict() for event in self.event_log],
        }


def _status_from_plan(plan: ExecutionPlan) -> RuntimeSessionStatus:
    return "blocked" if normalize_plan_verdict(plan) == "block" else "active"


def _build_runtime_event(result: RoutedTaskResult, session_id: str) -> RuntimeSessionEvent:
    plan = result.execution_plan
    return RuntimeSessionEvent(
        event_id=f"rse-{uuid4().hex[:12]}",
        session_id=session_id,
        agent_id=result.task.agent_id,
        file_path=result.task.file_path,
        action_type=result.task.action_type,
        target=result.task.target,
        verdict=normalize_plan_verdict(plan),
        lane=plan.lane,
        summary=plan.summary,
        risk_score=normalized_plan_risk_score(plan),
        matched_patterns=plan.matched_patterns,
        scan_id=plan.scan_id,
    )


def create_runtime_session(
    orchestrator: IronClawOrchestrator,
    *,
    file_path: str | None = None,
    agent_id: str | None = None,
) -> RuntimeSession:
    descriptor = orchestrator.get_agent(file_path=file_path, agent_id=agent_id)
    profile = build_agent_profile(descriptor)
    now = datetime.now(UTC).isoformat()

    return RuntimeSession(
        session_id=f"ics-{uuid4().hex}",
        agent_id=descriptor.agent_id,
        file_path=descriptor.relative_path,
        profile=profile,
        status="initialized",
        created_at=now,
        updated_at=now,
        current_plan=None,
        event_log=[],
    )


def execute_routed_task_in_session(
    orchestrator: IronClawOrchestrator,
    snapshot: CoordinationSnapshot,
    session: RuntimeSession,
    *,
    action_type: str,
    target: str,
    content: str = "",
    use_guard_api: bool = True,
) -> tuple[RuntimeSession, CoordinationSnapshot, RoutedTaskResult]:
    result = route_and_plan(
        orchestrator,
        snapshot,
        action_type=action_type,  # type: ignore[arg-type]
        target=target,
        content=content,
        agent_id=session.agent_id,
        session_id=session.session_id,
        use_guard_api=use_guard_api,
    )

    plan = result.execution_plan
    runtime_event = _build_runtime_event(result, session.session_id)
    updated_snapshot = apply_execution_plan(snapshot, plan)

    updated_session = RuntimeSession(
        session_id=session.session_id,
        agent_id=session.agent_id,
        file_path=session.file_path,
        profile=session.profile,
        status=_status_from_plan(plan),
        created_at=session.created_at,
        updated_at=datetime.now(UTC).isoformat(),
        current_plan=plan,
        event_log=[*session.event_log, runtime_event],
    )

    return updated_session, updated_snapshot, result


def coordination_events_from_session(session: RuntimeSession) -> list[CoordinationEvent]:
    events: list[CoordinationEvent] = []
    for event in session.event_log:
        verdict = "allow" if event.verdict == "allow" else "block"
        if verdict == "block":
            status = "blocked"
            priority = "critical"
        else:
            status = "observing"
            priority = "low"

        events.append(
            CoordinationEvent(
                agent_id=event.agent_id,
                file_path=event.file_path,
                verdict=verdict,
                status=status,  # type: ignore[arg-type]
                priority=priority,  # type: ignore[arg-type]
                summary=event.summary,
                risk_score=(max(event.risk_score, RISK_THRESHOLD_BLOCK_MIN) if verdict == "block" else event.risk_score),
                matched_patterns=event.matched_patterns,
                scan_id=event.scan_id,
                created_at=event.created_at,
            ),
        )
    return events


def save_runtime_session(
    session: RuntimeSession,
    output_path: str | Path,
) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(session.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    from app.orchestrator.coordination_state import initialize_coordination_state
    from app.orchestrator.dependency_graph import build_dependency_graph

    root = Path().resolve()
    orchestrator = IronClawOrchestrator(project_root=root)
    graph = build_dependency_graph(root)
    snapshot = initialize_coordination_state(orchestrator.registry, graph)

    session = create_runtime_session(
        orchestrator,
        file_path="app/services/scanner.py",
    )

    updated_session, updated_snapshot, result = execute_routed_task_in_session(
        orchestrator,
        snapshot,
        session,
        action_type="tool_call",
        target="app/services/scanner.py",
        content="perform_scan('text', payload)",
        use_guard_api=False,
    )

    print(json.dumps(updated_session.to_dict(), ensure_ascii=False, indent=2))
