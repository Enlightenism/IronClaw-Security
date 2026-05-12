from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
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


def _clamp_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    for method in ("as_dict", "to_dict", "model_dump", "dict"):
        fn = getattr(value, method, None)
        if callable(fn):
            result = fn()
            if isinstance(result, dict):
                return dict(result)
    return {}


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
        return {
            "session": _as_dict(self.session),
            "execution_plan": _as_dict(self.execution_plan),
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
                key: _as_dict(value)
                for key, value in self.active_sessions.items()
            },
            "execution_history": [record.to_dict() for record in self.execution_history],
            "escalations": [item.to_dict() for item in self.escalations],
        }


# ---------------------------------------------------------------------------
# Injected supervisor — used by build_supervisor / testsupervisor.py
# ---------------------------------------------------------------------------

def _merge_reasons(raw: Any) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    merged: list[dict[str, Any]] = []
    for item in (raw or []):
        if isinstance(item, dict):
            key = (_text(item.get("label")), _text(item.get("details")))
            if key not in seen:
                seen.add(key)
                merged.append(dict(item))
    return merged


def _merge_rules(raw: Any) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for rule in (raw or []):
        r = _text(rule)
        if r and r not in seen:
            seen.add(r)
            result.append(r)
    return result


@dataclass(slots=True)
class _SupervisedResult:
    session_id: str
    tool_name: str
    verdict: str
    allowed: bool
    should_review: bool
    should_block: bool
    should_quarantine: bool
    risk_delta: int
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    pipeline_decision: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "sessionid": self.session_id,
            "toolname": self.tool_name,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": self.risk_delta,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
            "pipelinedecision": dict(self.pipeline_decision),
        }


class _InjectedSupervisor:
    """Dependency-injected supervisor consumed by testsupervisor.py."""

    def __init__(
        self,
        *,
        secure_runtime_pipeline: Any,
        review_queue: Any,
        audit_sink: Any,
    ) -> None:
        self._pipeline = secure_runtime_pipeline
        self._review_queue = review_queue
        self._audit_sink = audit_sink

    # ------------------------------------------------------------------
    def _emit(self, event: dict[str, Any]) -> None:
        sink = self._audit_sink
        if sink is None:
            return
        for method_name in ("record", "emit", "write"):
            fn = getattr(sink, method_name, None)
            if callable(fn):
                try:
                    fn(event)
                except Exception:
                    pass
                return

    def _enqueue(self, item: dict[str, Any]) -> None:
        q = self._review_queue
        if q is None:
            return
        for method_name in ("enqueue", "submit"):
            fn = getattr(q, method_name, None)
            if callable(fn):
                try:
                    fn(item)
                except Exception:
                    pass
                return

    # ------------------------------------------------------------------
    def evaluate(self, *, session_id: str = "", tool_name: str = "", **kwargs: Any) -> _SupervisedResult:
        session_id = (session_id or "").strip()
        tool_name = (tool_name or "").strip().lower()

        if not session_id:
            result = _SupervisedResult(
                session_id=session_id,
                tool_name=tool_name,
                verdict="quarantine",
                allowed=False,
                should_review=False,
                should_block=True,
                should_quarantine=True,
                risk_delta=0,
                matched_rules=["supervisor:missing_session_id"],
                reasons=[],
                pipeline_decision={},
            )
            self._emit({"event": "quarantine", "reason": "missing_session_id", "session_id": session_id})
            return result

        if not tool_name:
            result = _SupervisedResult(
                session_id=session_id,
                tool_name=tool_name,
                verdict="quarantine",
                allowed=False,
                should_review=False,
                should_block=True,
                should_quarantine=True,
                risk_delta=0,
                matched_rules=["supervisor:missing_tool_name"],
                reasons=[],
                pipeline_decision={},
            )
            self._emit({"event": "quarantine", "reason": "missing_tool_name", "session_id": session_id})
            return result

        cwd = kwargs.get("cwd")
        if isinstance(cwd, str):
            kwargs["cwd"] = cwd.strip()

        pipeline_decision = self._pipeline.evaluate(
            session_id=session_id,
            tool_name=tool_name,
            **kwargs,
        )

        pipeline_dict = _as_dict(pipeline_decision)
        verdict = _text(getattr(pipeline_decision, "verdict", pipeline_dict.get("verdict", "allow"))).lower() or "allow"
        allowed = bool(getattr(pipeline_decision, "allowed", pipeline_dict.get("allowed", True)))
        should_review = bool(getattr(pipeline_decision, "should_review", pipeline_dict.get("shouldreview", False)))
        should_block = bool(getattr(pipeline_decision, "should_block", pipeline_dict.get("shouldblock", False)))
        should_quarantine = bool(getattr(pipeline_decision, "should_quarantine", pipeline_dict.get("shouldquarantine", False)))
        risk_delta = _clamp_int(getattr(pipeline_decision, "risk_delta", pipeline_dict.get("riskdelta", 0)))

        raw_rules = getattr(pipeline_decision, "matched_rules", pipeline_dict.get("matchedrules", None)) or []
        raw_reasons = getattr(pipeline_decision, "reasons", pipeline_dict.get("reasons", None)) or []

        matched_rules = _merge_rules(raw_rules)
        reasons = _merge_reasons(raw_reasons)

        result = _SupervisedResult(
            session_id=session_id,
            tool_name=tool_name,
            verdict=verdict,
            allowed=allowed,
            should_review=should_review,
            should_block=should_block,
            should_quarantine=should_quarantine,
            risk_delta=risk_delta,
            matched_rules=matched_rules,
            reasons=reasons,
            pipeline_decision=pipeline_dict,
        )

        self._emit({
            "event": verdict,
            "session_id": session_id,
            "tool_name": tool_name,
            "allowed": allowed,
            "risk_delta": risk_delta,
        })

        if should_review and verdict == "review":
            self._enqueue({
                "session_id": session_id,
                "tool_name": tool_name,
                "verdict": verdict,
                "risk_delta": risk_delta,
                "matched_rules": matched_rules,
            })

        return result

    def allow(self, *, session_id: str = "", tool_name: str = "", **kwargs: Any) -> bool:
        return self.evaluate(session_id=session_id, tool_name=tool_name, **kwargs).allowed


def build_supervisor(
    *,
    secure_runtime_pipeline: Any,
    review_queue: Any = None,
    audit_sink: Any = None,
) -> _InjectedSupervisor:
    return _InjectedSupervisor(
        secure_runtime_pipeline=secure_runtime_pipeline,
        review_queue=review_queue,
        audit_sink=audit_sink,
    )


# ---------------------------------------------------------------------------
# Orchestrator-pattern functions (preserved exactly)
# ---------------------------------------------------------------------------

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