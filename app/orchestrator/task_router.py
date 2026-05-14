from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from app.orchestrator.agent_registry import AgentDescriptor, ProtectedAction
from app.orchestrator.coordination_state import (
    AgentState,
    CoordinationSnapshot,
    get_agent_state,
)
from app.orchestrator.execution_plan import ExecutionPlan, build_execution_plan
from app.orchestrator.orchestrator import IronClawOrchestrator, OrchestrationDecision

RoutingMode = Literal[
    "direct_file",
    "agent_id",
    "dependency_inferred",
    "broadcast_security_scope",
]

RoutingPriority = Literal[
    "low",
    "normal",
    "high",
    "critical",
]


@dataclass
class RoutedTask:
    route_id: str
    agent_id: str
    file_path: str
    action_type: ProtectedAction
    target: str
    content: str
    routing_mode: RoutingMode
    priority: RoutingPriority
    summary: str
    tags: list[str] = field(default_factory=list)
    dependency_scope: list[str] = field(default_factory=list)
    client_id: str | None = None
    session_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RoutedTaskResult:
    task: RoutedTask
    decision: OrchestrationDecision
    execution_plan: ExecutionPlan
    agent_state: AgentState | None = None

    def to_dict(self) -> dict:
        return {
            "task": self.task.to_dict(),
            "decision": self.decision.to_dict(),
            "execution_plan": self.execution_plan.to_dict(),
            "agent_state": asdict(self.agent_state) if self.agent_state else None,
        }


def _normalize_path(file_path: str) -> str:
    return file_path.replace("\\", "/").strip()


def _priority_for_agent(agent: AgentDescriptor, action_type: ProtectedAction) -> RoutingPriority:
    if agent.threat_profile == "security_critical":
        return "critical"
    if agent.threat_profile == "execution_capable":
        return "high"
    if action_type in {"shell_command", "network_request", "git_operation", "tool_call"}:
        return "high"
    if agent.threat_profile == "sensitive":
        return "normal"
    return "low"


def _build_route_id(agent_id: str, action_type: ProtectedAction, target: str) -> str:
    normalized_target = target.strip().replace("\\", "/")[:80]
    return f"{agent_id}:{action_type}:{normalized_target}"


def _summary_for_route(
    agent: AgentDescriptor,
    action_type: ProtectedAction,
    routing_mode: RoutingMode,
) -> str:
    return f"Routed action '{action_type}' to agent {agent.agent_id} for file {agent.relative_path} via mode '{routing_mode}'."


def create_routed_task(
    orchestrator: IronClawOrchestrator,
    *,
    action_type: ProtectedAction,
    target: str,
    content: str = "",
    file_path: str | None = None,
    agent_id: str | None = None,
    routing_mode: RoutingMode | None = None,
    dependency_scope: list[str] | None = None,
    client_id: str | None = None,
    session_id: str | None = None,
) -> RoutedTask:
    agent = orchestrator.get_agent(
        file_path=_normalize_path(file_path) if file_path else None,
        agent_id=agent_id,
    )

    resolved_mode: RoutingMode = routing_mode or ("agent_id" if agent_id else "direct_file")

    return RoutedTask(
        route_id=_build_route_id(agent.agent_id, action_type, target),
        agent_id=agent.agent_id,
        file_path=agent.relative_path,
        action_type=action_type,
        target=target,
        content=content,
        routing_mode=resolved_mode,
        priority=_priority_for_agent(agent, action_type),
        summary=_summary_for_route(agent, action_type, resolved_mode),
        tags=agent.tags,
        dependency_scope=sorted(set(dependency_scope or [])),
        client_id=client_id or agent.agent_id,
        session_id=session_id,
    )


def route_and_plan(
    orchestrator: IronClawOrchestrator,
    snapshot: CoordinationSnapshot,
    *,
    action_type: ProtectedAction,
    target: str,
    content: str = "",
    file_path: str | None = None,
    agent_id: str | None = None,
    routing_mode: RoutingMode | None = None,
    dependency_scope: list[str] | None = None,
    client_id: str | None = None,
    session_id: str | None = None,
    use_guard_api: bool = True,
) -> RoutedTaskResult:
    task = create_routed_task(
        orchestrator,
        action_type=action_type,
        target=target,
        content=content,
        file_path=file_path,
        agent_id=agent_id,
        routing_mode=routing_mode,
        dependency_scope=dependency_scope,
        client_id=client_id,
        session_id=session_id,
    )

    decision = orchestrator.route_action(
        action_type=task.action_type,
        target=task.target,
        content=task.content,
        file_path=task.file_path,
        agent_id=task.agent_id,
        client_id=task.client_id,
        session_id=task.session_id,
        use_guard_api=use_guard_api,
    )

    execution_plan = build_execution_plan(decision)
    state = get_agent_state(snapshot, task.agent_id)

    return RoutedTaskResult(
        task=task,
        decision=decision,
        execution_plan=execution_plan,
        agent_state=state,
    )


if __name__ == "__main__":
    from app.orchestrator.coordination_state import initialize_coordination_state
    from app.orchestrator.dependency_graph import build_dependency_graph

    root = Path().resolve()
    orchestrator = IronClawOrchestrator(project_root=root)
    graph = build_dependency_graph(root)
    snapshot = initialize_coordination_state(orchestrator.registry, graph)

    result = route_and_plan(
        orchestrator,
        snapshot,
        action_type="tool_call",
        target="app/services/scanner.py",
        content="perform_scan('text', payload)",
        file_path="app/services/scanner.py",
        use_guard_api=False,
    )
    print(result.to_dict())
