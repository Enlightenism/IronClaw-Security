from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from app.orchestrator.agent_registry import AgentRegistry
from app.orchestrator.dependency_graph import DependencyGraph
from app.orchestrator.execution_plan import ExecutionPlan

CoordinationStatus = Literal[
    "idle",
    "observing",
    "review",
    "quarantined",
    "blocked",
]

CoordinationPriority = Literal[
    "low",
    "normal",
    "high",
    "critical",
]


@dataclass
class AgentState:
    agent_id: str
    file_path: str
    registry_threat_profile: str
    status: CoordinationStatus = "idle"
    priority: CoordinationPriority = "normal"
    last_summary: str = ""
    last_verdict: str = "allow"
    last_risk_score: int = 0
    last_scan_id: str | None = None
    last_updated_at: str | None = None
    upstream_agents: list[str] = field(default_factory=list)
    downstream_agents: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class CoordinationEvent:
    agent_id: str
    file_path: str
    verdict: str
    status: CoordinationStatus
    priority: CoordinationPriority
    summary: str
    risk_score: int
    matched_patterns: list[str] = field(default_factory=list)
    scan_id: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class CoordinationSnapshot:
    project_root: str
    total_agents: int
    states: list[AgentState] = field(default_factory=list)
    recent_events: list[CoordinationEvent] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "project_root": self.project_root,
            "total_agents": self.total_agents,
            "states": [asdict(state) for state in self.states],
            "recent_events": [asdict(event) for event in self.recent_events],
        }


def _priority_for_plan(plan: ExecutionPlan) -> CoordinationPriority:
    if plan.verdict == "block":
        return "critical"
    if plan.verdict == "quarantine":
        return "high"
    if plan.verdict == "warn":
        return "normal"
    return "low"


def _status_for_plan(plan: ExecutionPlan) -> CoordinationStatus:
    if plan.verdict == "block":
        return "blocked"
    if plan.verdict == "quarantine":
        return "quarantined"
    if plan.verdict == "warn":
        return "review"
    if plan.registry_threat_profile in {"execution_capable", "security_critical"}:
        return "observing"
    return "idle"


def _build_agent_links(
    registry: AgentRegistry,
    graph: DependencyGraph,
) -> dict[str, dict[str, list[str]]]:
    path_to_agent_id = {
        item.relative_path: item.agent_id
        for item in registry.items
    }

    links: dict[str, dict[str, list[str]]] = {}

    for node in graph.nodes:
        agent_id = path_to_agent_id.get(node.relative_path)
        if not agent_id:
            continue

        links[agent_id] = {
            "upstream_agents": sorted(
                path_to_agent_id[path]
                for path in node.incoming
                if path in path_to_agent_id
            ),
            "downstream_agents": sorted(
                path_to_agent_id[path]
                for path in node.outgoing
                if path in path_to_agent_id
            ),
        }

    return links


def initialize_coordination_state(
    registry: AgentRegistry,
    graph: DependencyGraph,
) -> CoordinationSnapshot:
    links = _build_agent_links(registry, graph)

    states: list[AgentState] = []
    for item in registry.items:
        agent_links = links.get(item.agent_id, {})
        status: CoordinationStatus = "observing" if item.threat_profile in {
            "execution_capable",
            "security_critical",
            "sensitive",
        } else "idle"

        priority: CoordinationPriority = "high" if item.threat_profile == "security_critical" else (
            "normal" if item.threat_profile in {"sensitive", "execution_capable"} else "low"
        )

        states.append(
            AgentState(
                agent_id=item.agent_id,
                file_path=item.relative_path,
                registry_threat_profile=item.threat_profile,
                status=status,
                priority=priority,
                last_summary="",
                last_verdict="allow",
                last_risk_score=0,
                last_scan_id=None,
                last_updated_at=None,
                upstream_agents=agent_links.get("upstream_agents", []),
                downstream_agents=agent_links.get("downstream_agents", []),
                tags=item.tags,
            )
        )

    states.sort(key=lambda state: state.file_path)

    return CoordinationSnapshot(
        project_root=registry.project_root,
        total_agents=len(states),
        states=states,
        recent_events=[],
    )


def apply_execution_plan(
    snapshot: CoordinationSnapshot,
    plan: ExecutionPlan,
    max_recent_events: int = 100,
) -> CoordinationSnapshot:
    updated_states: list[AgentState] = []
    matched = False

    for state in snapshot.states:
        if state.agent_id != plan.agent_id:
            updated_states.append(state)
            continue

        matched = True
        updated_states.append(
            AgentState(
                agent_id=state.agent_id,
                file_path=state.file_path,
                registry_threat_profile=state.registry_threat_profile,
                status=_status_for_plan(plan),
                priority=_priority_for_plan(plan),
                last_summary=plan.summary,
                last_verdict=plan.verdict,
                last_risk_score=plan.risk_score,
                last_scan_id=plan.scan_id,
                last_updated_at=datetime.now(UTC).isoformat(),
                upstream_agents=state.upstream_agents,
                downstream_agents=state.downstream_agents,
                tags=state.tags,
            )
        )

    if not matched:
        raise ValueError(f"Unknown agent_id in execution plan: {plan.agent_id}")

    event = CoordinationEvent(
        agent_id=plan.agent_id,
        file_path=plan.file_path,
        verdict=plan.verdict,
        status=_status_for_plan(plan),
        priority=_priority_for_plan(plan),
        summary=plan.summary,
        risk_score=plan.risk_score,
        matched_patterns=plan.matched_patterns,
        scan_id=plan.scan_id,
    )

    recent_events = [event, *snapshot.recent_events][:max_recent_events]

    return CoordinationSnapshot(
        project_root=snapshot.project_root,
        total_agents=snapshot.total_agents,
        states=updated_states,
        recent_events=recent_events,
    )


def get_agent_state(snapshot: CoordinationSnapshot, agent_id: str) -> AgentState | None:
    for state in snapshot.states:
        if state.agent_id == agent_id:
            return state
    return None


def save_coordination_snapshot(
    snapshot: CoordinationSnapshot,
    output_path: str | Path,
) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(snapshot.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    from pathlib import Path

    from app.orchestrator.agent_registry import discover_agents
    from app.orchestrator.dependency_graph import build_dependency_graph

    root = Path(".").resolve()
    registry = discover_agents(root)
    graph = build_dependency_graph(root)
    snapshot = initialize_coordination_state(registry, graph)
    print(json.dumps(snapshot.to_dict(), ensure_ascii=False, indent=2))