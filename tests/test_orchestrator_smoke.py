from __future__ import annotations

from pathlib import Path

from app.orchestrator.coordination_state import initialize_coordination_state
from app.orchestrator.dependency_graph import build_dependency_graph
from app.orchestrator.orchestrator import IronClawOrchestrator
from app.orchestrator.policy_engine import apply_policy_to_plan
from app.orchestrator.supervisor import (
    SessionExecutionRequest,
    initialize_supervisor,
    run_supervised_request,
)


def _build_runtime():
    root = Path().resolve()
    orchestrator = IronClawOrchestrator(project_root=root)
    graph = build_dependency_graph(root)
    coordination_snapshot = initialize_coordination_state(orchestrator.registry, graph)
    supervisor = initialize_supervisor(orchestrator)
    return orchestrator, coordination_snapshot, supervisor


def test_orchestrator_smoke_allows_happy_path():
    orchestrator, coordination_snapshot, supervisor = _build_runtime()

    supervisor, updated_snapshot, record = run_supervised_request(
        orchestrator,
        coordination_snapshot,
        supervisor,
        SessionExecutionRequest(
            file_path="app/services/scanner.py",
            action_type="read",
            target="app/services/scanner.py",
            content="def scan_text(value: str) -> dict: return {'ok': True}",
            use_guard_api=False,
        ),
    )

    assert record.session.session_id.startswith("ics-")
    assert record.session.agent_id
    assert record.session.file_path == "app/services/scanner.py"
    assert record.execution_plan.verdict in {"allow", "warn", "quarantine", "block"}
    assert len(record.session.event_log) == 1
    assert supervisor.active_sessions
    assert supervisor.execution_history
    assert updated_snapshot is not None
    assert updated_snapshot != coordination_snapshot


def test_orchestrator_smoke_policy_can_harden_execution_plan():
    orchestrator, coordination_snapshot, supervisor = _build_runtime()

    supervisor, coordination_snapshot, record = run_supervised_request(
        orchestrator,
        coordination_snapshot,
        supervisor,
        SessionExecutionRequest(
            file_path="app/services/scanner.py",
            action_type="tool_call",
            target="app/services/scanner.py",
            content="export_credentials()",
            use_guard_api=False,
        ),
    )

    hardened_plan, evaluation = apply_policy_to_plan(
        record.execution_plan,
        agent_id=record.session.agent_id,
        file_path=record.session.file_path,
        action_type="tool_call",
        target=record.session.file_path,
    )

    assert evaluation.evaluation_id.startswith("pe-")
    assert evaluation.final_effect in {"allow", "review", "quarantine", "block"}
    assert hardened_plan.verdict in {"allow", "warn", "quarantine", "block"}

    if evaluation.final_effect == "review":
        assert hardened_plan.verdict == "warn"
        assert hardened_plan.risk_score >= 50
    elif evaluation.final_effect == "quarantine":
        assert hardened_plan.verdict == "quarantine"
        assert hardened_plan.lane == "containment"
        assert hardened_plan.risk_score >= 75
    elif evaluation.final_effect == "block":
        assert hardened_plan.verdict == "block"
        assert hardened_plan.lane == "containment"
        assert hardened_plan.risk_score >= 90


def test_orchestrator_smoke_reuses_existing_session_for_same_file():
    orchestrator, coordination_snapshot, supervisor = _build_runtime()

    supervisor, coordination_snapshot, first_record = run_supervised_request(
        orchestrator,
        coordination_snapshot,
        supervisor,
        SessionExecutionRequest(
            file_path="app/services/scanner.py",
            action_type="read",
            target="app/services/scanner.py",
            content="scan payload one",
            use_guard_api=False,
        ),
    )

    supervisor, coordination_snapshot, second_record = run_supervised_request(
        orchestrator,
        coordination_snapshot,
        supervisor,
        SessionExecutionRequest(
            file_path="app/services/scanner.py",
            action_type="read",
            target="app/services/scanner.py",
            content="scan payload two",
            use_guard_api=False,
        ),
    )

    assert first_record.session.session_id == second_record.session.session_id
    assert len(second_record.session.event_log) >= 2
    assert len(supervisor.active_sessions) == 1
    assert len(supervisor.execution_history) >= 2
