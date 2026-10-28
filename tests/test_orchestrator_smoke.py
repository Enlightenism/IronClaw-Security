from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.orchestrator.coordination_state import initialize_coordination_state
from app.orchestrator.decision_trace import build_decision_trace
from app.orchestrator.dependency_graph import build_dependency_graph
from app.orchestrator.orchestrator import IronClawOrchestrator
from app.orchestrator.policy_engine import (
    PolicyContext,
    PolicyRule,
    apply_policy_to_plan,
    evaluate_policy,
)
from app.orchestrator.replay_controller import _build_replay_step
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


def test_orchestrator_smoke_emits_binary_plan_and_trace():
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
    assert record.execution_plan.verdict in {"allow", "block"}
    assert record.execution_plan.should_warn is False
    assert record.execution_plan.should_halt == (record.execution_plan.verdict == "block")
    assert len(record.session.event_log) == 1
    assert record.session.event_log[0].verdict == record.execution_plan.verdict
    assert updated_snapshot.recent_events[0].verdict == record.execution_plan.verdict
    trace = build_decision_trace(
        session=record.session,
        action_type="read",
        target="app/services/scanner.py",
        content="def scan_text(value: str) -> dict: return {'ok': True}",
        execution_plan=record.execution_plan,
    )
    assert trace.outcome == ("allowed" if record.execution_plan.verdict == "allow" else "blocked")
    if record.execution_plan.verdict == "block":
        assert record.execution_plan.risk_score >= RISK_THRESHOLD_BLOCK_MIN
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
    assert evaluation.final_effect in {"allow", "block"}
    assert evaluation.decision == evaluation.final_effect
    assert evaluation.allowed == (evaluation.final_effect == "allow")
    assert hardened_plan.verdict in {"allow", "block"}
    assert hardened_plan.should_warn is False

    if evaluation.final_effect == "block":
        assert hardened_plan.verdict == "block"
        assert hardened_plan.lane == "hard_block"
        assert hardened_plan.allowed is False
        assert hardened_plan.should_halt is True
        assert hardened_plan.risk_score >= RISK_THRESHOLD_BLOCK_MIN
    else:
        assert hardened_plan.verdict == "allow"
        assert hardened_plan.allowed is True
        assert hardened_plan.should_halt is False


def test_orchestrator_blocks_legacy_guard_warning():
    client = SimpleNamespace(
        guard_action_decision=lambda **_: SimpleNamespace(
            verdict="warn",
            should_halt=False,
            should_warn=True,
            risk_score=45,
            matched_patterns=[],
            summary="The guard requested review.",
            scan_id=None,
        ),
    )
    orchestrator = IronClawOrchestrator(
        project_root=Path().resolve(),
        client=client,
    )

    decision = orchestrator.route_action(
        action_type="tool_call",
        target="scanner",
        content="run a tool",
        file_path="app/services/scanner.py",
    )

    assert decision.verdict == "block"
    assert decision.allowed is False
    assert decision.should_halt is True
    assert decision.should_warn is False
    assert decision.risk_score >= RISK_THRESHOLD_BLOCK_MIN


def test_orchestrator_guard_api_failure_blocks_even_when_fallback_flag_is_false():
    def fail_guard_api(**_):
        raise RuntimeError("guard unavailable")

    client = SimpleNamespace(guard_action_decision=fail_guard_api)
    orchestrator = IronClawOrchestrator(
        project_root=Path().resolve(),
        client=client,
    )

    decision = orchestrator.route_action(
        action_type="read",
        target="scanner",
        content="read scanner",
        file_path="app/services/scanner.py",
        fail_secure_fallback=False,
    )

    assert decision.verdict == "block"
    assert decision.allowed is False
    assert decision.should_halt is True
    assert decision.should_warn is False
    assert decision.risk_score >= RISK_THRESHOLD_BLOCK_MIN
    assert "block-only policy" in decision.summary


def test_policy_monitor_mode_still_returns_block_for_matched_review_rule():
    context = PolicyContext(
        agent_id="agent-1",
        file_path="app/services/scanner.py",
        action_type="tool_call",
        target="scanner",
        risk_score=0,
        lane="direct_allow",
        verdict="allow",
    )
    rule = PolicyRule(
        rule_id="legacy-review-rule",
        name="Legacy review rule",
        description="A legacy review effect must fail closed.",
        effect="review",
        min_risk_score=0,
    )

    evaluation = evaluate_policy(context, [rule], mode="monitor")

    assert evaluation.decision == "block"
    assert evaluation.final_effect == "block"
    assert evaluation.allowed is False
    assert evaluation.matched_rules[0].effect == "block"


def test_replay_normalizes_non_allow_verdicts_to_block():
    for verdict in ("warn", "quarantine", "review", "invalid"):
        trace = SimpleNamespace(
            trace_id="trace-legacy",
            session_id="session-legacy",
            action_type="tool_call",
            target="shell",
            execution_plan=SimpleNamespace(verdict=verdict, risk_score=25),
        )

        step = _build_replay_step(trace)

        assert step.verdict == "block"
        assert step.risk_score >= RISK_THRESHOLD_BLOCK_MIN
        assert step.replay_outcome == "halted"


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
