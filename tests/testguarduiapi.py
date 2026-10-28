from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.main import app
from app.services.guard_security_brain import GuardSecurityDecision
from app.ui.guard import prompt_guard_simulator
from app.ui.guard.prompt_guard_policy import (
    PromptGuardPolicyView,
    PromptGuardRule,
    PromptGuardThresholds,
    build_prompt_guard_policy_view,
)
from app.ui.guard.verdict_assist import (
    VerdictAssistContext,
    _build_verdict_assist_insight,
)

client = TestClient(app)


def test_guard_ui_dashboard_route_is_registered() -> None:
    response = client.get("/ui/guard/prompt-guard/dashboard-index")
    assert response.status_code == 200


def test_guard_ui_dashboard_returns_json_object() -> None:
    response = client.get("/ui/guard/prompt-guard/dashboard-index")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_guard_ui_dashboard_contains_basic_shape() -> None:
    response = client.get("/ui/guard/prompt-guard/dashboard-index")

    assert response.status_code == 200

    data = response.json()
    assert {"generated_at", "dashboard", "sections", "metadata"} <= data.keys()


def test_prompt_guard_policy_uses_binary_actions_and_config_thresholds() -> None:
    policy = build_prompt_guard_policy_view()

    assert all(rule.default_action in {"allow", "block"} for rule in policy.rules)
    assert policy.thresholds.warn_score == RISK_THRESHOLD_BLOCK_MIN
    assert policy.thresholds.block_score == RISK_THRESHOLD_BLOCK_MIN
    assert policy.thresholds.quarantine_score == RISK_THRESHOLD_BLOCK_MIN


def test_prompt_guard_simulator_blocks_any_matched_rule(monkeypatch) -> None:
    policy = PromptGuardPolicyView(
        title="Test policy",
        mode="assist",
        health="healthy",
        generated_at="2026-10-26T00:00:00+00:00",
        thresholds=PromptGuardThresholds(
            warn_score=RISK_THRESHOLD_BLOCK_MIN,
            block_score=RISK_THRESHOLD_BLOCK_MIN,
            quarantine_score=RISK_THRESHOLD_BLOCK_MIN,
        ),
        rules=[
            PromptGuardRule(
                id="low-severity",
                name="Low severity match",
                category="tool_misuse",
                description="Test rule.",
                enabled=True,
                severity_weight=1,
                default_action="allow",
                match_patterns=["suspicious marker"],
            )
        ],
    )
    monkeypatch.setattr(prompt_guard_simulator, "build_prompt_guard_policy_view", lambda: policy)

    simulation = prompt_guard_simulator._simulate_prompt("suspicious marker")

    assert simulation.verdict == "block"
    assert simulation.risk_score >= RISK_THRESHOLD_BLOCK_MIN
    assert simulation.matches[0].action == "block"


def test_prompt_guard_simulator_allows_clean_prompt() -> None:
    simulation = prompt_guard_simulator._simulate_prompt("A harmless message.")

    assert simulation.verdict == "allow"
    assert simulation.matches == []


def test_verdict_assist_suggests_block_above_configured_allow_ceiling() -> None:
    context = VerdictAssistContext(
        action_type="prompt",
        target="local",
        content="Test prompt.",
        mode="assist",
    )
    decision = GuardSecurityDecision(
        mode="assist",
        verdict="allow",
        risk_score=RISK_THRESHOLD_ALLOW_MAX + 1,
        summary="Risk exceeds configured allow ceiling.",
    )

    insight = _build_verdict_assist_insight(context=context, decision=decision)

    assert insight.suggested_verdict == "block"
    assert insight.suggested_mode == "enforce"
