from __future__ import annotations

from app.services.compatibility_matrix import (
    evaluate_compatibility,
    initialize_compatibility_matrix,
    list_compatibility_rules,
    summarize_compatibility_decision,
)


def test_list_compatibility_rules_returns_expected_runtime_families():
    matrix = initialize_compatibility_matrix()

    rules = list_compatibility_rules(matrix)

    assert len(rules) >= 3
    assert any(rule.runtime_family == "claude-code" for rule in rules)
    assert any(rule.runtime_family == "openclaw" for rule in rules)
    assert any(rule.runtime_family == "generic-agent" for rule in rules)


def test_evaluate_compatibility_returns_supported_for_claude_code_gen1():
    matrix = initialize_compatibility_matrix()

    decision = evaluate_compatibility(
        matrix,
        runtime_family="claude-code",
        version="0.1.0",
    )

    assert decision.runtime_family == "claude-code"
    assert decision.version == "0.1.0"
    assert decision.state == "supported"
    assert decision.matched_rule is not None


def test_evaluate_compatibility_returns_warning_for_generic_agent():
    matrix = initialize_compatibility_matrix()

    decision = evaluate_compatibility(
        matrix,
        runtime_family="generic-agent",
        version="0.5.0",
    )

    assert decision.runtime_family == "generic-agent"
    assert decision.state == "warning"
    assert "custom wrapper hooks" in decision.reason.lower()


def test_evaluate_compatibility_returns_unsupported_when_no_rule_matches():
    matrix = initialize_compatibility_matrix()

    decision = evaluate_compatibility(
        matrix,
        runtime_family="openclaw",
        version="9.9.9",
    )

    assert decision.runtime_family == "openclaw"
    assert decision.version == "9.9.9"
    assert decision.state == "unsupported"
    assert decision.matched_rule is None


def test_summarize_compatibility_decision_returns_expected_shape():
    matrix = initialize_compatibility_matrix()
    decision = evaluate_compatibility(
        matrix,
        runtime_family="claude-code",
        version="0.4.0",
    )

    summary = summarize_compatibility_decision(decision)

    assert summary["runtime_family"] == "claude-code"
    assert summary["version"] == "0.4.0"
    assert summary["state"] == "supported"
    assert summary["matched"] is True
    assert "checked_at" in summary
