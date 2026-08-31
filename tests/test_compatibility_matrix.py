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

    expected_runtime_families = {
        "claude-code",
        "openclaw",
        "hermes",
        "cursor",
        "goose",
        "gemini-cli",
        "copilot",
        "security-guardian",
        "generic-agent",
    }

    assert len(rules) >= len(expected_runtime_families)
    assert {rule.runtime_family for rule in rules} >= expected_runtime_families
    assert any(rule.metadata.get("install_key_program") == "claude_code" for rule in rules)
    assert any(rule.metadata.get("install_key_program") == "security_guardian" for rule in rules)


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
    assert decision.metadata["install_key_program"] == "claude_code"
    assert decision.metadata["install_key_prefix"] == "ic_install_claude_code_"


def test_evaluate_compatibility_returns_supported_for_aliases_and_shared_family_assignment():
    matrix = initialize_compatibility_matrix()

    decision = evaluate_compatibility(
        matrix,
        runtime_family="github-copilot",
        version="0.3.0",
    )
    guardian_decision = evaluate_compatibility(
        matrix,
        runtime_family="security_guardian",
        version="0.2.0",
    )

    assert decision.runtime_family == "copilot"
    assert decision.state == "supported"
    assert decision.metadata["install_key_program"] == "copilot"
    assert guardian_decision.runtime_family == "security-guardian"
    assert guardian_decision.metadata["install_key_program"] == "security_guardian"
    assert guardian_decision.metadata["install_key_prefix"] == "ic_install_security_guardian_"


def test_evaluate_compatibility_returns_supported_for_hermes():
    matrix = initialize_compatibility_matrix()

    decision = evaluate_compatibility(
        matrix,
        runtime_family="hermes",
        version="0.4.0",
    )

    assert decision.runtime_family == "hermes"
    assert decision.state == "supported"
    assert decision.metadata["install_key_program"] == "hermes"
    assert decision.metadata["install_key_prefix"] == "ic_install_hermes_"


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
