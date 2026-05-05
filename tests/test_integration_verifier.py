from __future__ import annotations

import pytest

from app.services.integration_registry import initialize_integration_registry
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)


def test_verify_integration_warns_when_planned_not_strict():
    registry = initialize_integration_registry()

    result = verify_integration(
        registry,
        "integration-claude-code",
        requested_by="tester",
        strict=False,
    )

    assert result.integration_id == "integration-claude-code"
    assert result.verified is True
    assert any(check.name == "status-active" and check.state == "warn" for check in result.checks)


def test_verify_integration_fails_when_planned_and_strict():
    registry = initialize_integration_registry()

    result = verify_integration(
        registry,
        "integration-openclaw",
        requested_by="tester",
        strict=True,
    )

    assert result.integration_id == "integration-openclaw"
    assert result.verified is False
    assert any(check.name == "status-active" and check.state == "fail" for check in result.checks)


def test_verify_integration_raises_for_unknown_integration():
    registry = initialize_integration_registry()

    with pytest.raises(KeyError):
        verify_integration(registry, "integration-missing")


def test_summarize_verification_result_returns_expected_counts():
    registry = initialize_integration_registry()

    result = verify_integration(
        registry,
        "integration-generic-agent",
        strict=False,
    )
    summary = summarize_verification_result(result)

    assert summary["integration_id"] == "integration-generic-agent"
    assert summary["slug"] == "generic-agent"
    assert summary["platform"] == "generic"
    assert summary["warn_count"] >= 1
    assert summary["pass_count"] >= 1
    assert summary["fail_count"] == 0