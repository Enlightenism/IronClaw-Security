from __future__ import annotations

import pytest

from app.services.integration_installer import (
    build_install_plan,
    install_integration,
    summarize_install_result,
)
from app.services.integration_registry import (
    get_integration,
    initialize_integration_registry,
)


def test_install_integration_dry_run_does_not_change_status():
    registry = initialize_integration_registry()
    record_before = get_integration(registry, "integration-claude-code")
    assert record_before is not None
    assert record_before.status == "planned"

    result = install_integration(
        registry,
        "integration-claude-code",
        dry_run=True,
        requested_by="tester",
    )

    record_after = get_integration(registry, "integration-claude-code")
    assert record_after is not None
    assert record_after.status == "planned"
    assert result.installed is False
    assert result.status_before == "planned"
    assert result.status_after == "planned"
    assert any(step.name == "apply-install" and step.state == "skipped" for step in result.steps)


def test_install_integration_marks_record_active():
    registry = initialize_integration_registry()

    result = install_integration(
        registry,
        "integration-openclaw",
        requested_by="tester",
    )

    record_after = get_integration(registry, "integration-openclaw")
    assert record_after is not None
    assert record_after.status == "active"
    assert result.installed is True
    assert result.status_before == "planned"
    assert result.status_after == "active"
    assert any(step.name == "apply-install" and step.state == "installed" for step in result.steps)


def test_install_integration_raises_for_unknown_integration():
    registry = initialize_integration_registry()

    with pytest.raises(KeyError):
        install_integration(registry, "integration-missing")


def test_build_install_plan_contains_expected_steps():
    registry = initialize_integration_registry()
    record = get_integration(registry, "integration-generic-agent")
    assert record is not None

    plan = build_install_plan(record)

    assert [step["step"] for step in plan] == [
        "resolve-integration",
        "validate-command",
        "prepare-target",
        "apply-install",
    ]


def test_summarize_install_result_returns_expected_shape():
    registry = initialize_integration_registry()

    result = install_integration(
        registry,
        "integration-generic-agent",
        requested_by="tester",
    )
    summary = summarize_install_result(result)

    assert summary["integration_id"] == "integration-generic-agent"
    assert summary["slug"] == "generic-agent"
    assert summary["installed"] is True
    assert summary["status_after"] == "active"
    assert summary["step_count"] == len(result.steps)