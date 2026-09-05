from __future__ import annotations

import pytest

from app.services.integration_registry import (
    IntegrationCapability,
    IntegrationRecord,
    default_integrations,
    get_integration,
    initialize_integration_registry,
    list_integrations,
    register_integration,
    summarize_integration_registry,
    update_integration_status,
)
from app.ui.integrations.adapters import build_integration_adapters_view
from app.ui.integrations.coverage import build_integration_coverage_view
from app.ui.integrations.dependencies import build_integration_dependencies_view
from app.ui.integrations.matrix import build_integration_matrix_view


def _make_record(
    *,
    integration_id: str = "integration-test-slack",
    name: str = "Slack Adapter",
    slug: str = "slack",
    platform: str = "slack",
) -> IntegrationRecord:
    return IntegrationRecord(
        integration_id=integration_id,
        name=name,
        slug=slug,
        platform=platform,
        integration_type="adapter",
        status="planned",
        version="1.0.0",
        command_name="ironclaw install slack",
        description="Slack integration for guarded agent workflows.",
        entrypoint="app.adapters.slack_adapter",
        install_target="local",
        capabilities=[
            IntegrationCapability(
                name="tool_interception",
                enabled=True,
                details="Intercept tool calls before execution.",
            ),
            IntegrationCapability(
                name="telemetry",
                enabled=True,
                details="Emit telemetry for integration events.",
            ),
        ],
        metadata={
            "priority": 10,
            "one_command_install": True,
        },
    )


def test_default_integrations_returns_expected_seed_data():
    records = default_integrations()

    expected_slugs = {
        "claude-code",
        "openclaw",
        "generic-agent",
        "cursor",
        "goose",
        "gemini-cli",
        "copilot",
        "security-guardian",
        "hermes",
    }
    platform_by_slug = {record.slug: record.platform for record in records}
    modern_runtime_matrix = {
        "cursor": "cursor",
        "goose": "goose",
        "gemini-cli": "gemini-cli",
        "copilot": "copilot",
        "security-guardian": "security-guardian",
        "hermes": "hermes",
    }

    assert len(records) >= len(expected_slugs)
    assert {record.slug for record in records} >= expected_slugs
    assert {slug for slug in modern_runtime_matrix if platform_by_slug.get(slug) == modern_runtime_matrix[slug]} == set(modern_runtime_matrix)
    assert platform_by_slug["hermes"] == "hermes"
    assert platform_by_slug["cursor"] == "cursor"
    assert platform_by_slug["goose"] == "goose"
    assert platform_by_slug["gemini-cli"] == "gemini-cli"
    assert platform_by_slug["copilot"] == "copilot"
    assert platform_by_slug["security-guardian"] == "security-guardian"
    assert any(record.slug == "hermes" and record.platform == "hermes" and record.entrypoint == "app.adapters.hermes_adapter" for record in records)
    assert all(record.integration_id for record in records)
    assert all(record.integration_type in {"adapter", "native", "cli", "remote"} for record in records)


def test_initialize_integration_registry_populates_items():
    registry = initialize_integration_registry()

    assert len(registry.items) >= 3
    assert "integration-claude-code" in registry.items
    assert registry.created_at
    assert registry.updated_at


def test_register_and_get_integration_round_trip():
    registry = initialize_integration_registry()
    record = _make_record()

    register_integration(registry, record)
    stored = get_integration(registry, record.integration_id)

    assert stored is not None
    assert stored.integration_id == record.integration_id
    assert stored.slug == "slack"
    assert stored.platform == "slack"
    assert stored.command_name == "ironclaw install slack"


def test_register_integration_rejects_missing_required_fields():
    registry = initialize_integration_registry()

    with pytest.raises(ValueError, match="integration_id is required"):
        register_integration(
            registry,
            _make_record(integration_id=""),
        )

    with pytest.raises(ValueError, match="slug is required"):
        register_integration(
            registry,
            _make_record(integration_id="integration-missing-slug", slug=""),
        )

    with pytest.raises(ValueError, match="name is required"):
        register_integration(
            registry,
            _make_record(integration_id="integration-missing-name", name=""),
        )


def test_register_integration_rejects_duplicate_id():
    registry = initialize_integration_registry()
    record = _make_record()

    register_integration(registry, record)

    with pytest.raises(ValueError, match=f"integration already registered: {record.integration_id}"):
        register_integration(registry, _make_record(integration_id=record.integration_id, slug="slack-2"))


def test_list_integrations_supports_status_platform_and_capability_filters():
    registry = initialize_integration_registry()

    active_record = _make_record(
        integration_id="integration-slack-active",
        slug="slack-active",
        name="Slack Active Adapter",
        platform="slack",
    )
    active_record.status = "active"

    disabled_record = _make_record(
        integration_id="integration-github-disabled",
        slug="github-disabled",
        name="GitHub Disabled Adapter",
        platform="github",
    )
    disabled_record.status = "disabled"
    disabled_record.capabilities = [
        IntegrationCapability(
            name="audit_export",
            enabled=False,
            details="Disabled audit export capability.",
        ),
    ]

    register_integration(registry, active_record)
    register_integration(registry, disabled_record)

    active_results = list_integrations(registry, status="active")
    assert any(record.integration_id == "integration-slack-active" for record in active_results)

    platform_results = list_integrations(registry, platform="github")
    assert len(platform_results) == 1
    assert platform_results[0].integration_id == "integration-github-disabled"

    capability_results = list_integrations(registry, capability="tool_interception")
    assert any(record.integration_id == "integration-slack-active" for record in capability_results)
    assert all(any(cap.name == "tool_interception" and cap.enabled for cap in record.capabilities) for record in capability_results)


def test_update_integration_status_changes_record_and_registry_timestamp():
    registry = initialize_integration_registry()
    record = _make_record()
    register_integration(registry, record)

    previous_registry_updated_at = registry.updated_at

    updated = update_integration_status(registry, record.integration_id, "active")

    assert updated.status == "active"
    assert updated.updated_at
    assert registry.updated_at >= previous_registry_updated_at


def test_update_integration_status_raises_for_unknown_id():
    registry = initialize_integration_registry()

    with pytest.raises(KeyError, match="unknown integration_id: integration-missing"):
        update_integration_status(registry, "integration-missing", "active")


def test_summarize_integration_registry_returns_expected_aggregates():
    registry = initialize_integration_registry()
    register_integration(
        registry,
        _make_record(
            integration_id="integration-slack-summary",
            slug="slack-summary",
            name="Slack Summary Adapter",
            platform="slack",
        ),
    )

    summary = summarize_integration_registry(registry)

    assert summary["total_integrations"] >= 4
    assert "platforms" in summary
    assert "capabilities" in summary
    assert "one_command_ready_targets" in summary
    assert "claude-code" in summary["one_command_ready_targets"]
    assert "slack-summary" in summary["one_command_ready_targets"]


def test_build_integration_adapters_view_tracks_supported_runtime_cards_and_install_key_model():
    registry = initialize_integration_registry()

    view = build_integration_adapters_view(registry=registry)
    payload = view.to_dict()

    supported_runtime_cards = payload["metadata"]["supported_runtime_cards"]
    supported_runtime_programs = {card["install_key_program"] for card in supported_runtime_cards}

    assert {
        "claude_code",
        "openclaw",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "hermes",
    } <= supported_runtime_programs
    assert "security_guardian" not in supported_runtime_programs

    assert any(item["slug"] == "hermes" and item["install_key_program"] == "hermes" for item in payload["items"])
    assert any(item["slug"] == "security-guardian" and item["shared_install_key_family"] for item in payload["items"])

    assert any(item["capability_pills"] for item in payload["items"])
    assert all(item["platform_cards"] for item in payload["items"])
    assert all(item["install_key_program"] or item["install_key_program"] is None for item in payload["items"])


def test_build_integration_coverage_view_tracks_install_key_rollout_status():
    registry = initialize_integration_registry()
    record = _make_record(
        integration_id="integration-rollout-cursor",
        slug="rollout-cursor",
        name="Rollout Cursor Adapter",
        platform="cursor",
    )
    record.status = "active"
    record.metadata["install_key_program"] = "cursor"
    register_integration(registry, record)

    view = build_integration_coverage_view(registry=registry)
    payload = view.to_dict()
    item = next(item for item in payload["items"] if item["integration_id"] == "integration-rollout-cursor")

    assert item["install_key_program"] == "cursor"
    assert item["rollout_status"] == "available"
    assert item["available"] is True
    assert item["install_key_family"] == "cursor"


def test_build_integration_dependencies_view_links_platforms_to_key_family_and_installer_path():
    registry = initialize_integration_registry()
    record = _make_record(
        integration_id="integration-deps-cursor",
        slug="deps-cursor",
        name="Cursor Dependency Adapter",
        platform="cursor",
    )
    record.install_target = "local"
    record.metadata["installer_path"] = "local"
    record.metadata["install_key_program"] = "cursor"
    register_integration(registry, record)

    view = build_integration_dependencies_view(registry=registry)
    payload = view.to_dict()
    item = next(item for item in payload["items"] if item["integration_id"] == "integration-deps-cursor")

    assert item["install_key_program"] == "cursor"
    assert item["install_key_family"] == "cursor"
    assert item["installer_path"] == "local"
    assert "cursor" in item["install_key_aliases"]
    assert item["metadata"]["install_key_program"] == "cursor"
    assert item["metadata"]["installer_path"] == "local"


def test_build_integration_matrix_view_tracks_install_key_registry_and_skill_package_model():
    registry = initialize_integration_registry()
    record = _make_record(
        integration_id="integration-matrix-skill",
        slug="matrix-skill",
        name="Skill Package Matrix Adapter",
        platform="security-guardian",
    )
    record.install_target = "local"
    record.metadata["installer_path"] = "local"
    record.metadata["runtime"] = "skill"
    register_integration(registry, record)

    view = build_integration_matrix_view(registry=registry)
    payload = view.to_dict()
    item = next(item for item in payload["items"] if item["integration_id"] == "integration-matrix-skill")

    assert item["install_key_program"] == "security_guardian"
    assert item["install_key_family"] == "security_guardian"
    assert item["installer_path"] == "local"
    assert item["shared_install_key_family"] is True
    assert "skill" not in item["install_key_aliases"]
    assert item["metadata"]["install_key_program"] == "security_guardian"
    assert item["metadata"]["platform_aliases"] == []
