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

    assert len(records) >= 3
    assert any(record.slug == "claude-code" for record in records)
    assert any(record.slug == "openclaw" for record in records)
    assert any(record.slug == "generic-agent" for record in records)
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
