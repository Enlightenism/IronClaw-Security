from __future__ import annotations

from app.services.adapter_manifest import build_adapter_manifest, summarize_adapter_manifest
from app.services.integration_registry import IntegrationCapability, IntegrationRecord


def _make_record() -> IntegrationRecord:
    return IntegrationRecord(
        integration_id="int_123",
        slug="slack",
        platform="slack",
        name="Slack",
        integration_type="adapter",
        version="2.4.1",
        command_name="ironclaw-slack",
        entrypoint="app.adapters.slack:main",
        install_target="pip install ironclaw-slack",
        capabilities=[
            IntegrationCapability(
                name="prompt_interception",
                enabled=True,
                details="Dispatch security alerts to Slack channels.",
            ),
            IntegrationCapability(
                name="telemetry",
                enabled=True,
                details="Enumerate available destination channels.",
            ),
        ],
        metadata={
            "category": "communications",
            "supports_oauth": True,
        },
    )


def test_build_adapter_manifest_maps_record_fields() -> None:
    record = _make_record()

    manifest = build_adapter_manifest(record)

    assert manifest.manifest_version == "1.0.0"
    assert manifest.integration_id == record.integration_id
    assert manifest.slug == record.slug
    assert manifest.platform == record.platform
    assert manifest.name == record.name
    assert manifest.version == record.version
    assert manifest.command_name == record.command_name
    assert manifest.entrypoint == record.entrypoint
    assert manifest.install_target == record.install_target
    assert manifest.metadata == record.metadata
    assert manifest.generated_at.endswith("+00:00")
    assert len(manifest.capabilities) == 2
    assert manifest.capabilities[0]["name"] == "prompt_interception"
    assert manifest.capabilities[1]["name"] == "telemetry"


def test_build_adapter_manifest_merges_extra_metadata_without_mutating_record() -> None:
    record = _make_record()

    manifest = build_adapter_manifest(
        record,
        manifest_version="1.2.0",
        extra_metadata={"region": "us", "supports_oauth": False},
    )

    assert manifest.manifest_version == "1.2.0"
    assert manifest.metadata == {
        "category": "communications",
        "supports_oauth": False,
        "region": "us",
    }
    assert record.metadata == {
        "category": "communications",
        "supports_oauth": True,
    }


def test_adapter_manifest_to_dict_returns_serializable_payload() -> None:
    record = _make_record()

    manifest = build_adapter_manifest(record)
    payload = manifest.to_dict()

    assert payload["manifest_version"] == "1.0.0"
    assert payload["integration_id"] == "int_123"
    assert payload["slug"] == "slack"
    assert payload["platform"] == "slack"
    assert payload["name"] == "Slack"
    assert payload["version"] == "2.4.1"
    assert payload["command_name"] == "ironclaw-slack"
    assert payload["entrypoint"] == "app.adapters.slack:main"
    assert payload["install_target"] == "pip install ironclaw-slack"
    assert payload["metadata"]["category"] == "communications"
    assert payload["capabilities"][0]["name"] == "prompt_interception"
    assert payload["capabilities"][1]["details"] == "Enumerate available destination channels."


def test_summarize_adapter_manifest_returns_compact_summary() -> None:
    record = _make_record()
    manifest = build_adapter_manifest(record)

    summary = summarize_adapter_manifest(manifest)

    assert summary == {
        "manifest_version": manifest.manifest_version,
        "integration_id": "int_123",
        "slug": "slack",
        "platform": "slack",
        "version": "2.4.1",
        "capability_count": 2,
        "generated_at": manifest.generated_at,
    }