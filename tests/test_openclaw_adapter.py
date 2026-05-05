from __future__ import annotations

from app.adapters.base import AdapterExecutionRequest
from app.adapters.openclaw_adapter import OpenClawAdapter, build_openclaw_adapter
from app.services.integration_registry import initialize_integration_registry


def test_build_openclaw_adapter_returns_expected_adapter():
    registry = initialize_integration_registry()

    adapter = build_openclaw_adapter(registry)

    assert isinstance(adapter, OpenClawAdapter)
    assert adapter.record.integration_id == "integration-openclaw"
    assert adapter.record.slug == "openclaw"
    assert adapter.record.platform == "openclaw"


def test_openclaw_adapter_handshake_contains_expected_metadata():
    registry = initialize_integration_registry()
    adapter = build_openclaw_adapter(registry)

    handshake = adapter.handshake()

    assert handshake.adapter_slug == "openclaw"
    assert handshake.platform == "openclaw"
    assert handshake.status == "ready"
    assert handshake.metadata["integration_id"] == "integration-openclaw"
    assert handshake.metadata["runtime"] == "openclaw"
    assert handshake.metadata["workflow_mode"] == "builder-guard"


def test_openclaw_adapter_manifest_includes_adapter_metadata():
    registry = initialize_integration_registry()
    adapter = build_openclaw_adapter(registry)

    manifest = adapter.manifest()

    assert manifest.slug == "openclaw"
    assert manifest.platform == "openclaw"
    assert manifest.metadata["runtime"] == "openclaw"
    assert manifest.metadata["workflow_mode"] == "builder-guard"


def test_openclaw_adapter_execute_returns_guarded_result():
    registry = initialize_integration_registry()
    adapter = build_openclaw_adapter(registry)

    result = adapter.execute(
        AdapterExecutionRequest(
            action_type="workflow",
            target="workspace://openclaw/pipeline",
            payload={"step": "toolchain-build", "policy_gate": True},
        )
    )

    assert result.adapter_slug == "openclaw"
    assert result.platform == "openclaw"
    assert result.success is True
    assert result.status == "guarded"
    assert result.metadata["runtime"] == "openclaw"
    assert result.output["guard_applied"] is True
    assert result.output["execution_mode"] == "workflow-gated"
    assert result.output["request"]["action_type"] == "workflow"