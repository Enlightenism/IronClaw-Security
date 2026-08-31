from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.adapters.openclaw_adapter import OpenClawAdapter, build_openclaw_adapter
from app.api.integrations import router as integrations_router
from app.cli.main import run_cli
from app.main import create_app
from app.services.integration_installer import (
    build_install_plan,
    install_integration,
    summarize_install_result,
)
from app.services.integration_registry import (
    get_integration,
    initialize_integration_registry,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)


def _client() -> TestClient:
    app = create_app()
    # Defensively include integrations router; main should already do this.
    app.include_router(integrations_router)
    return TestClient(app)


def test_end_to_end_openclaw_registry_install_and_verify():
    # 1. Initialize registry and confirm OpenClaw integration is present as planned.
    registry = initialize_integration_registry()
    record = get_integration(registry, "integration-openclaw")

    assert record is not None
    assert record.slug == "openclaw"
    assert record.platform == "openclaw"
    assert record.status == "planned"

    # 2. Build an install plan to verify the one-command installer steps are wired.
    plan = build_install_plan(record)
    assert [step["step"] for step in plan] == [
        "resolve-integration",
        "validate-command",
        "prepare-target",
        "validate-paid-install-key",
        "apply-install",
    ]

    # 3. Perform a dry-run install without a valid paid key; status must remain blocked.
    dry_result = install_integration(
        registry,
        "integration-openclaw",
        dry_run=True,
        requested_by="e2e-test",
    )
    dry_summary = summarize_install_result(dry_result)

    assert dry_summary["integration_id"] == "integration-openclaw"
    assert dry_summary["installed"] is False
    assert dry_summary["status_before"] == "planned"
    assert dry_summary["status_after"] == "blocked"

    # 4. Perform a real install without a valid paid key; the payment gate blocks activation.
    real_result = install_integration(
        registry,
        "integration-openclaw",
        requested_by="e2e-test",
    )
    real_summary = summarize_install_result(real_result)

    assert real_summary["integration_id"] == "integration-openclaw"
    assert real_summary["installed"] is False
    assert real_summary["status_after"] == "blocked"

    record_after = get_integration(registry, "integration-openclaw")
    assert record_after is not None
    assert record_after.status == "planned"

    # 5. Verify the integration in non-strict mode; should pass with possible warnings.
    verify_result = verify_integration(
        registry,
        "integration-openclaw",
        requested_by="e2e-test",
        strict=False,
    )
    verify_summary = summarize_verification_result(verify_result)

    assert verify_summary["integration_id"] == "integration-openclaw"
    assert verify_summary["verified"] is True
    assert verify_summary["fail_count"] == 0
    assert verify_summary["pass_count"] >= 1

    # 6. Exercise the adapter handshake/manifest/execute end-to-end.
    adapter = build_openclaw_adapter(registry)
    assert isinstance(adapter, OpenClawAdapter)

    handshake = adapter.handshake()
    assert handshake.adapter_slug == "openclaw"
    assert handshake.platform == "openclaw"
    assert handshake.status == "ready"
    assert handshake.metadata["integration_id"] == "integration-openclaw"

    manifest = adapter.manifest()
    assert manifest.slug == "openclaw"
    assert manifest.platform == "openclaw"
    assert manifest.metadata["runtime"] == "openclaw"

    from app.adapters.base import AdapterExecutionRequest  # local import to avoid cycles

    exec_result = adapter.execute(
        AdapterExecutionRequest(
            action_type="toolcall",
            target="openclaw://builder/plan",
            payload={
                "prompt": "Generate a guarded execution plan.",
                "tool_name": "openclaw.builder.plan",
            },
        ),
    )

    assert exec_result.adapter_slug == "openclaw"
    assert exec_result.platform == "openclaw"
    assert exec_result.success is True
    assert exec_result.status == "guarded"
    assert exec_result.metadata["runtime"] == "openclaw"
    assert exec_result.output["guard_applied"] is True
    assert exec_result.output["request"]["action_type"] == "toolcall"


def test_openclaw_route_reinforces_canonical_runtime_contract(monkeypatch):
    registry = initialize_integration_registry()
    record = get_integration(registry, "integration-openclaw")
    drifted_adapter = OpenClawAdapter(
        record=record,
        metadata={"runtime": "hermes", "workflow_mode": "loose"},
    )
    monkeypatch.setattr("app.routes.integrations.openclaw._build_adapter", lambda: drifted_adapter)

    client = _client()
    handshake = client.post(
        "/integrations/openclaw/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "benchmark-client",
            "protocol_version": "1.0.0",
            "builder_id": "builder-42",
            "metadata": {"environment": "test"},
        },
    )

    assert handshake.status_code == 200, handshake.text
    payload = handshake.json()
    assert payload["platform"] == "openclaw"
    assert payload["adapter_name"] == "ironclaw-openclaw"
    assert payload["metadata"]["runtime"] == "openclaw"
    assert payload["metadata"]["workflow_mode"] == "builder-guard"


def test_openclaw_route_contract_handshake_manifest_and_secret_scan_gate():
    client = _client()

    handshake = client.post(
        "/integrations/openclaw/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "benchmark-client",
            "protocol_version": "1.0.0",
            "builder_id": "builder-42",
            "metadata": {"environment": "test"},
        },
    )
    assert handshake.status_code == 200, handshake.text
    payload = handshake.json()
    assert payload["status"] == "ok"
    assert payload["platform"] == "openclaw"
    assert payload["adapter_name"] == "ironclaw-openclaw"
    assert any(cap["name"] == "secret-scan" for cap in payload["capabilities"])
    assert payload["metadata"]["handshake_status"] == "guarded"

    manifest = client.get("/integrations/openclaw/manifest", headers={"X-API-Key": "test-api-key"})
    assert manifest.status_code == 200, manifest.text
    manifest_payload = manifest.json()
    assert manifest_payload["platform"] == "openclaw"
    assert manifest_payload["adapter_name"] == "ironclaw-openclaw"
    assert "workflow_step" in manifest_payload["supported_action_types"]
    assert any(cap["name"] == "audit-trail" for cap in manifest_payload["capabilities"])

    evaluate = client.post(
        "/integrations/openclaw/evaluate",
        headers={"X-API-Key": "test-api-key"},
        json={
            "action_type": "workflow_step",
            "target": "deploy-pipeline",
            "content": "AKIA1234567890EXAMPLE secret token",
            "builder_id": "builder-42",
            "workflow_id": "wf-42",
            "client_id": "benchmark-client",
            "session_id": "session-42",
            "risk_score": 30,
            "metadata": {"tenant": "alpha"},
        },
    )
    assert evaluate.status_code == 200, evaluate.text
    evaluate_payload = evaluate.json()
    assert evaluate_payload["verdict"] == "block"
    assert evaluate_payload["should_block"] is True
    assert evaluate_payload["should_hold"] is True
    assert evaluate_payload["secret_scan"]["scanned"] is True
    assert evaluate_payload["secret_scan"]["findings"]
    assert evaluate_payload["audit_trail"]["secret_scan_triggered"] is True
    assert evaluate_payload["audit_trail"]["metadata"]["tenant"] == "alpha"


def test_end_to_end_openclaw_cli_install_and_verify(capsys):
    # 1. Run CLI list to make sure OpenClaw appears as an available integration.
    exit_code = run_cli(["list"])
    assert exit_code == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["total"] >= 1
    assert any(item["slug"] == "openclaw" for item in payload["items"])

    # 2. Run CLI install in dry-run mode.
    exit_code = run_cli(
        ["install", "integration-openclaw", "--dry-run", "--requested-by", "e2e-cli"],
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    install_payload = json.loads(captured.out)

    assert install_payload["integration_id"] == "integration-openclaw"
    assert install_payload["installed"] is False
    assert install_payload["status_before"] == "planned"
    assert install_payload["status_after"] == "blocked"

    # 3. Run CLI install in real mode; without a valid paid key it stays blocked.
    exit_code = run_cli(
        ["install", "integration-openclaw", "--requested-by", "e2e-cli"],
    )
    assert exit_code == 1

    captured = capsys.readouterr()
    real_install_payload = json.loads(captured.out)

    assert real_install_payload["integration_id"] == "integration-openclaw"
    assert real_install_payload["installed"] is False
    assert real_install_payload["status_after"] == "blocked"

    # 4. Run CLI verify in non-strict mode after the blocked install state.
    exit_code = run_cli(
        ["verify", "integration-openclaw", "--requested-by", "e2e-cli"],
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    verify_payload = json.loads(captured.out)

    assert verify_payload["integration_id"] == "integration-openclaw"
    assert verify_payload["verified"] is True
    assert verify_payload["warn_count"] >= 0

    # 5. Run CLI verify in strict mode; we only assert that it returns a structured summary.
    exit_code = run_cli(
        ["verify", "integration-openclaw", "--strict", "--requested-by", "e2e-cli"],
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    strict_payload = json.loads(captured.out)

    assert strict_payload["integration_id"] == "integration-openclaw"
    assert "verified" in strict_payload
    assert "fail_count" in strict_payload
