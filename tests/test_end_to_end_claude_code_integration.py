from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.adapters.claude_code_adapter import ClaudeCodeAdapter, build_claude_code_adapter
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
    app.include_router(integrations_router)
    return TestClient(app)


def test_end_to_end_claude_code_registry_install_and_verify():
    # 1. Initialize registry and confirm Claude Code integration is present as planned.
    registry = initialize_integration_registry()
    record = get_integration(registry, "integration-claude-code")

    assert record is not None
    assert record.slug == "claude-code"
    assert record.platform == "claude-code"
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
        "integration-claude-code",
        dry_run=True,
        requested_by="e2e-test",
    )
    dry_summary = summarize_install_result(dry_result)

    assert dry_summary["integration_id"] == "integration-claude-code"
    assert dry_summary["installed"] is False
    assert dry_summary["status_before"] == "planned"
    assert dry_summary["status_after"] == "blocked"

    # 4. Perform a real install without a valid paid key; the payment gate blocks activation.
    real_result = install_integration(
        registry,
        "integration-claude-code",
        requested_by="e2e-test",
    )
    real_summary = summarize_install_result(real_result)

    assert real_summary["integration_id"] == "integration-claude-code"
    assert real_summary["installed"] is False
    assert real_summary["status_after"] == "blocked"

    record_after = get_integration(registry, "integration-claude-code")
    assert record_after is not None
    assert record_after.status == "planned"

    # 5. Verify the integration in non-strict mode; should pass with possible warnings.
    verify_result = verify_integration(
        registry,
        "integration-claude-code",
        requested_by="e2e-test",
        strict=False,
    )
    verify_summary = summarize_verification_result(verify_result)

    assert verify_summary["integration_id"] == "integration-claude-code"
    assert verify_summary["verified"] is True
    assert verify_summary["fail_count"] == 0
    assert verify_summary["pass_count"] >= 1

    # 6. Exercise the adapter handshake/manifest/execute end-to-end.
    adapter = build_claude_code_adapter(registry)
    assert isinstance(adapter, ClaudeCodeAdapter)

    handshake = adapter.handshake()
    assert handshake.adapter_slug == "claude-code"
    assert handshake.platform == "claude-code"
    assert handshake.status == "ready"
    assert handshake.metadata["integration_id"] == "integration-claude-code"

    manifest = adapter.manifest()
    assert manifest.slug == "claude-code"
    assert manifest.platform == "claude-code"
    assert manifest.metadata["runtime"] == "claude-code"

    from app.adapters.base import AdapterExecutionRequest  # local import to avoid cycles

    exec_result = adapter.execute(
        AdapterExecutionRequest(
            action_type="toolcall",
            target="local-http://127.0.0.1/claude-code/run",
            payload={
                "prompt": "Summarize the project structure.",
                "tool_name": "http.post",
            },
        ),
    )

    assert exec_result.adapter_slug == "claude-code"
    assert exec_result.platform == "claude-code"
    assert exec_result.success is True
    assert exec_result.status == "accepted"
    assert exec_result.metadata["runtime"] == "claude-code"
    assert exec_result.output["guard_applied"] is True
    assert exec_result.output["request"]["action_type"] == "toolcall"


def test_end_to_end_claude_code_cli_install_and_verify(monkeypatch, capsys):
    # 1. Run CLI list to make sure Claude Code appears as an available integration.
    exit_code = run_cli(["list"])
    assert exit_code == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["total"] >= 1
    assert any(item["slug"] == "claude-code" for item in payload["items"])

    # 2. Run CLI install in dry-run mode.
    exit_code = run_cli(
        ["install", "integration-claude-code", "--dry-run", "--requested-by", "e2e-cli"],
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    install_payload = json.loads(captured.out)

    assert install_payload["integration_id"] == "integration-claude-code"
    assert install_payload["installed"] is False
    assert install_payload["status_before"] == "planned"
    assert install_payload["status_after"] == "blocked"

    # 3. Run CLI verify in non-strict mode after dry-run.
    exit_code = run_cli(
        ["verify", "integration-claude-code", "--requested-by", "e2e-cli"],
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    verify_payload = json.loads(captured.out)

    assert verify_payload["integration_id"] == "integration-claude-code"
    assert verify_payload["verified"] is True
    assert verify_payload["warn_count"] >= 0

    # 4. Run CLI verify in strict mode; we only assert that it returns a structured summary.
    exit_code = run_cli(
        ["verify", "integration-claude-code", "--strict", "--requested-by", "e2e-cli"],
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    strict_payload = json.loads(captured.out)

    assert strict_payload["integration_id"] == "integration-claude-code"
    assert "verified" in strict_payload
    assert "fail_count" in strict_payload
