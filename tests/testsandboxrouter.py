from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from app.runtime.sandboxrouter import build_sandboxrouter


@dataclass(slots=True)
class _Decision:
    verdict: str = "allow"
    allowed: bool = True
    should_review: bool = False
    should_block: bool = False
    should_quarantine: bool = False
    risk_delta: int = 0
    reasons: list[dict[str, Any]] | None = None
    matched_rules: list[str] | None = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = []
        if self.matched_rules is None:
            self.matched_rules = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": self.risk_delta,
            "reasons": list(self.reasons or []),
            "matchedrules": list(self.matched_rules or []),
        }


class _ToolCallGuardStub:
    def __init__(self, decision: _Decision) -> None:
        self.decision = decision
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, *, request: Any) -> _Decision:
        self.calls.append(
            {
                "tool_name": getattr(request, "tool_name", None),
                "actiontype": getattr(request, "actiontype", None),
                "target": getattr(request, "target", None),
                "command": getattr(request, "command", None),
                "network_url": getattr(request, "network_url", None),
                "artifact_paths": list(getattr(request, "artifact_paths", []) or []),
                "cwd": getattr(request, "cwd", None),
                "environment_scope": getattr(request, "environment_scope", None),
                "metadata": dict(getattr(request, "metadata", {}) or {}),
            }
        )
        return self.decision


class _CommandExecutorStub:
    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self.result = result or {"ok": True, "stdout": "done"}
        self.calls: list[dict[str, Any]] = []

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        return dict(self.result)


class _NetworkExecutorStub:
    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self.result = result or {"ok": True, "status_code": 200}
        self.calls: list[dict[str, Any]] = []

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        return dict(self.result)


class _ArtifactExecutorStub:
    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self.result = result or {"ok": True, "artifacts": ["artifacts/report.txt"]}
        self.calls: list[dict[str, Any]] = []

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        return dict(self.result)


@pytest.fixture()
def allow_decision() -> _Decision:
    return _Decision(
        verdict="allow",
        allowed=True,
        risk_delta=5,
        reasons=[
            {
                "source": "toolcallguard",
                "label": "Allowed",
                "details": "Safe tool call.",
                "score": 5,
            }
        ],
        matched_rules=["toolcallguard:allow"],
    )


@pytest.fixture()
def review_decision() -> _Decision:
    return _Decision(
        verdict="review",
        allowed=True,
        should_review=True,
        risk_delta=35,
        reasons=[
            {
                "source": "toolcallguard",
                "label": "Review",
                "details": "Requires analyst review.",
                "score": 35,
            }
        ],
        matched_rules=["toolcallguard:review"],
    )


@pytest.fixture()
def block_decision() -> _Decision:
    return _Decision(
        verdict="block",
        allowed=False,
        should_block=True,
        risk_delta=70,
        reasons=[
            {
                "source": "toolcallguard",
                "label": "Blocked",
                "details": "Unsafe tool call.",
                "score": 70,
            }
        ],
        matched_rules=["toolcallguard:block"],
    )


@pytest.fixture()
def quarantine_decision() -> _Decision:
    return _Decision(
        verdict="quarantine",
        allowed=False,
        should_block=True,
        should_quarantine=True,
        risk_delta=90,
        reasons=[
            {
                "source": "toolcallguard",
                "label": "Quarantined",
                "details": "Severe tool call risk.",
                "score": 90,
            }
        ],
        matched_rules=["toolcallguard:quarantine"],
    )


def _build_router(
    *,
    decision: _Decision,
    command_result: dict[str, Any] | None = None,
    network_result: dict[str, Any] | None = None,
    artifact_result: dict[str, Any] | None = None,
):
    tool_guard = _ToolCallGuardStub(decision)
    command_executor = _CommandExecutorStub(command_result)
    network_executor = _NetworkExecutorStub(network_result)
    artifact_executor = _ArtifactExecutorStub(artifact_result)

    router = build_sandboxrouter(
        toolcallguard=tool_guard,
        command_executor=command_executor,
        network_executor=network_executor,
        artifact_executor=artifact_executor,
    )
    return router, tool_guard, command_executor, network_executor, artifact_executor


def test_route_command_executes_when_allowed(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
        command_result={"ok": True, "stdout": "hello"},
    )

    result = router.route(
        tool_name="bash",
        command="echo hello",
        cwd="/workspace",
        metadata={"request_id": "req-1"},
    )

    assert result["verdict"] == "allow"
    assert result["allowed"] is True
    assert result["executed"] is True
    assert result["channel"] == "command"
    assert result["result"]["stdout"] == "hello"
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 1
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 0


def test_route_network_executes_when_allowed(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
        network_result={"ok": True, "status_code": 204},
    )

    result = router.route(
        tool_name="fetch",
        network_url="https://api.example.com/v1/ping",
        network_method="POST",
        metadata={"request_id": "req-2"},
    )

    assert result["verdict"] == "allow"
    assert result["allowed"] is True
    assert result["executed"] is True
    assert result["channel"] == "network"
    assert result["result"]["status_code"] == 204
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 1
    assert len(artifact_executor.calls) == 0


def test_route_artifact_executes_when_allowed(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
        artifact_result={"ok": True, "artifacts": ["artifacts/output.txt"]},
    )

    result = router.route(
        tool_name="return_file",
        artifact_paths=["artifacts/output.txt"],
        content="safe text",
        metadata={"request_id": "req-3"},
    )

    assert result["verdict"] == "allow"
    assert result["allowed"] is True
    assert result["executed"] is True
    assert result["channel"] == "artifact"
    assert result["result"]["artifacts"] == ["artifacts/output.txt"]
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 1


def test_review_does_not_execute_by_default(review_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=review_decision,
    )

    result = router.route(
        tool_name="bash",
        command="whoami",
        metadata={"request_id": "req-4"},
    )

    assert result["verdict"] == "review"
    assert result["allowed"] is True
    assert result["executed"] is False
    assert result["channel"] == "command"
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 0


def test_review_can_execute_when_explicit_override_enabled(review_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=review_decision,
        command_result={"ok": True, "stdout": "approved"},
    )

    result = router.route(
        tool_name="bash",
        command="echo approved",
        allow_review_execution=True,
        metadata={"request_id": "req-5"},
    )

    assert result["verdict"] == "review"
    assert result["allowed"] is True
    assert result["executed"] is True
    assert result["channel"] == "command"
    assert result["result"]["stdout"] == "approved"
    assert len(command_executor.calls) == 1


def test_block_never_executes(block_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=block_decision,
    )

    result = router.route(
        tool_name="bash",
        command="cat /etc/passwd",
        metadata={"request_id": "req-6"},
    )

    assert result["verdict"] == "block"
    assert result["allowed"] is False
    assert result["executed"] is False
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 0


def test_quarantine_never_executes(quarantine_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=quarantine_decision,
    )

    result = router.route(
        tool_name="fetch",
        network_url="http://169.254.169.254/latest/meta-data",
        metadata={"request_id": "req-7"},
    )

    assert result["verdict"] == "quarantine"
    assert result["allowed"] is False
    assert result["executed"] is False
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 0


def test_prefers_command_channel_when_command_present(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
    )

    result = router.route(
        tool_name="bash",
        command="echo hi",
        network_url="https://api.example.com/v1/ping",
        artifact_paths=["artifacts/out.txt"],
    )

    assert result["channel"] == "command"
    assert result["executed"] is True
    assert len(command_executor.calls) == 1
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 0


def test_uses_network_channel_when_no_command_but_network_present(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
    )

    result = router.route(
        tool_name="fetch",
        network_url="https://example.com/status",
    )

    assert result["channel"] == "network"
    assert result["executed"] is True
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 1
    assert len(artifact_executor.calls) == 0


def test_uses_artifact_channel_when_only_artifacts_present(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
    )

    result = router.route(
        tool_name="return_file",
        artifact_paths=["artifacts/report.txt"],
        content="safe report",
    )

    assert result["channel"] == "artifact"
    assert result["executed"] is True
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 1


def test_defaults_tocontrol_when_no_explicit_payload_channel_exists(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
    )

    result = router.route(
        tool_name="policy_check",
        metadata={"request_id": "req-8"},
    )

    assert result["channel"] == "control"
    assert result["executed"] is False
    assert result["verdict"] == "allow"
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 0
    assert len(network_executor.calls) == 0
    assert len(artifact_executor.calls) == 0


def test_passes_metadata_to_guard_and_executor(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
    )

    metadata = {"request_id": "req-9", "actor": "ironclaw-test"}

    router.route(
        tool_name="bash",
        command="echo metadata",
        cwd="/tmp/work",
        metadata=metadata,
    )

    assert tool_guard.calls[0]["metadata"]["request_id"] == "req-9"
    assert tool_guard.calls[0]["metadata"]["actor"] == "ironclaw-test"
    assert command_executor.calls[0]["metadata"]["request_id"] == "req-9"
    assert command_executor.calls[0]["metadata"]["actor"] == "ironclaw-test"
    assert command_executor.calls[0]["cwd"] == "/tmp/work"


def test_passes_network_method_to_executor(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
    )

    router.route(
        tool_name="fetch",
        network_url="https://api.example.com/v1/items",
        network_method="DELETE",
        metadata={"request_id": "req-10"},
    )

    assert network_executor.calls[0]["url"] == "https://api.example.com/v1/items"
    assert network_executor.calls[0]["method"] == "DELETE"


def test_passes_artifact_payload_to_executor(allow_decision):
    router, tool_guard, command_executor, network_executor, artifact_executor = _build_router(
        decision=allow_decision,
    )

    router.route(
        tool_name="return_file",
        artifact_paths=["artifacts/one.txt", "artifacts/two.txt"],
        content="artifact body",
        metadata={"request_id": "req-11"},
    )

    assert artifact_executor.calls[0]["artifact_paths"] == ["artifacts/one.txt", "artifacts/two.txt"]
    assert artifact_executor.calls[0]["content"] == "artifact body"


def test_executor_exception_is_captured_as_failed_execution(allow_decision):
    class _ExplodingCommandExecutor:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def execute(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append(dict(kwargs))
            raise RuntimeError("executor exploded")

    tool_guard = _ToolCallGuardStub(allow_decision)
    command_executor = _ExplodingCommandExecutor()
    network_executor = _NetworkExecutorStub()
    artifact_executor = _ArtifactExecutorStub()

    router = build_sandboxrouter(
        toolcallguard=tool_guard,
        command_executor=command_executor,
        network_executor=network_executor,
        artifact_executor=artifact_executor,
    )

    result = router.route(
        tool_name="bash",
        command="echo boom",
        metadata={"request_id": "req-12"},
    )

    assert result["verdict"] in {"error", "block"}
    assert result["allowed"] is False
    assert result["executed"] is False
    assert "executor exploded" in str(result["error"]).lower()
    assert len(tool_guard.calls) == 1
    assert len(command_executor.calls) == 1


def test_allow_helper_reflects_route_allowed_state(allow_decision):
    router, _, _, _, _ = _build_router(decision=allow_decision)

    assert router.allow(
        tool_name="bash",
        command="echo ok",
        metadata={"request_id": "req-13"},
    ) is True


def test_allow_helper_returns_false_for_block(block_decision):
    router, _, _, _, _ = _build_router(decision=block_decision)

    assert router.allow(
        tool_name="bash",
        command="rm -rf /",
        metadata={"request_id": "req-14"},
    ) is False


def test_route_result_contains_expected_shapes(allow_decision):
    router, _, _, _, _ = _build_router(decision=allow_decision)

    result = router.route(
        tool_name="bash",
        command="echo shape",
        metadata={"request_id": "req-15"},
    )

    assert isinstance(result, dict)
    assert result["tool_name"] == "bash"
    assert result["channel"] == "command"
    assert "policy" in result
    assert "reasons" in result
    assert "matchedrules" in result
    assert isinstance(result["reasons"], list)
    assert isinstance(result["matchedrules"], list)