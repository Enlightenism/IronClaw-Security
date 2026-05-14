from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.runtime.toolcallguard import ToolCallRequest, build_toolcallguard


@dataclass(slots=True)
class _Policy:
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


class _CommandSupervisorStub:
    def __init__(self, policy: _Policy | None = None) -> None:
        self.policy = policy or _Policy()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _Policy:
        self.calls.append(dict(kwargs))
        return self.policy


class _NetworkGuardStub:
    def __init__(self, policy: _Policy | None = None) -> None:
        self.policy = policy or _Policy()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _Policy:
        self.calls.append(dict(kwargs))
        return self.policy


class _FileReturnGuardStub:
    def __init__(self, policies: list[_Policy] | None = None) -> None:
        self.policies = list(policies or [_Policy()])
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _Policy:
        self.calls.append(dict(kwargs))
        if self.policies:
            return self.policies.pop(0)
        return _Policy()


def _build_guard(
    *,
    command_policy: _Policy | None = None,
    network_policy: _Policy | None = None,
    artifact_policies: list[_Policy] | None = None,
):
    command_supervisor = _CommandSupervisorStub(command_policy)
    network_guard = _NetworkGuardStub(network_policy)
    file_return_guard = _FileReturnGuardStub(artifact_policies)
    guard = build_toolcallguard(
        command_supervisor=command_supervisor,
        network_guard=network_guard,
        file_return_guard=file_return_guard,
    )
    return guard, command_supervisor, network_guard, file_return_guard


def test_allow_safe_command_request():
    command_policy = _Policy(
        verdict="allow",
        allowed=True,
        risk_delta=5,
        reasons=[{"source": "commandsupervisor", "label": "Safe", "details": "Safe command.", "score": 5}],
        matched_rules=["commandsupervisor:allow"],
    )
    guard, command_supervisor, network_guard, file_return_guard = _build_guard(command_policy=command_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="bash",
            command="echo hello",
            cwd="/workspace",
            metadata={"request_id": "req-1"},
        ),
    )

    assert decision.allowed is True
    assert decision.verdict == "allow"
    assert decision.tool_name == "bash"
    assert decision.actiontype == "toolcall"
    assert decision.target == "runtime"
    assert decision.risk_delta == 30
    assert "toolcallguard:high_risk:bash" in decision.matched_rules
    assert "commandsupervisor:allow" in decision.matched_rules
    assert len(command_supervisor.calls) == 1
    assert len(network_guard.calls) == 0
    assert len(file_return_guard.calls) == 0


def test_normalizes_request_fields_before_evaluation():
    command_policy = _Policy(risk_delta=0)
    guard, command_supervisor, _, _ = _build_guard(command_policy=command_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="  BASH  ",
            actiontype="  EXECUTE  ",
            target="  RUNTIME  ",
            command="echo hi",
            cwd=" /tmp/run ",
            environment_scope="  sandbox  ",
            metadata={"trace": "abc"},
        ),
    )

    assert decision.tool_name == "bash"
    assert decision.actiontype == "execute"
    assert decision.target == "runtime"
    assert command_supervisor.calls[0]["cwd"] == "/tmp/run"
    assert command_supervisor.calls[0]["metadata"]["environment_scope"] == "sandbox"
    assert command_supervisor.calls[0]["metadata"]["tool_name"] == "bash"


def test_missing_tool_name_quarantines():
    guard, command_supervisor, network_guard, file_return_guard = _build_guard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="",
            command=None,
        ),
    )

    assert decision.allowed is False
    assert decision.verdict == "quarantine"
    assert decision.should_quarantine is True
    assert decision.should_block is True
    assert "toolcallguard:missing_tool_name" in decision.matched_rules
    assert len(command_supervisor.calls) == 0
    assert len(network_guard.calls) == 0
    assert len(file_return_guard.calls) == 0


def test_non_sandbox_scope_triggers_review_or_block():
    guard, _, _, _ = _build_guard(
        command_policy=_Policy(
            verdict="allow",
            allowed=True,
            risk_delta=0,
            matched_rules=["commandsupervisor:allow"],
        ),
    )

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="bash",
            command="echo hi",
            environment_scope="host",
        ),
    )

    assert decision.verdict in {"review", "block", "quarantine"}
    assert "toolcallguard:non_sandbox_scope" in decision.matched_rules


def test_missing_command_for_command_tool_raises_risk():
    command_policy = _Policy(
        verdict="allow",
        allowed=True,
        risk_delta=0,
        matched_rules=["commandsupervisor:allow"],
    )
    guard, command_supervisor, _, _ = _build_guard(command_policy=command_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="bash",
            command=None,
        ),
    )

    assert decision.verdict in {"review", "block", "quarantine"}
    assert "toolcallguard:missing_command" in decision.matched_rules
    assert len(command_supervisor.calls) == 1


def test_missing_network_url_for_network_tool_raises_risk():
    guard, _, _, _ = _build_guard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="fetch",
            network_url=None,
        ),
    )

    assert decision.verdict in {"review", "block", "quarantine"}
    assert "toolcallguard:missing_network_url" in decision.matched_rules


def test_missing_artifact_paths_for_file_tool_raises_risk():
    guard, _, _, _ = _build_guard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="return_file",
            artifact_paths=[],
        ),
    )

    assert decision.verdict in {"review", "block", "quarantine"}
    assert "toolcallguard:missing_artifact_paths" in decision.matched_rules


def test_network_request_invokes_network_guard():
    network_policy = _Policy(
        verdict="allow",
        allowed=True,
        risk_delta=10,
        reasons=[{"source": "networkguard", "label": "Safe", "details": "Safe URL.", "score": 10}],
        matched_rules=["networkguard:allow"],
    )
    guard, command_supervisor, network_guard, file_return_guard = _build_guard(network_policy=network_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="fetch",
            network_url="https://api.example.com/v1/status",
            network_method="POST",
            metadata={"request_id": "req-2"},
        ),
    )

    assert decision.allowed is True
    assert decision.verdict == "allow"
    assert "networkguard:allow" in decision.matched_rules
    assert len(command_supervisor.calls) == 0
    assert len(network_guard.calls) == 1
    assert network_guard.calls[0]["url"] == "https://api.example.com/v1/status"
    assert network_guard.calls[0]["method"] == "POST"
    assert network_guard.calls[0]["metadata"]["direction"] == "egress"
    assert network_guard.calls[0]["metadata"]["tool_name"] == "fetch"
    assert len(file_return_guard.calls) == 0


def test_file_request_invokes_file_return_guard_for_each_artifact():
    artifact_policies = [
        _Policy(
            verdict="allow",
            allowed=True,
            risk_delta=5,
            matched_rules=["filereturnguard:allow:first"],
        ),
        _Policy(
            verdict="review",
            allowed=True,
            should_review=True,
            risk_delta=20,
            matched_rules=["filereturnguard:review:second"],
        ),
    ]
    guard, _, _, file_return_guard = _build_guard(artifact_policies=artifact_policies)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="return_file",
            artifact_paths=["artifacts/one.txt", "artifacts/two.txt"],
            content="safe output",
            metadata={"request_id": "req-3"},
        ),
    )

    assert decision.allowed is True
    assert decision.verdict == "review"
    assert decision.should_review is True
    assert "filereturnguard:allow:first" in decision.matched_rules
    assert "filereturnguard:review:second" in decision.matched_rules
    assert len(file_return_guard.calls) == 2
    assert file_return_guard.calls[0]["path"] == "artifacts/one.txt"
    assert file_return_guard.calls[1]["path"] == "artifacts/two.txt"


def test_command_policy_block_forces_block_verdict():
    command_policy = _Policy(
        verdict="block",
        allowed=False,
        should_block=True,
        risk_delta=15,
        matched_rules=["commandsupervisor:block"],
    )
    guard, _, _, _ = _build_guard(command_policy=command_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="bash",
            command="rm -rf /",
        ),
    )

    assert decision.allowed is False
    assert decision.verdict == "block"
    assert decision.should_block is True
    assert "commandsupervisor:block" in decision.matched_rules


def test_network_policy_quarantine_forces_quarantine_verdict():
    network_policy = _Policy(
        verdict="quarantine",
        allowed=False,
        should_block=True,
        should_quarantine=True,
        risk_delta=25,
        matched_rules=["networkguard:quarantine"],
    )
    guard, _, _, _ = _build_guard(network_policy=network_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="fetch",
            network_url="http://169.254.169.254/latest/meta-data",
        ),
    )

    assert decision.allowed is False
    assert decision.verdict == "quarantine"
    assert decision.should_quarantine is True
    assert decision.should_block is True
    assert "networkguard:quarantine" in decision.matched_rules


def test_risk_threshold_alone_can_trigger_review():
    command_policy = _Policy(
        verdict="allow",
        allowed=True,
        risk_delta=0,
        matched_rules=["commandsupervisor:allow"],
    )
    guard, _, _, _ = _build_guard(command_policy=command_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="powershell",
            command="Get-Process",
        ),
    )

    assert decision.verdict == "review"
    assert decision.should_review is True
    assert decision.allowed is True
    assert "toolcallguard:high_risk:powershell" in decision.matched_rules


def test_risk_threshold_alone_can_trigger_block():
    guard, _, _, _ = _build_guard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="powershell",
            environment_scope="host",
        ),
    )

    assert decision.allowed is False
    assert decision.verdict == "block"
    assert decision.should_block is True
    assert "toolcallguard:high_risk:powershell" in decision.matched_rules
    assert "toolcallguard:non_sandbox_scope" in decision.matched_rules


def test_risk_threshold_alone_can_trigger_quarantine():
    guard, _, _, _ = _build_guard()

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="",
            environment_scope="host",
        ),
    )

    assert decision.allowed is False
    assert decision.verdict == "quarantine"
    assert decision.should_quarantine is True
    assert "toolcallguard:missing_tool_name" in decision.matched_rules


def test_allow_helper_matches_decision():
    command_policy = _Policy(
        verdict="allow",
        allowed=True,
        risk_delta=0,
        matched_rules=["commandsupervisor:allow"],
    )
    guard, _, _, _ = _build_guard(command_policy=command_policy)

    allowed = guard.allow(
        request=ToolCallRequest(
            tool_name="bash",
            command="echo ok",
        ),
    )

    assert allowed is True


def test_as_dict_contains_expected_shapes():
    command_policy = _Policy(
        verdict="allow",
        allowed=True,
        risk_delta=5,
        reasons=[{"source": "commandsupervisor", "label": "Safe", "details": "OK", "score": 5}],
        matched_rules=["commandsupervisor:allow"],
    )
    guard, _, _, _ = _build_guard(command_policy=command_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="bash",
            command="echo ok",
        ),
    )
    body = decision.as_dict()

    assert body["verdict"] == decision.verdict
    assert body["allowed"] is True
    assert body["toolname"] == "bash"
    assert isinstance(body["reasons"], list)
    assert isinstance(body["matchedrules"], list)
    assert isinstance(body["commandpolicy"], dict)
    assert isinstance(body["networkpolicy"], dict)
    assert isinstance(body["artifactpolicies"], list)


def test_request_as_dict_contains_expected_shapes():
    request = ToolCallRequest(
        tool_name="fetch",
        actiontype="toolcall",
        target="runtime",
        command=None,
        network_url="https://api.example.com",
        network_method="GET",
        artifact_paths=["artifacts/report.txt"],
        cwd="/workspace",
        environment_scope="sandbox",
        metadata={"request_id": "req-4"},
    )
    body = request.as_dict()

    assert body["toolname"] == "fetch"
    assert body["networkurl"] == "https://api.example.com"
    assert body["networkmethod"] == "GET"
    assert body["artifactpaths"] == ["artifacts/report.txt"]
    assert body["environmentscope"] == "sandbox"


def test_reasons_and_rules_are_deduplicated():
    repeated_reason = {
        "source": "commandsupervisor",
        "label": "Repeated",
        "details": "Same reason",
        "score": 10,
    }
    command_policy = _Policy(
        verdict="review",
        allowed=True,
        should_review=True,
        risk_delta=10,
        reasons=[repeated_reason, repeated_reason],
        matched_rules=["repeat_rule", "repeat_rule"],
    )
    guard, _, _, _ = _build_guard(command_policy=command_policy)

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="bash",
            command="echo duplicate",
        ),
    )

    repeated = [item for item in decision.reasons if item["label"] == "Repeated" and item["details"] == "Same reason"]
    assert len(repeated) == 1
    assert decision.matched_rules.count("repeat_rule") == 1


def test_initialize_builder_uses_custom_high_risk_tools():
    command_policy = _Policy(
        verdict="allow",
        allowed=True,
        risk_delta=0,
        matched_rules=["commandsupervisor:allow"],
    )
    command_supervisor = _CommandSupervisorStub(command_policy)
    network_guard = _NetworkGuardStub(_Policy())
    file_return_guard = _FileReturnGuardStub([_Policy()])

    guard = build_toolcallguard(
        command_supervisor=command_supervisor,
        network_guard=network_guard,
        file_return_guard=file_return_guard,
        high_risk_tools={"custom_exec"},
    )

    decision = guard.evaluate(
        request=ToolCallRequest(
            tool_name="custom_exec",
            command="do-something",
        ),
    )

    assert "toolcallguard:high_risk:custom_exec" in decision.matched_rules
