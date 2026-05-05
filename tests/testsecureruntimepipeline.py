from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from app.orchestrator.secureruntimepipeline import build_secure_runtime_pipeline


@dataclass(slots=True)
class _GuardDecision:
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


class _SandboxRouterStub:
    def __init__(self, decision: _GuardDecision | None = None) -> None:
        self.decision = decision or _GuardDecision()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _GuardDecision:
        self.calls.append(dict(kwargs))
        return self.decision


class _ToolCallGuardStub:
    def __init__(self, decision: _GuardDecision | None = None) -> None:
        self.decision = decision or _GuardDecision()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _GuardDecision:
        self.calls.append(dict(kwargs))
        return self.decision


class _TelemetrySinkStub:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))


class _ReviewQueueStub:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def enqueue(self, item: dict[str, Any]) -> dict[str, Any]:
        self.items.append(dict(item))
        return {"queued": True, "id": f"review-{len(self.items)}"}

    def submit(self, item: dict[str, Any]) -> dict[str, Any]:
        self.items.append(dict(item))
        return {"queued": True, "id": f"review-{len(self.items)}"}


def _build_pipeline(
    *,
    sandbox_decision: _GuardDecision | None = None,
    tool_decision: _GuardDecision | None = None,
):
    sandbox_router = _SandboxRouterStub(sandbox_decision)
    tool_guard = _ToolCallGuardStub(tool_decision)
    telemetry_sink = _TelemetrySinkStub()
    review_queue = _ReviewQueueStub()
    pipeline = build_secure_runtime_pipeline(
        sandbox_router=sandbox_router,
        tool_call_guard=tool_guard,
        telemetry_sink=telemetry_sink,
        review_queue=review_queue,
    )
    return pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue


def test_allow_safe_runtime_request():
    pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            risk_delta=5,
            matched_rules=["sandboxrouter:allow"],
        ),
        tool_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            risk_delta=10,
            matched_rules=["toolcallguard:allow"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-001",
        tool_name="bash",
        command="echo hello",
        cwd="/workspace",
        metadata={"request_id": "req-001"},
    )

    assert result.allowed is True
    assert result.verdict == "allow"
    assert result.session_id == "sess-001"
    assert result.tool_name == "bash"
    assert result.should_review is False
    assert result.should_block is False
    assert result.should_quarantine is False
    assert "sandboxrouter:allow" in result.matched_rules
    assert "toolcallguard:allow" in result.matched_rules
    assert len(sandbox_router.calls) == 1
    assert len(tool_guard.calls) == 1
    assert len(telemetry_sink.events) >= 1
    assert len(review_queue.items) == 0


def test_missing_session_id_quarantines_early():
    pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue = _build_pipeline()

    result = pipeline.evaluate(
        session_id="",
        tool_name="bash",
        command="echo hello",
    )

    assert result.allowed is False
    assert result.verdict == "quarantine"
    assert result.should_quarantine is True
    assert result.should_block is True
    assert "secureruntimepipeline:missing_session_id" in result.matched_rules
    assert len(sandbox_router.calls) == 0
    assert len(tool_guard.calls) == 0
    assert len(telemetry_sink.events) >= 1
    assert len(review_queue.items) == 0


def test_missing_tool_name_quarantines_early():
    pipeline, sandbox_router, tool_guard, telemetry_sink, _ = _build_pipeline()

    result = pipeline.evaluate(
        session_id="sess-002",
        tool_name="",
        command="echo hello",
    )

    assert result.allowed is False
    assert result.verdict == "quarantine"
    assert result.should_quarantine is True
    assert "secureruntimepipeline:missing_tool_name" in result.matched_rules
    assert len(sandbox_router.calls) == 0
    assert len(tool_guard.calls) == 0
    assert len(telemetry_sink.events) >= 1


def test_sandbox_block_short_circuits_before_tool_guard():
    pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="block",
            allowed=False,
            should_block=True,
            risk_delta=45,
            matched_rules=["sandboxrouter:block"],
        ),
        tool_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            risk_delta=5,
            matched_rules=["toolcallguard:allow"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-003",
        tool_name="bash",
        command="echo hello",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.should_block is True
    assert "sandboxrouter:block" in result.matched_rules
    assert len(sandbox_router.calls) == 1
    assert len(tool_guard.calls) == 0
    assert len(telemetry_sink.events) >= 1
    assert len(review_queue.items) == 0


def test_sandbox_quarantine_short_circuits_before_tool_guard():
    pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="quarantine",
            allowed=False,
            should_block=True,
            should_quarantine=True,
            risk_delta=80,
            matched_rules=["sandboxrouter:quarantine"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-004",
        tool_name="bash",
        command="echo hello",
    )

    assert result.allowed is False
    assert result.verdict == "quarantine"
    assert result.should_quarantine is True
    assert "sandboxrouter:quarantine" in result.matched_rules
    assert len(sandbox_router.calls) == 1
    assert len(tool_guard.calls) == 0
    assert len(telemetry_sink.events) >= 1
    assert len(review_queue.items) == 0


def test_tool_guard_review_enqueues_review():
    pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            risk_delta=5,
            matched_rules=["sandboxrouter:allow"],
        ),
        tool_decision=_GuardDecision(
            verdict="review",
            allowed=True,
            should_review=True,
            risk_delta=35,
            matched_rules=["toolcallguard:review"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-005",
        tool_name="fetch",
        network_url="https://api.example.com",
        metadata={"request_id": "req-005"},
    )

    assert result.allowed is True
    assert result.verdict == "review"
    assert result.should_review is True
    assert "toolcallguard:review" in result.matched_rules
    assert len(sandbox_router.calls) == 1
    assert len(tool_guard.calls) == 1
    assert len(review_queue.items) == 1
    assert review_queue.items[0]["session_id"] == "sess-005"
    assert len(telemetry_sink.events) >= 1


def test_tool_guard_block_blocks_request():
    pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            risk_delta=5,
            matched_rules=["sandboxrouter:allow"],
        ),
        tool_decision=_GuardDecision(
            verdict="block",
            allowed=False,
            should_block=True,
            risk_delta=60,
            matched_rules=["toolcallguard:block"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-006",
        tool_name="bash",
        command="sudo whoami",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.should_block is True
    assert "toolcallguard:block" in result.matched_rules
    assert len(sandbox_router.calls) == 1
    assert len(tool_guard.calls) == 1
    assert len(review_queue.items) == 0
    assert len(telemetry_sink.events) >= 1


def test_tool_guard_quarantine_quarantines_request():
    pipeline, sandbox_router, tool_guard, telemetry_sink, review_queue = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            risk_delta=5,
            matched_rules=["sandboxrouter:allow"],
        ),
        tool_decision=_GuardDecision(
            verdict="quarantine",
            allowed=False,
            should_block=True,
            should_quarantine=True,
            risk_delta=90,
            matched_rules=["toolcallguard:quarantine"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-007",
        tool_name="return_file",
        artifact_paths=["../secret.txt"],
    )

    assert result.allowed is False
    assert result.verdict == "quarantine"
    assert result.should_quarantine is True
    assert result.should_block is True
    assert "toolcallguard:quarantine" in result.matched_rules
    assert len(sandbox_router.calls) == 1
    assert len(tool_guard.calls) == 1
    assert len(review_queue.items) == 0
    assert len(telemetry_sink.events) >= 1


def test_normalizes_request_fields_before_dispatch():
    pipeline, sandbox_router, tool_guard, _, _ = _build_pipeline(
        sandbox_decision=_GuardDecision(verdict="allow", allowed=True, matched_rules=["sandboxrouter:allow"]),
        tool_decision=_GuardDecision(verdict="allow", allowed=True, matched_rules=["toolcallguard:allow"]),
    )

    result = pipeline.evaluate(
        session_id="  sess-008  ",
        tool_name="  BASH  ",
        command="echo hi",
        cwd=" /workspace/run ",
        metadata={"trace": "abc"},
    )

    assert result.session_id == "sess-008"
    assert result.tool_name == "bash"
    assert sandbox_router.calls[0]["session_id"] == "sess-008"
    assert tool_guard.calls[0]["request"].tool_name == "bash"
    assert tool_guard.calls[0]["request"].cwd == "/workspace/run"


def test_risk_delta_is_aggregated():
    pipeline, _, _, _, _ = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            risk_delta=15,
            matched_rules=["sandboxrouter:allow"],
        ),
        tool_decision=_GuardDecision(
            verdict="review",
            allowed=True,
            should_review=True,
            risk_delta=25,
            matched_rules=["toolcallguard:review"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-009",
        tool_name="fetch",
        network_url="https://example.com",
    )

    assert result.risk_delta == 40
    assert result.verdict == "review"


def test_allow_helper_matches_safe_decision():
    pipeline, _, _, _, _ = _build_pipeline(
        sandbox_decision=_GuardDecision(verdict="allow", allowed=True, matched_rules=["sandboxrouter:allow"]),
        tool_decision=_GuardDecision(verdict="allow", allowed=True, matched_rules=["toolcallguard:allow"]),
    )

    allowed = pipeline.allow(
        session_id="sess-010",
        tool_name="bash",
        command="echo ok",
    )

    assert allowed is True


def test_allow_helper_matches_unsafe_decision():
    pipeline, _, _, _, _ = _build_pipeline(
        sandbox_decision=_GuardDecision(verdict="block", allowed=False, should_block=True, matched_rules=["sandboxrouter:block"]),
    )

    allowed = pipeline.allow(
        session_id="sess-011",
        tool_name="bash",
        command="echo ok",
    )

    assert allowed is False


def test_as_dict_contains_expected_shapes():
    pipeline, _, _, _, _ = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            reasons=[{"source": "sandboxrouter", "label": "Safe", "details": "Sandbox ok", "score": 5}],
            matched_rules=["sandboxrouter:allow"],
        ),
        tool_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            reasons=[{"source": "toolcallguard", "label": "Safe", "details": "Tool ok", "score": 5}],
            matched_rules=["toolcallguard:allow"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-012",
        tool_name="bash",
        command="echo ok",
    )
    body = result.as_dict()

    assert body["verdict"] == result.verdict
    assert body["allowed"] is True
    assert body["sessionid"] == "sess-012"
    assert body["toolname"] == "bash"
    assert isinstance(body["reasons"], list)
    assert isinstance(body["matchedrules"], list)
    assert isinstance(body["sandboxdecision"], dict)
    assert isinstance(body["tooldecision"], dict)


def test_deduplicates_reasons_and_rules():
    duplicate_reason = {
        "source": "sandboxrouter",
        "label": "Repeated",
        "details": "Same reason",
        "score": 10,
    }
    pipeline, _, _, _, _ = _build_pipeline(
        sandbox_decision=_GuardDecision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[duplicate_reason, duplicate_reason],
            matched_rules=["repeat_rule", "repeat_rule"],
        ),
        tool_decision=_GuardDecision(
            verdict="allow",
            allowed=True,
            reasons=[duplicate_reason],
            matched_rules=["repeat_rule"],
        ),
    )

    result = pipeline.evaluate(
        session_id="sess-013",
        tool_name="bash",
        command="echo duplicate",
    )

    repeated = [
        item
        for item in result.reasons
        if item["label"] == "Repeated" and item["details"] == "Same reason"
    ]
    assert len(repeated) == 1
    assert result.matched_rules.count("repeat_rule") == 1


def test_review_queue_not_called_for_allow():
    pipeline, _, _, _, review_queue = _build_pipeline(
        sandbox_decision=_GuardDecision(verdict="allow", allowed=True, matched_rules=["sandboxrouter:allow"]),
        tool_decision=_GuardDecision(verdict="allow", allowed=True, matched_rules=["toolcallguard:allow"]),
    )

    result = pipeline.evaluate(
        session_id="sess-014",
        tool_name="bash",
        command="echo ok",
    )

    assert result.verdict == "allow"
    assert len(review_queue.items) == 0


def test_builder_accepts_submit_style_review_queue_only():
    class _SubmitOnlyReviewQueue:
        def __init__(self) -> None:
            self.items: list[dict[str, Any]] = []

        def submit(self, item: dict[str, Any]) -> dict[str, Any]:
            self.items.append(dict(item))
            return {"queued": True, "id": "submit-1"}

    review_queue = _SubmitOnlyReviewQueue()
    telemetry_sink = _TelemetrySinkStub()
    pipeline = build_secure_runtime_pipeline(
        sandbox_router=_SandboxRouterStub(
            _GuardDecision(verdict="allow", allowed=True, matched_rules=["sandboxrouter:allow"])
        ),
        tool_call_guard=_ToolCallGuardStub(
            _GuardDecision(verdict="review", allowed=True, should_review=True, matched_rules=["toolcallguard:review"])
        ),
        telemetry_sink=telemetry_sink,
        review_queue=review_queue,
    )

    result = pipeline.evaluate(
        session_id="sess-015",
        tool_name="fetch",
        network_url="https://example.com",
    )

    assert result.verdict == "review"
    assert len(review_queue.items) == 1
    assert review_queue.items[0]["session_id"] == "sess-015"