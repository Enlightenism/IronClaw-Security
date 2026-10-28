from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.orchestrator.supervisor import build_supervisor


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


class _SecureRuntimePipelineStub:
    def __init__(self, decision: _Decision | None = None) -> None:
        self.decision = decision or _Decision()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _Decision:
        self.calls.append(dict(kwargs))
        return self.decision


class _ReviewQueueStub:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def enqueue(self, item: dict[str, Any]) -> dict[str, Any]:
        self.items.append(dict(item))
        return {"queued": True, "id": f"review-{len(self.items)}"}

    def submit(self, item: dict[str, Any]) -> dict[str, Any]:
        self.items.append(dict(item))
        return {"queued": True, "id": f"review-{len(self.items)}"}


class _AuditSinkStub:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))


def _build(
    *,
    pipeline_decision: _Decision | None = None,
):
    secure_runtime_pipeline = _SecureRuntimePipelineStub(pipeline_decision)
    review_queue = _ReviewQueueStub()
    audit_sink = _AuditSinkStub()
    supervisor = build_supervisor(
        secure_runtime_pipeline=secure_runtime_pipeline,
        review_queue=review_queue,
        audit_sink=audit_sink,
    )
    return supervisor, secure_runtime_pipeline, review_queue, audit_sink


def test_allow_safe_supervised_request():
    supervisor, pipeline, review_queue, audit_sink = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
            risk_delta=10,
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-100",
        tool_name="bash",
        command="echo hello",
        cwd="/workspace",
        metadata={"request_id": "req-100"},
    )

    assert result.allowed is True
    assert result.verdict == "allow"
    assert result.session_id == "sess-100"
    assert result.tool_name == "bash"
    assert result.should_review is False
    assert result.should_block is False
    assert result.should_quarantine is False
    assert result.matched_rules == []
    assert len(pipeline.calls) == 1
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_missing_session_id_blocks_early():
    supervisor, pipeline, review_queue, audit_sink = _build()

    result = supervisor.evaluate(
        session_id="",
        tool_name="bash",
        command="echo hello",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.should_quarantine is False
    assert result.should_block is True
    assert "supervisor:missing_session_id" in result.matched_rules
    assert len(pipeline.calls) == 0
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_missing_tool_name_blocks_early():
    supervisor, pipeline, review_queue, audit_sink = _build()

    result = supervisor.evaluate(
        session_id="sess-101",
        tool_name="",
        command="echo hello",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.should_quarantine is False
    assert "supervisor:missing_tool_name" in result.matched_rules
    assert len(pipeline.calls) == 0
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_pipeline_allow_flows_through():
    supervisor, pipeline, review_queue, audit_sink = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
            risk_delta=5,
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-102",
        tool_name="fetch",
        network_url="https://api.example.com/status",
    )

    assert result.allowed is True
    assert result.verdict == "allow"
    assert result.risk_delta == 5
    assert len(pipeline.calls) == 1
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_pipeline_review_blocks_and_enqueues_review():
    supervisor, pipeline, review_queue, audit_sink = _build(
        pipeline_decision=_Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            risk_delta=35,
            matched_rules=["secureruntimepipeline:review"],
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-103",
        tool_name="bash",
        command="python -c 'print(1)'",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.should_review is True
    assert "secureruntimepipeline:review" in result.matched_rules
    assert len(pipeline.calls) == 1
    assert len(review_queue.items) == 1
    assert review_queue.items[0]["session_id"] == "sess-103"
    assert review_queue.items[0]["tool_name"] == "bash"
    assert len(audit_sink.events) >= 1


def test_pipeline_block_blocks_request():
    supervisor, pipeline, review_queue, audit_sink = _build(
        pipeline_decision=_Decision(
            verdict="block",
            allowed=False,
            should_block=True,
            risk_delta=70,
            matched_rules=["secureruntimepipeline:block"],
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-104",
        tool_name="bash",
        command="sudo whoami",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.should_block is True
    assert "secureruntimepipeline:block" in result.matched_rules
    assert len(pipeline.calls) == 1
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_pipeline_quarantine_signal_blocks_request():
    supervisor, pipeline, review_queue, audit_sink = _build(
        pipeline_decision=_Decision(
            verdict="quarantine",
            allowed=False,
            should_block=True,
            should_quarantine=True,
            risk_delta=90,
            matched_rules=["secureruntimepipeline:quarantine"],
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-105",
        tool_name="return_file",
        artifact_paths=["../secret.txt"],
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.should_quarantine is False
    assert result.should_block is True
    assert "secureruntimepipeline:quarantine" in result.matched_rules
    assert len(pipeline.calls) == 1
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_normalizes_fields_before_pipeline_dispatch():
    supervisor, pipeline, _, _ = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
        ),
    )

    result = supervisor.evaluate(
        session_id="  sess-106  ",
        tool_name="  BASH  ",
        command="echo hi",
        cwd=" /workspace/run ",
        metadata={"trace_id": "abc"},
    )

    assert result.session_id == "sess-106"
    assert result.tool_name == "bash"
    assert pipeline.calls[0]["session_id"] == "sess-106"
    assert pipeline.calls[0]["tool_name"] == "bash"
    assert pipeline.calls[0]["cwd"] == "/workspace/run"


def test_preserves_request_shape_for_network_calls():
    supervisor, pipeline, _, _ = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-107",
        tool_name="fetch",
        network_url="https://example.com/v1/items",
        network_method="POST",
        metadata={"request_id": "req-107"},
    )

    assert result.verdict == "allow"
    assert pipeline.calls[0]["network_url"] == "https://example.com/v1/items"
    assert pipeline.calls[0]["network_method"] == "POST"


def test_preserves_request_shape_for_artifact_calls():
    supervisor, pipeline, _, _ = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-108",
        tool_name="return_file",
        artifact_paths=["artifacts/report.txt", "artifacts/log.txt"],
        content="safe output",
    )

    assert result.verdict == "allow"
    assert pipeline.calls[0]["artifact_paths"] == ["artifacts/report.txt", "artifacts/log.txt"]
    assert pipeline.calls[0]["content"] == "safe output"


def test_allow_helper_matches_safe_decision():
    supervisor, _, _, _ = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
        ),
    )

    allowed = supervisor.allow(
        session_id="sess-109",
        tool_name="bash",
        command="echo ok",
    )

    assert allowed is True


def test_allow_helper_matches_unsafe_decision():
    supervisor, _, _, _ = _build(
        pipeline_decision=_Decision(
            verdict="block",
            allowed=False,
            should_block=True,
            matched_rules=["secureruntimepipeline:block"],
        ),
    )

    allowed = supervisor.allow(
        session_id="sess-110",
        tool_name="bash",
        command="sudo whoami",
    )

    assert allowed is False


def test_as_dict_contains_expected_shapes():
    supervisor, _, _, _ = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
            reasons=[{"source": "secureruntimepipeline", "label": "Safe", "details": "ok", "score": 5}],
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-111",
        tool_name="bash",
        command="echo ok",
    )
    body = result.as_dict()

    assert body["verdict"] == result.verdict
    assert body["allowed"] is True
    assert body["sessionid"] == "sess-111"
    assert body["toolname"] == "bash"
    assert isinstance(body["reasons"], list)
    assert isinstance(body["matchedrules"], list)
    assert isinstance(body["pipelinedecision"], dict)


def test_deduplicates_reasons_and_rules():
    repeated_reason = {
        "source": "secureruntimepipeline",
        "label": "Repeated",
        "details": "Same reason",
        "score": 10,
    }
    supervisor, _, _, _ = _build(
        pipeline_decision=_Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[repeated_reason, repeated_reason],
            matched_rules=["repeat_rule", "repeat_rule"],
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-112",
        tool_name="bash",
        command="echo duplicate",
    )

    repeated = [item for item in result.reasons if item["label"] == "Repeated" and item["details"] == "Same reason"]
    assert len(repeated) == 1
    assert result.matched_rules.count("repeat_rule") == 1


def test_review_queue_not_called_for_allow():
    supervisor, _, review_queue, _ = _build(
        pipeline_decision=_Decision(
            verdict="allow",
            allowed=True,
        ),
    )

    result = supervisor.evaluate(
        session_id="sess-113",
        tool_name="bash",
        command="echo ok",
    )

    assert result.verdict == "allow"
    assert len(review_queue.items) == 0


def test_builder_accepts_submit_only_review_queue():
    class _SubmitOnlyReviewQueue:
        def __init__(self) -> None:
            self.items: list[dict[str, Any]] = []

        def submit(self, item: dict[str, Any]) -> dict[str, Any]:
            self.items.append(dict(item))
            return {"queued": True, "id": "submit-1"}

    review_queue = _SubmitOnlyReviewQueue()
    audit_sink = _AuditSinkStub()
    supervisor = build_supervisor(
        secure_runtime_pipeline=_SecureRuntimePipelineStub(
            _Decision(
                verdict="review",
                allowed=True,
                should_review=True,
                matched_rules=["secureruntimepipeline:review"],
            ),
        ),
        review_queue=review_queue,
        audit_sink=audit_sink,
    )

    result = supervisor.evaluate(
        session_id="sess-114",
        tool_name="fetch",
        network_url="https://example.com",
    )

    assert result.verdict == "block"
    assert result.allowed is False
    assert len(review_queue.items) == 1
    assert review_queue.items[0]["session_id"] == "sess-114"


def test_audit_sink_optional_method_shapes_are_supported():
    class _EmitOnlyAuditSink:
        def __init__(self) -> None:
            self.events: list[dict[str, Any]] = []

        def emit(self, event: dict[str, Any]) -> None:
            self.events.append(dict(event))

    audit_sink = _EmitOnlyAuditSink()
    supervisor = build_supervisor(
        secure_runtime_pipeline=_SecureRuntimePipelineStub(
            _Decision(
                verdict="allow",
                allowed=True,
            ),
        ),
        review_queue=_ReviewQueueStub(),
        audit_sink=audit_sink,
    )

    result = supervisor.evaluate(
        session_id="sess-115",
        tool_name="bash",
        command="echo ok",
    )

    assert result.verdict == "allow"
    assert len(audit_sink.events) >= 1
