from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

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
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
        }


class _Pipeline:
    def __init__(self, decisions: list[_Decision] | None = None) -> None:
        self.decisions = list(decisions or [_Decision()])
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _Decision:
        self.calls.append(dict(kwargs))
        if len(self.decisions) == 1:
            return self.decisions[0]
        return self.decisions.pop(0)


class _ReviewQueueEnqueue:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def enqueue(self, item: dict[str, Any]) -> dict[str, Any]:
        self.items.append(dict(item))
        return {"queued": True, "queue_id": f"rq-{len(self.items)}"}


class _ReviewQueueSubmit:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def submit(self, item: dict[str, Any]) -> dict[str, Any]:
        self.items.append(dict(item))
        return {"queued": True, "queue_id": f"rq-{len(self.items)}"}


class _ReviewQueueBroken:
    pass


class _AuditRecord:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))


class _AuditEmit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))


class _AuditWrite:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))


class _AuditBroken:
    pass


def _build(
    *,
    decisions: list[_Decision] | None = None,
    review_queue: Any | None = None,
    audit_sink: Any | None = None,
):
    pipeline = _Pipeline(decisions)
    review_queue = review_queue if review_queue is not None else _ReviewQueueEnqueue()
    audit_sink = audit_sink if audit_sink is not None else _AuditRecord()
    supervisor = build_supervisor(
        secure_runtime_pipeline=pipeline,
        review_queue=review_queue,
        audit_sink=audit_sink,
    )
    return supervisor, pipeline, review_queue, audit_sink


def test_review_behavior_enqueues_exactly_once():
    supervisor, pipeline, review_queue, audit_sink = _build(
        decisions=[
            _Decision(
                verdict="review",
                allowed=True,
                should_review=True,
                risk_delta=41,
                matched_rules=["pipeline:review"],
            ),
        ],
    )

    result = supervisor.evaluate(
        session_id="sess-review-1",
        tool_name="bash",
        command="python scan.py",
        metadata={"request_id": "req-review-1"},
    )

    assert result.verdict == "review"
    assert result.allowed is True
    assert result.should_review is True
    assert len(review_queue.items) == 1
    assert review_queue.items[0]["session_id"] == "sess-review-1"
    assert review_queue.items[0]["tool_name"] == "bash"
    assert len(pipeline.calls) == 1
    assert len(audit_sink.events) >= 1


def test_review_behavior_uses_submit_when_enqueue_missing():
    review_queue = _ReviewQueueSubmit()
    supervisor, pipeline, _, audit_sink = _build(
        decisions=[
            _Decision(
                verdict="review",
                allowed=True,
                should_review=True,
                matched_rules=["pipeline:review"],
            ),
        ],
        review_queue=review_queue,
    )

    result = supervisor.evaluate(
        session_id="sess-review-2",
        tool_name="fetch",
        network_url="https://example.com/api",
    )

    assert result.verdict == "review"
    assert len(review_queue.items) == 1
    assert review_queue.items[0]["session_id"] == "sess-review-2"
    assert len(pipeline.calls) == 1
    assert len(audit_sink.events) >= 1


def test_allow_behavior_never_enqueues_review():
    supervisor, pipeline, review_queue, audit_sink = _build(
        decisions=[
            _Decision(
                verdict="allow",
                allowed=True,
                risk_delta=4,
                matched_rules=["pipeline:allow"],
            ),
        ],
    )

    result = supervisor.evaluate(
        session_id="sess-allow-1",
        tool_name="bash",
        command="echo safe",
    )

    assert result.verdict == "allow"
    assert result.allowed is True
    assert result.should_review is False
    assert len(review_queue.items) == 0
    assert len(pipeline.calls) == 1
    assert len(audit_sink.events) >= 1


def test_block_behavior_never_enqueues_review():
    supervisor, pipeline, review_queue, audit_sink = _build(
        decisions=[
            _Decision(
                verdict="block",
                allowed=False,
                should_block=True,
                risk_delta=72,
                matched_rules=["pipeline:block"],
            ),
        ],
    )

    result = supervisor.evaluate(
        session_id="sess-block-1",
        tool_name="bash",
        command="sudo cat /etc/shadow",
    )

    assert result.verdict == "block"
    assert result.allowed is False
    assert result.should_block is True
    assert len(review_queue.items) == 0
    assert len(pipeline.calls) == 1
    assert len(audit_sink.events) >= 1


def test_quarantine_behavior_never_enqueues_review():
    supervisor, pipeline, review_queue, audit_sink = _build(
        decisions=[
            _Decision(
                verdict="quarantine",
                allowed=False,
                should_block=True,
                should_quarantine=True,
                risk_delta=95,
                matched_rules=["pipeline:quarantine"],
            ),
        ],
    )

    result = supervisor.evaluate(
        session_id="sess-quarantine-1",
        tool_name="return_file",
        artifact_paths=["../secret.txt"],
    )

    assert result.verdict == "quarantine"
    assert result.allowed is False
    assert result.should_quarantine is True
    assert len(review_queue.items) == 0
    assert len(pipeline.calls) == 1
    assert len(audit_sink.events) >= 1


def test_missing_session_short_circuits_pipeline():
    supervisor, pipeline, review_queue, audit_sink = _build()

    result = supervisor.evaluate(
        session_id="",
        tool_name="bash",
        command="echo hi",
    )

    assert result.verdict == "quarantine"
    assert result.allowed is False
    assert "supervisor:missing_session_id" in result.matched_rules
    assert len(pipeline.calls) == 0
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_missing_tool_short_circuits_pipeline():
    supervisor, pipeline, review_queue, audit_sink = _build()

    result = supervisor.evaluate(
        session_id="sess-missing-tool",
        tool_name="",
        command="echo hi",
    )

    assert result.verdict == "quarantine"
    assert result.allowed is False
    assert "supervisor:missing_tool_name" in result.matched_rules
    assert len(pipeline.calls) == 0
    assert len(review_queue.items) == 0
    assert len(audit_sink.events) >= 1


def test_input_normalization_behavior_is_stable():
    supervisor, pipeline, _, _ = _build(
        decisions=[_Decision(verdict="allow", allowed=True, matched_rules=["pipeline:allow"])],
    )

    result = supervisor.evaluate(
        session_id="  sess-normalize  ",
        tool_name="  BASH  ",
        command="echo normalized",
        cwd=" /workspace/tmp ",
    )

    assert result.session_id == "sess-normalize"
    assert result.tool_name == "bash"
    assert pipeline.calls[0]["session_id"] == "sess-normalize"
    assert pipeline.calls[0]["tool_name"] == "bash"
    assert pipeline.calls[0]["cwd"] == "/workspace/tmp"


def test_reason_dedup_behavior_is_stable():
    repeated = {
        "source": "pipeline",
        "label": "Same",
        "details": "duplicate",
        "score": 12,
    }
    supervisor, _, _, _ = _build(
        decisions=[
            _Decision(
                verdict="review",
                allowed=True,
                should_review=True,
                reasons=[repeated, repeated],
                matched_rules=["dup-rule", "dup-rule"],
            ),
        ],
    )

    result = supervisor.evaluate(
        session_id="sess-dedup",
        tool_name="bash",
        command="echo x",
    )

    same = [item for item in result.reasons if item["label"] == "Same" and item["details"] == "duplicate"]
    assert len(same) == 1
    assert result.matched_rules.count("dup-rule") == 1


def test_audit_record_method_is_supported():
    audit_sink = _AuditRecord()
    supervisor, _, _, _ = _build(
        decisions=[_Decision(verdict="allow", allowed=True, matched_rules=["pipeline:allow"])],
        audit_sink=audit_sink,
    )

    result = supervisor.evaluate(
        session_id="sess-audit-record",
        tool_name="bash",
        command="echo ok",
    )

    assert result.verdict == "allow"
    assert len(audit_sink.events) >= 1


def test_audit_emit_method_is_supported():
    audit_sink = _AuditEmit()
    supervisor, _, _, _ = _build(
        decisions=[_Decision(verdict="allow", allowed=True, matched_rules=["pipeline:allow"])],
        audit_sink=audit_sink,
    )

    result = supervisor.evaluate(
        session_id="sess-audit-emit",
        tool_name="bash",
        command="echo ok",
    )

    assert result.verdict == "allow"
    assert len(audit_sink.events) >= 1


def test_audit_write_method_is_supported():
    audit_sink = _AuditWrite()
    supervisor, _, _, _ = _build(
        decisions=[_Decision(verdict="allow", allowed=True, matched_rules=["pipeline:allow"])],
        audit_sink=audit_sink,
    )

    result = supervisor.evaluate(
        session_id="sess-audit-write",
        tool_name="bash",
        command="echo ok",
    )

    assert result.verdict == "allow"
    assert len(audit_sink.events) >= 1


def test_missing_review_queue_methods_does_not_break_review_flow():
    supervisor, pipeline, review_queue, audit_sink = _build(
        decisions=[
            _Decision(
                verdict="review",
                allowed=True,
                should_review=True,
                matched_rules=["pipeline:review"],
            ),
        ],
        review_queue=_ReviewQueueBroken(),
    )

    result = supervisor.evaluate(
        session_id="sess-review-broken-queue",
        tool_name="bash",
        command="echo maybe",
    )

    assert result.verdict == "review"
    assert result.allowed is True
    assert result.should_review is True
    assert len(pipeline.calls) == 1
    assert isinstance(review_queue, _ReviewQueueBroken)
    assert len(audit_sink.events) >= 1


def test_missing_audit_methods_does_not_break_allow_flow():
    supervisor, pipeline, review_queue, audit_sink = _build(
        decisions=[_Decision(verdict="allow", allowed=True, matched_rules=["pipeline:allow"])],
        audit_sink=_AuditBroken(),
    )

    result = supervisor.evaluate(
        session_id="sess-audit-broken",
        tool_name="bash",
        command="echo ok",
    )

    assert result.verdict == "allow"
    assert result.allowed is True
    assert len(pipeline.calls) == 1
    assert len(review_queue.items) == 0
    assert isinstance(audit_sink, _AuditBroken)


def test_multiple_calls_follow_pipeline_sequence():
    supervisor, pipeline, review_queue, audit_sink = _build(
        decisions=[
            _Decision(verdict="allow", allowed=True, matched_rules=["pipeline:allow"]),
            _Decision(
                verdict="review",
                allowed=True,
                should_review=True,
                matched_rules=["pipeline:review"],
            ),
            _Decision(
                verdict="block",
                allowed=False,
                should_block=True,
                matched_rules=["pipeline:block"],
            ),
        ],
    )

    first = supervisor.evaluate(
        session_id="sess-seq-1",
        tool_name="bash",
        command="echo one",
    )
    second = supervisor.evaluate(
        session_id="sess-seq-2",
        tool_name="bash",
        command="echo two",
    )
    third = supervisor.evaluate(
        session_id="sess-seq-3",
        tool_name="bash",
        command="echo three",
    )

    assert first.verdict == "allow"
    assert second.verdict == "review"
    assert third.verdict == "block"
    assert len(review_queue.items) == 1
    assert review_queue.items[0]["session_id"] == "sess-seq-2"
    assert len(pipeline.calls) == 3
    assert len(audit_sink.events) >= 3


@pytest.mark.parametrize(
    ("tool_name", "payload"),
    [
        ("bash", {"command": "echo safe", "cwd": "/workspace"}),
        ("fetch", {"network_url": "https://example.com/status", "network_method": "GET"}),
        ("return_file", {"artifact_paths": ["artifacts/report.txt"], "content": "safe"}),
    ],
)
def test_behavior_preserves_tool_specific_context(tool_name: str, payload: dict[str, Any]):
    supervisor, pipeline, _, _ = _build(
        decisions=[_Decision(verdict="allow", allowed=True, matched_rules=["pipeline:allow"])],
    )

    kwargs = {"session_id": f"sess-{tool_name}", "tool_name": tool_name}
    kwargs.update(payload)

    result = supervisor.evaluate(**kwargs)

    assert result.verdict == "allow"
    for key, value in payload.items():
        assert pipeline.calls[0][key] == value
