from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from app.config import RISK_THRESHOLD_ALLOW_MAX
import app.orchestrator.executor_boundary as executor_boundary
from app.orchestrator.executor_boundary import execute_with_boundary
from app.orchestrator.secure_runtime_pipeline import (
    RuntimeRequest,
    SecureRuntimePipeline,
)


def _pipeline_result(
    *,
    verdict: str = "allow",
    action: str = "allow",
    status: str = "completed",
    requires_review: bool = False,
    allow_execution: bool | None = None,
    policy_risk_score: int = 10,
) -> SimpleNamespace:
    if allow_execution is None:
        allow_execution = verdict == "allow" and not requires_review
    return SimpleNamespace(
        decision=SimpleNamespace(
            decision_id="decision-from-pipeline",
            verdict=verdict,
            allow_execution=allow_execution,
            requires_review=requires_review,
            risk_score=policy_risk_score,
            reasons=["Pipeline policy decision."],
        ),
        coordination=SimpleNamespace(
            response=SimpleNamespace(
                action=action,
                status=status,
                reason="Pipeline response reason.",
                review_item_id=("review-from-pipeline" if status == "queued_for_review" else None),
            )
        ),
        trace=SimpleNamespace(
            request_id="request-from-pipeline",
            trace_id="trace-from-pipeline",
        ),
    )


def _make_pipeline(result: SimpleNamespace) -> tuple[Mock, SecureRuntimePipeline]:
    pipeline_mock = Mock(spec=SecureRuntimePipeline)
    pipeline_mock.run.return_value = result
    return pipeline_mock, cast(SecureRuntimePipeline, pipeline_mock)


def _execute(
    pipeline: SecureRuntimePipeline,
    executor: Any = None,
    **overrides: Any,
) -> tuple[Any, Any]:
    arguments: dict[str, Any] = {
        "actor_id": "user-123",
        "action_type": "file_read",
        "target": "workspace/file.txt",
        "content": "read file",
        "risk_score": 5,
        "session_id": "session-123",
        "file_path": "workspace/file.txt",
        "executor": executor,
    }
    arguments.update(overrides)
    return execute_with_boundary(pipeline=pipeline, **arguments)


def test_executor_boundary_uses_pipeline_ids_and_executes_after_allow() -> None:
    pipeline_mock, pipeline = _make_pipeline(_pipeline_result())
    executor = Mock(return_value={"result": "ok"})

    first_receipt, runtime_result = _execute(pipeline, executor)
    second_receipt, _ = _execute(pipeline, executor)

    pipeline_mock.run.assert_called()
    assert pipeline_mock.run.call_count == 2
    pipeline_request = pipeline_mock.run.call_args.args[0]
    assert isinstance(pipeline_request, RuntimeRequest)
    assert pipeline_request.actor_id == "user-123"
    assert runtime_result.request_id == "request-from-pipeline"
    assert runtime_result.trace_id == "trace-from-pipeline"
    assert first_receipt.decision_id == "decision-from-pipeline"
    assert first_receipt.execution_id != second_receipt.execution_id
    assert first_receipt.state == "executed"
    assert first_receipt.executor_result == {"result": "ok"}
    assert executor.call_count == 2


def test_blocked_pipeline_decision_never_calls_executor() -> None:
    pipeline_mock, pipeline = _make_pipeline(
        _pipeline_result(
            verdict="block",
            action="block",
            status="queued_for_review",
        )
    )
    executor = Mock(return_value={"result": "must not run"})

    receipt, runtime_result = _execute(pipeline, executor)

    pipeline_mock.run.assert_called_once()
    executor.assert_not_called()
    assert receipt.state == "denied"
    assert receipt.response_action == "block"
    assert receipt.response_status == "queued_for_review"
    assert receipt.halted_by_boundary is True
    assert receipt.trace_id == runtime_result.trace_id


def test_review_required_pipeline_result_never_calls_executor() -> None:
    _, pipeline = _make_pipeline(
        _pipeline_result(
            requires_review=True,
            status="queued_for_review",
        )
    )
    executor = Mock(return_value={"result": "must not run"})

    receipt, _ = _execute(pipeline, executor)

    executor.assert_not_called()
    assert receipt.state == "denied"
    assert receipt.response_status == "queued_for_review"
    assert receipt.review_item_id == "review-from-pipeline"


@pytest.mark.parametrize(
    ("risk_score", "expected_reason"),
    [
        (-1, "Invalid risk score"),
        (RISK_THRESHOLD_ALLOW_MAX + 1, "executor-boundary risk policy"),
    ],
)
def test_invalid_or_high_risk_input_never_calls_executor(
    risk_score: int,
    expected_reason: str,
) -> None:
    _, pipeline = _make_pipeline(_pipeline_result())
    executor = Mock(return_value={"result": "must not run"})

    receipt, _ = _execute(pipeline, executor, risk_score=risk_score)

    executor.assert_not_called()
    assert receipt.state == "denied"
    assert any(expected_reason in reason for reason in receipt.reasons)


def test_pipeline_reported_high_risk_never_calls_executor() -> None:
    _, pipeline = _make_pipeline(_pipeline_result(policy_risk_score=RISK_THRESHOLD_ALLOW_MAX + 1))
    executor = Mock(return_value={"result": "must not run"})

    receipt, _ = _execute(pipeline, executor)

    executor.assert_not_called()
    assert receipt.state == "denied"
    assert "executor-boundary risk policy" in receipt.reason


def test_network_egress_block_never_calls_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, pipeline = _make_pipeline(_pipeline_result())
    executor = Mock(return_value={"result": "must not run"})
    network_guard = Mock()
    network_guard.allow.return_value = False
    monkeypatch.setattr(
        executor_boundary,
        "_get_network_guard",
        Mock(return_value=network_guard),
    )

    receipt, _ = _execute(
        pipeline,
        executor,
        action_type="network_request",
        target="https://example.invalid",
    )

    executor.assert_not_called()
    network_guard.allow.assert_called_once_with(
        url="https://example.invalid",
        metadata={"direction": "egress"},
    )
    assert receipt.state == "denied"
    assert "network egress policy" in receipt.reason


def test_executor_failure_returns_failure_receipt() -> None:
    _, pipeline = _make_pipeline(_pipeline_result())
    executor = Mock(side_effect=RuntimeError("executor failed"))

    receipt, _ = _execute(pipeline, executor)

    assert receipt.state == "failed"
    assert receipt.response_action == "review"
    assert receipt.response_status == "queued_for_review"
    assert receipt.should_execute is False
    assert "executor failed" in receipt.reason
