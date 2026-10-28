from __future__ import annotations

from typing import Any

from app.dependencies.action_execute import get_action_execute_pipeline
from app.models.action_execute_result import ActionExecuteResult, ExecutionReason
from app.orchestrator.executor_boundary import (
    execute_with_boundary,
    summarize_execution_receipt,
)
from app.orchestrator.secure_runtime_pipeline import SecureRuntimePipeline


def executeguardedaction(
    *,
    action_type: str,
    target: str,
    content: str,
    risk_score: int,
    client_id: str | None = None,
    session_id: str | None = None,
    file_path: str | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    active_pipeline: SecureRuntimePipeline = pipeline if pipeline is not None else get_action_execute_pipeline()

    effective_file_path = file_path or "app/api/action_execute.py"

    receipt, runtime_result = execute_with_boundary(
        pipeline=active_pipeline,
        actor_id=client_id,
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        session_id=session_id,
        file_path=effective_file_path,
        metadata={"source": "service.execute"},
        executor=None,
    )

    summary: dict[str, Any] = summarize_execution_receipt(receipt, runtime_result)

    raw_reasons = summary.get("reasons") or []
    reasons: list[ExecutionReason] = []
    for raw in raw_reasons:
        if isinstance(raw, dict):
            reasons.append(
                {
                    "source": raw.get("source", "policy"),
                    "label": raw.get("label", raw.get("reason", "reason")),
                    "details": raw.get("details", str(raw)),
                    "score": raw.get("score"),
                },
            )
        else:
            text = str(raw)
            reasons.append(
                {
                    "source": "policy",
                    "label": text[:80],
                    "details": text,
                    "score": None,
                },
            )

    result: ActionExecuteResult = {
        "execution_id": summary["execution_id"],
        "execution_state": summary["execution_state"],
        "response_action": summary["response_action"],
        "response_status": summary["response_status"],
        "trace_id": summary["trace_id"],
        "request_id": summary["request_id"],
        "decision_id": summary["decision_id"],
        "policy_verdict": summary["policy_verdict"],
        "risk_score": summary["risk_score"],
        "should_execute": summary["should_execute"],
        "halted_by_boundary": summary["halted_by_boundary"],
        "review_item_id": summary["review_item_id"],
        "executor_name": summary["executor_name"],
        "executor_result": summary["executor_result"],
        "reason": summary["reason"],
        "reasons": reasons,
    }

    return result
