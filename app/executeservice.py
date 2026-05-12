from __future__ import annotations

from app.orchestrator.secureruntimepipeline import SecureRuntimePipeline

DEFAULT_FILEPATH = "app/api/action_execute.py"


def _normalize_executor_result(summary: dict) -> dict:
    if not isinstance(summary, dict):
        return {}

    executor_result = summary.get("executor_result")
    if isinstance(executor_result, dict):
        executor_result.setdefault("filepath", DEFAULT_FILEPATH)

    return summary


def get_action_execute_pipeline() -> SecureRuntimePipeline:
    return SecureRuntimePipeline()


def guard_and_execute_action(payload, pipeline: SecureRuntimePipeline | None = None) -> dict:
    pipeline = pipeline or get_action_execute_pipeline()

    summary = pipeline.guard_and_execute(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        risk_score=payload.risk_score,
        client_id=payload.client_id,
        session_id=payload.session_id,
        filepath=payload.filepath or DEFAULT_FILEPATH,
    )

    if not isinstance(summary, dict):
        summary = {}

    summary = _normalize_executor_result(summary)

    if "response_status" not in summary:
        if summary.get("should_execute") is False or summary.get("halted_by_boundary") is True:
            summary["response_status"] = "denied"
        elif summary.get("execution_state") == "executed":
            summary["response_status"] = "completed"
        else:
            summary["response_status"] = "queued_for_review"

    return summary