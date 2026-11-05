from __future__ import annotations

from typing import TypedDict, cast

from app.dependencies.action_execute import get_action_execute_pipeline
from app.models.action_execute_result import ActionExecuteResult
from app.orchestrator.executor_boundary import (
    execute_with_boundary,
    summarize_execution_receipt,
)
from app.orchestrator.secure_runtime_pipeline import SecureRuntimePipeline


class ExecutorResult(TypedDict, total=False):
    mode: str
    file_path: str
    output: str
    status: str


def execute_guarded_action(
    *,
    action_type: str,
    target: str,
    content: str,
    risk_score: int,
    client_id: str | None,
    session_id: str | None,
    file_path: str | None,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    active_pipeline: SecureRuntimePipeline = pipeline if pipeline is not None else get_action_execute_pipeline()

    effective_file_path = file_path or "app/api/action_execute.py"

    receipt, runtime_result = execute_with_boundary(
        pipeline=active_pipeline,
        actor_id=client_id or "anonymous-client",
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        session_id=session_id,
        file_path=effective_file_path,
        metadata={
            "source": "action_execute_api",
            "session_id": session_id,
            "client_id": client_id,
        },
        # Decision-only: no side-effecting executor is wired. The default dry-run receipt reports the verdict and runs nothing.
        executor=None,
    )

    summary = summarize_execution_receipt(receipt, runtime_result)
    summary["file_path"] = effective_file_path
    return cast("ActionExecuteResult", summary)
