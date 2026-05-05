from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.executeresult import ExecuteRequest, ExecuteResponse
from app.executeservice import get_action_execute_pipeline, guard_and_execute_action

router = APIRouter(prefix="/guard", tags=["guard"])


def _normalize_response_status(raw: object) -> str:
    if isinstance(raw, str):
        normalized = raw.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in {"completed", "queued_for_review", "denied"}:
            return normalized

    if raw == 200:
        return "completed"
    if raw in {202, 206, 409}:
        return "queued_for_review"
    if raw in {400, 401, 403}:
        return "denied"

    return "denied"


def _ensure_filepath(summary: dict) -> dict:
    executor_result = summary.get("executor_result")
    if isinstance(executor_result, dict) and not executor_result.get("filepath"):
        executor_result["filepath"] = "app/api/action_execute.py"
    return summary


@router.post("/execute", response_model=ExecuteResponse)
def guarded_execute(
    payload: ExecuteRequest,
    pipeline=Depends(get_action_execute_pipeline),
) -> ExecuteResponse:
    response_payload = guard_and_execute_action(payload, pipeline=pipeline)

    if not isinstance(response_payload, dict):
        response_payload = {"response_status": "denied", "summary": {}}

    response_payload = _ensure_filepath(response_payload)
    response_payload["response_status"] = _normalize_response_status(
        response_payload.get("response_status")
    )

    return ExecuteResponse(**response_payload)