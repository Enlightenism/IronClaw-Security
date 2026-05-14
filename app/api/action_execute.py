from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.dependencies.action_execute import get_action_execute_pipeline
from app.facade import guardandexecuteaction
from app.models.action_execute import ExecuteRequest, ExecuteResponse
from app.orchestrator.secure_runtime_pipeline import SecureRuntimePipeline
from app.services.telemetry import append_telemetry_event

router = APIRouter()


def _request_meta(request: Request) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", None),
        "trace_id": getattr(request.state, "trace_id", None),
        "path": request.url.path,
        "method": request.method,
    }


@router.post("/execute", response_model=ExecuteResponse)
def guarded_execute(
    payload: ExecuteRequest,
    request: Request,
    pipeline: SecureRuntimePipeline = Depends(get_action_execute_pipeline),
) -> ExecuteResponse:
    try:
        append_telemetry_event(
            "guard_execute_requested",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
            },
        )
    except Exception:
        pass

    response_payload = guardandexecuteaction(
        payload,
        pipeline=pipeline,
    )

    response = ExecuteResponse(**response_payload)

    try:
        append_telemetry_event(
            "guard_execute_completed",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
                "execution_id": getattr(response, "execution_id", None),
                "execution_state": getattr(response, "execution_state", None),
                "response_action": getattr(response, "response_action", None),
                "response_status": getattr(response, "response_status", None),
                "trace_id_response": getattr(response, "trace_id", None),
                "request_id_response": getattr(response, "request_id", None),
            },
        )
    except Exception:
        pass

    return response
