from __future__ import annotations

from app.execute_service import executeguardedaction
from app.models.action_execute import ExecuteRequest
from app.models.action_execute_result import ActionExecuteResult
from app.orchestrator.secure_runtime_pipeline import SecureRuntimePipeline


def guardandexecuteaction(
    request: ExecuteRequest,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    """High-level facade to guard and execute an action in one step."""
    return executeguardedaction(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        risk_score=request.risk_score,
        client_id=request.client_id,
        session_id=request.session_id,
        file_path=request.file_path,
        pipeline=pipeline,
    )


def guardandexecuteraw(
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
    """Convenience facade for callers that pass raw parameters."""
    request = ExecuteRequest(
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        file_path=file_path,
    )
    return guardandexecuteaction(request, pipeline=pipeline)


def guardaction(
    action_type: str,
    target: str,
    content: str,
    risk_score: int = 0,
    client_id: str | None = None,
    session_id: str | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    """Facade entry for guard-only action evaluation (no execute step)."""
    return executeguardedaction(
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        pipeline=pipeline,
    )


def guardactiondecision(
    action_type: str,
    target: str,
    content: str,
    risk_score: int = 0,
    client_id: str | None = None,
    session_id: str | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    """Facade entry for guard action decision evaluation."""
    return executeguardedaction(
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        pipeline=pipeline,
    )


def guardactionpolicy(
    action_type: str,
    target: str,
    content: str,
    risk_score: int = 0,
    client_id: str | None = None,
    session_id: str | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    """Facade entry for guard action policy enforcement."""
    return executeguardedaction(
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        pipeline=pipeline,
    )
