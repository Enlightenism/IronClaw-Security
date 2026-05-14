from __future__ import annotations

from typing import Any

from app.models.action_execute import ExecuteResponse
from app.models.action_execute_result import ActionExecuteResult
from app.models.guard_facade import GuardActionRequest
from app.services.action_execute_service import execute_guarded_action


def _normalize_reasons(summary: ActionExecuteResult) -> ActionExecuteResult:
    normalized_reasons: list[dict[str, object]] = []

    for item in summary.get("reasons", []):
        if isinstance(item, dict):
            normalized_reasons.append(
                {
                    "source": str(item.get("source", "scan")),
                    "label": str(item.get("label", "Explanation")),
                    "details": str(
                        item.get("details") or item.get("message") or item.get("summary") or "",
                    ),
                    "score": (float(item["score"]) if item.get("score") is not None else None),
                },
            )
            continue

        normalized_reasons.append(
            {
                "source": "scan",
                "label": "Explanation",
                "details": str(item),
                "score": None,
            },
        )

    summary["reasons"] = normalized_reasons
    return summary


def guard_and_execute_action(request: GuardActionRequest) -> ExecuteResponse:
    """Single entrypoint for IronClaw callers to route high-risk actions
    through the secure runtime pipeline and executor boundary.

    Internal services and external orchestrators should depend on this
    function instead of calling the HTTP /guard/execute route directly.
    """
    summary: ActionExecuteResult = execute_guarded_action(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        risk_score=request.risk_score,
        client_id=request.client_id,
        session_id=request.session_id,
        file_path=request.file_path,
    )

    summary = _normalize_reasons(summary)
    return ExecuteResponse(**summary)


def guard_and_execute_raw(
    *,
    action_type: str,
    target: str,
    content: str,
    risk_score: int,
    client_id: str | None = None,
    session_id: str | None = None,
    file_path: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> ExecuteResponse:
    """Lower-level convenience wrapper for non-Pydantic callers.

    Accepts raw primitives, passes them through the secure runtime pipeline,
    and returns a fully typed ExecuteResponse.
    """
    summary: ActionExecuteResult = execute_guarded_action(
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        file_path=file_path,
    )

    _ = extra_metadata

    summary = _normalize_reasons(summary)
    return ExecuteResponse(**summary)
