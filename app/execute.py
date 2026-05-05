from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.orchestrator.secureruntimepipeline import SecureRuntimePipeline, getactionexecutepipeline
from app.service import ActionExecuteResult, ExecutionReason, executeguardedaction


router = APIRouter()


ResponseStatus = Literal["completed", "queuedforreview", "denied"]
ExecutionState = Literal["executed", "denied", "queuedforreview"]
PolicyVerdict = Literal["allow", "warn", "quarantine", "block"]


class ExecuteRequest(BaseModel):
    actiontype: str = Field(..., description="Action type, such as httpfetch or toolcall.")
    target: str = Field(..., description="Execution target such as URL, shell, or tool name.")
    content: str = Field(..., description="Prompt, content, or execution description.")
    riskscore: int = Field(..., ge=0, le=100, description="Base risk score for the action.")
    clientid: Optional[str] = Field(None, description="Client or actor identifier.")
    sessionid: Optional[str] = Field(None, description="Session or conversation identifier.")
    filepath: Optional[str] = Field(
        None,
        description="Optional source filepath for attribution and audit visibility.",
    )


class ExecuteReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int


class ExecuteResponse(BaseModel):
    executionid: Optional[str] = None
    executionstate: ExecutionState
    responseaction: str
    responsestatus: ResponseStatus
    traceid: Optional[str] = None
    requestid: Optional[str] = None
    decisionid: Optional[str] = None
    policyverdict: PolicyVerdict
    riskscore: int
    shouldexecute: bool
    haltedbyboundary: bool
    reviewitemid: Optional[str] = None
    executorname: Optional[str] = None
    executorresult: Optional[dict] = None
    reason: Optional[str] = None
    reasons: list[ExecuteReasonView] = Field(default_factory=list)
    filepath: Optional[str] = None
    promptinjection: dict = Field(default_factory=dict)


def _normalize_responsestatus(value: str | None) -> ResponseStatus:
    if not value:
        return "completed"

    lowered = str(value).lower()
    if lowered in {"completed", "done", "ok", "success"}:
        return "completed"
    if lowered in {"queuedforreview", "queued", "pending_review", "review"}:
        return "queuedforreview"
    if lowered in {"denied", "blocked", "forbidden", "403"}:
        return "denied"

    if lowered in {"200", "201", "202"}:
        return "completed"
    return "denied"


def _normalize_executionstate(value: str | None) -> ExecutionState:
    if not value:
        return "executed"

    lowered = str(value).lower()
    if lowered in {"executed", "completed", "succeeded"}:
        return "executed"
    if lowered in {"queuedforreview", "queued", "pending_review", "review"}:
        return "queuedforreview"
    if lowered in {"denied", "blocked", "forbidden", "failed"}:
        return "denied"
    return "executed"


def _normalize_policyverdict(value: str | None) -> PolicyVerdict:
    if not value:
        return "allow"

    lowered = str(value).lower()
    if lowered in {"allow", "warn", "quarantine", "block"}:
        return lowered  # type: ignore[return-value]
    if lowered in {"deny", "denied", "forbidden"}:
        return "block"
    return "allow"


def _normalize_reason(reason: ExecutionReason | dict | str) -> ExecuteReasonView:
    if isinstance(reason, ExecutionReason):
        return ExecuteReasonView(
            source=reason.source,
            label=reason.label,
            details=reason.details,
            score=reason.score,
        )

    if isinstance(reason, dict):
        return ExecuteReasonView(
            source=str(reason.get("source", "runtime")),
            label=str(reason.get("label", "Execution reason")),
            details=str(reason.get("details", "")),
            score=int(reason.get("score", 0)),
        )

    return ExecuteReasonView(
        source="runtime",
        label="Execution reason",
        details=str(reason),
        score=0,
    )


def _normalize_reasons(reasons: list[ExecutionReason] | list[dict] | list[str] | None) -> list[ExecuteReasonView]:
    if not reasons:
        return []
    return [_normalize_reason(reason) for reason in reasons]


def guardandexecuteraw(
    actiontype: str,
    target: str,
    content: str,
    riskscore: int,
    clientid: str | None = None,
    sessionid: str | None = None,
    filepath: str | None = None,
    pipeline: SecureRuntimePipeline | None = None,
) -> ActionExecuteResult:
    return executeguardedaction(
        actiontype=actiontype,
        target=target,
        content=content,
        riskscore=riskscore,
        clientid=clientid,
        sessionid=sessionid,
        filepath=filepath,
        pipeline=pipeline,
    )


def guardandexecuteaction(
    payload: ExecuteRequest,
    pipeline: SecureRuntimePipeline | None = None,
) -> ExecuteResponse:
    result = guardandexecuteraw(
        actiontype=payload.actiontype,
        target=payload.target,
        content=payload.content,
        riskscore=payload.riskscore,
        clientid=payload.clientid,
        sessionid=payload.sessionid,
        filepath=payload.filepath,
        pipeline=pipeline,
    )

    return ExecuteResponse(
        executionid=result.executionid,
        executionstate=_normalize_executionstate(result.executionstate),
        responseaction=result.responseaction,
        responsestatus=_normalize_responsestatus(result.responsestatus),
        traceid=result.traceid,
        requestid=result.requestid,
        decisionid=result.decisionid,
        policyverdict=_normalize_policyverdict(result.policyverdict),
        riskscore=result.riskscore,
        shouldexecute=result.shouldexecute,
        haltedbyboundary=result.haltedbyboundary,
        reviewitemid=result.reviewitemid,
        executorname=result.executorname,
        executorresult=result.executorresult,
        reason=result.reason,
        reasons=_normalize_reasons(result.reasons),
        filepath=result.filepath,
        promptinjection=dict(result.promptinjection or {}),
    )


@router.post(
    "/guard/execute",
    response_model=ExecuteResponse,
    summary="Guard and execute an action through the secure runtime pipeline.",
)
def guardedexecute(
    payload: ExecuteRequest,
    pipeline: SecureRuntimePipeline = Depends(getactionexecutepipeline),
) -> ExecuteResponse:
    return guardandexecuteaction(payload, pipeline)