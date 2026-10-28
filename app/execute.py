from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.orchestrator.secureruntimepipeline import SecureRuntimePipeline, getactionexecutepipeline
from app.service import ActionExecuteResult, ExecutionReason, executeguardedaction

logger = logging.getLogger(__name__)

router = APIRouter()


ResponseStatus = Literal["completed", "queuedforreview", "denied"]
ExecutionState = Literal["executed", "denied", "queuedforreview"]
ResponseAction = Literal["allow", "block"]
PolicyVerdict = Literal["allow", "block"]


class ExecuteRequest(BaseModel):
    actiontype: str = Field(..., description="Action type, such as httpfetch or toolcall.")
    target: str = Field(..., description="Execution target such as URL, shell, or tool name.")
    content: str = Field(..., description="Prompt, content, or execution description.")
    riskscore: int = Field(..., ge=0, le=100, description="Base risk score for the action.")
    clientid: str | None = Field(None, description="Client or actor identifier.")
    sessionid: str | None = Field(None, description="Session or conversation identifier.")
    filepath: str | None = Field(
        None,
        description="Optional source filepath for attribution and audit visibility.",
    )


class ExecuteReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int


class ExecuteResponse(BaseModel):
    executionid: str | None = None
    executionstate: ExecutionState
    responseaction: ResponseAction
    responsestatus: ResponseStatus
    traceid: str | None = None
    requestid: str | None = None
    decisionid: str | None = None
    policyverdict: PolicyVerdict
    riskscore: int
    shouldexecute: bool
    haltedbyboundary: bool
    reviewitemid: str | None = None
    executorname: str | None = None
    executorresult: dict | None = None
    reason: str | None = None
    reasons: list[ExecuteReasonView] = Field(default_factory=list)
    filepath: str | None = None
    promptinjection: dict = Field(default_factory=dict)


def _normalize_responsestatus(value: str | None) -> ResponseStatus:
    if not isinstance(value, str) or not value.strip():
        return "denied"

    lowered = value.strip().lower()
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
    if not isinstance(value, str) or not value.strip():
        return "denied"

    lowered = value.strip().lower()
    if lowered in {"executed", "completed", "succeeded"}:
        return "executed"
    if lowered in {"queuedforreview", "queued", "pending_review", "review"}:
        return "queuedforreview"
    if lowered in {"denied", "blocked", "forbidden", "failed"}:
        return "denied"
    return "denied"


def _normalize_policyverdict(value: str | None) -> PolicyVerdict:
    return "allow" if isinstance(value, str) and value.strip().lower() == "allow" else "block"


def _normalize_responseaction(value: str | None, verdict: PolicyVerdict) -> ResponseAction:
    if verdict == "block":
        return "block"
    if value is None:
        return "allow"
    return "allow" if isinstance(value, str) and value.strip().lower() == "allow" else "block"


def _normalize_actionexecuteresult(result: ActionExecuteResult) -> ActionExecuteResult:
    raw_policyverdict = result.policyverdict
    policyverdict = _normalize_policyverdict(raw_policyverdict)
    raw_responseaction = result.responseaction
    responseaction = _normalize_responseaction(raw_responseaction, policyverdict)
    invalid_result = not isinstance(raw_policyverdict, str) or raw_policyverdict.strip().lower() not in {"allow", "block"} or (raw_responseaction is not None and (not isinstance(raw_responseaction, str) or raw_responseaction.strip().lower() not in {"allow", "block"}))
    if responseaction == "block":
        policyverdict = "block"
    raw_haltedbyboundary = result.haltedbyboundary
    if raw_haltedbyboundary is not False:
        policyverdict = "block"
        responseaction = "block"

    raw_riskscore = result.riskscore
    if isinstance(raw_riskscore, int) and not isinstance(raw_riskscore, bool) and 0 <= raw_riskscore <= 100:
        riskscore = raw_riskscore
        invalid_riskscore = False
    else:
        logger.error("app.execute: invalid risk score; blocking action")
        riskscore = RISK_THRESHOLD_BLOCK_MIN
        policyverdict = "block"
        responseaction = "block"
        invalid_result = True
        invalid_riskscore = True
    if riskscore > RISK_THRESHOLD_ALLOW_MAX:
        policyverdict = "block"
        responseaction = "block"
    if policyverdict == "block":
        riskscore = max(riskscore, RISK_THRESHOLD_BLOCK_MIN)

    responsestatus = _normalize_responsestatus(result.responsestatus)
    executionstate = _normalize_executionstate(result.executionstate)
    haltedbyboundary = raw_haltedbyboundary is not False or policyverdict == "block" or responseaction == "block"
    shouldexecute = result.shouldexecute is True and policyverdict == "allow" and responseaction == "allow" and responsestatus == "completed" and executionstate == "executed" and not haltedbyboundary

    if invalid_result:
        logger.error("app.execute: invalid execution result; blocking action")
        result.reason = "Invalid execution result; action blocked."
    elif policyverdict == "block" and isinstance(raw_policyverdict, str) and raw_policyverdict.strip().lower() == "allow":
        result.reason = "Invalid risk score; action blocked." if invalid_riskscore else "Execution boundary or risk policy blocked the action."
    result.policyverdict = policyverdict
    result.responseaction = responseaction
    result.riskscore = riskscore
    result.responsestatus = responsestatus
    result.executionstate = executionstate
    result.haltedbyboundary = haltedbyboundary
    result.shouldexecute = shouldexecute
    return result


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


def _normalize_reasons(
    reasons: list[ExecutionReason] | list[dict] | list[str] | None,
) -> list[ExecuteReasonView]:
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
    result = executeguardedaction(
        actiontype=actiontype,
        target=target,
        content=content,
        riskscore=riskscore,
        clientid=clientid,
        sessionid=sessionid,
        filepath=filepath,
        pipeline=pipeline,
    )
    return _normalize_actionexecuteresult(result)


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

    policyverdict = _normalize_policyverdict(result.policyverdict)
    responseaction = _normalize_responseaction(result.responseaction, policyverdict)
    if responseaction == "block":
        policyverdict = "block"
    raw_haltedbyboundary = result.haltedbyboundary
    if raw_haltedbyboundary is not False:
        policyverdict = "block"
        responseaction = "block"

    raw_riskscore = result.riskscore
    if isinstance(raw_riskscore, int) and not isinstance(raw_riskscore, bool) and 0 <= raw_riskscore <= 100:
        riskscore = raw_riskscore
    else:
        policyverdict = "block"
        responseaction = "block"
        riskscore = RISK_THRESHOLD_BLOCK_MIN
    if riskscore > RISK_THRESHOLD_ALLOW_MAX:
        policyverdict = "block"
        responseaction = "block"
    if policyverdict == "block":
        riskscore = max(riskscore, RISK_THRESHOLD_BLOCK_MIN)

    responsestatus = _normalize_responsestatus(result.responsestatus)
    executionstate = _normalize_executionstate(result.executionstate)
    haltedbyboundary = raw_haltedbyboundary is not False or policyverdict == "block" or responseaction == "block"
    shouldexecute = result.shouldexecute is True and policyverdict == "allow" and responseaction == "allow" and responsestatus == "completed" and executionstate == "executed" and not haltedbyboundary

    return ExecuteResponse(
        executionid=result.executionid,
        executionstate=executionstate,
        responseaction=responseaction,
        responsestatus=responsestatus,
        traceid=result.traceid,
        requestid=result.requestid,
        decisionid=result.decisionid,
        policyverdict=policyverdict,
        riskscore=riskscore,
        shouldexecute=shouldexecute,
        haltedbyboundary=haltedbyboundary,
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
