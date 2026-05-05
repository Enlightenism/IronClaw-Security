from __future__ import annotations

from http import HTTPStatus
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.guard.facade import guardandexecuteaction
from app.orchestrator.secureruntimepipeline import SecureRuntimePipeline, getactionexecutepipeline

router = APIRouter()

# --------------------------------------------------------------------------------------
# Pydantic models
# --------------------------------------------------------------------------------------


class ExecuteRequest(BaseModel):
    """
    Incoming request for guarded action execution.
    Mirrors the payload used in testsactionexecute.py.
    """

    actiontype: str = Field(..., description="High-level action type, e.g. httpfetch or toolcall.")
    target: str = Field(..., description="Execution target, e.g. URL or tool identifier.")
    content: str = Field(..., description="Human-readable description or prompt text.")
    riskscore: int = Field(..., ge=0, le=100, description="Pre-computed risk score 0-100.")
    clientid: str = Field(..., description="Logical client identifier.")
    sessionid: str = Field(..., description="Execution/session correlation id.")
    filepath: Optional[str] = Field(
        None,
        description="Logical source filepath for this action; defaults to app/api/action/execute.py.",
    )


ExecutionStatus = Literal["completed", "queuedforreview", "denied"]
ResponseAction = Literal["allow", "warn", "quarantine", "block", "review"]
PolicyVerdict = Literal["allow", "warn", "quarantine", "block"]


class ExecuteResponse(BaseModel):
    """
    HTTP facade response for guarded execution.
    Constrained to the literals expected by tests and down‑stream callers.
    """

    # Core execution state
    executionstate: ExecutionStatus = Field(
        ...,
        description="High-level execution outcome: completed, queuedforreview, or denied.",
    )
    responseaction: ResponseAction = Field(
        ...,
        description="Action recommended/applied by policy and boundary.",
    )
    responsestatus: ExecutionStatus = Field(
        ...,
        description="HTTP-style status mapped into the same execution status domain.",
    )

    # Decision / policy metadata
    policyverdict: PolicyVerdict = Field(
        ...,
        description="Final policy verdict: allow, warn, quarantine, or block.",
    )
    riskscore: int = Field(
        ...,
        ge=0,
        le=100,
        description="Echoed risk score, for client-side introspection.",
    )
    shouldexecute: bool = Field(
        ...,
        description="Whether the action should actually execute beyond dry-run.",
    )
    haltedbyboundary: bool = Field(
        ...,
        description="True if boundary logic prevented real execution.",
    )
    reviewitemid: Optional[str] = Field(
        None,
        description="Identifier of a queued review item when queuedforreview.",
    )

    # Tracing / correlation
    executionid: Optional[str] = Field(
        None,
        description="Opaque identifier for this guarded execution.",
    )
    traceid: Optional[str] = Field(
        None,
        description="Distributed trace correlation id (if available).",
    )
    requestid: Optional[str] = Field(
        None,
        description="Logical request id, may map to gateway / ingress id.",
    )
    decisionid: Optional[str] = Field(
        None,
        description="Identifier for the policy decision entry.",
    )

    # Executor details
    executorname: Optional[str] = Field(
        None,
        description="Name of the executor used: dryrunexecutor, real executor, etc.",
    )
    executorresult: Optional[dict[str, Any]] = Field(
        default=None,
        description="Opaque executor result payload, if available.",
    )

    # Human-readable explanation
    reason: Optional[str] = Field(
        None,
        description="Primary human-readable reason string for the decision.",
    )
    reasons: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured list of contributing reasons with scores/labels.",
    )


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


_DEFAULT_FILEPATH = "app/api/action/execute.py"


def _map_http_status_to_execution_status(status_code: int) -> ExecutionStatus:
    """
    Map numeric HTTP-ish status into the literal status domain required
    by ExecuteResponse.responsestatus and .executionstate.

    Tests assert that only 'completed', 'queuedforreview', or 'denied'
    are ever present here.[file:4]
    """
    if status_code in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
        return "completed"
    if status_code in (
        HTTPStatus.TOO_MANY_REQUESTS,
        HTTPStatus.SERVICE_UNAVAILABLE,
        HTTPStatus.LOCKED,
    ):
        return "queuedforreview"
    # 4xx/5xx and anything unexpected collapse to denied
    return "denied"


def _normalize_policy_verdict(raw: Optional[str]) -> PolicyVerdict:
    """
    Ensure policyverdict stays within the allowed literal set.
    Some older components may emit 'deny'; tests expect block/quarantine
    membership checks instead.[file:4]
    """
    if not raw:
        return "allow"

    value = raw.lower()
    if value in {"allow", "warn", "quarantine", "block"}:
        return value  # type: ignore[return-value]

    # Backwards-compat: unify any deny/forbid style to 'block'
    return "block"


def _normalize_response_action(raw: Optional[str], verdict: PolicyVerdict) -> ResponseAction:
    """
    Normalize the raw response action from lower layers to the allowed literals.
    Tests assert responseaction is in allow, warn, quarantine, block, review.[file:4]
    """
    if not raw:
        # Derive from verdict when missing.
        if verdict in ("allow", "warn"):
            return verdict
        if verdict in ("quarantine", "block"):
            return verdict
        return "review"

    value = raw.lower()
    if value in {"allow", "warn", "quarantine", "block", "review"}:
        return value  # type: ignore[return-value]

    if value in {"deny", "denied"}:
        return "block"

    # Fallback to verdict alignment.
    if verdict in ("allow", "warn"):
        return verdict
    if verdict in ("quarantine", "block"):
        return verdict
    return "review"


def _normalize_execution_state(raw_state: Optional[str], status: ExecutionStatus) -> ExecutionStatus:
    """
    Normalize executionstate to the literal domain required by the tests,
    using either the raw state emitted by summarizeexecution or the
    mapped HTTPish status code.[file:1]
    """
    if raw_state:
        value = raw_state.lower()
        if value in {"completed", "executed", "succeeded", "ok"}:
            return "completed"
        if value in {"queuedforreview", "queued", "pending_review", "pending"}:
            return "queuedforreview"
        if value in {"denied", "blocked", "failed", "error"}:
            return "denied"

    # Fall back to the mapped status when the raw state is unknown/missing.
    return status


# --------------------------------------------------------------------------------------
# Route
# --------------------------------------------------------------------------------------


@router.post(
    "/execute",
    response_model=ExecuteResponse,
    summary="Guard and execute an action through the secure runtime pipeline.",
)
def guardedexecute(
    payload: ExecuteRequest,
    pipeline: SecureRuntimePipeline = Depends(getactionexecutepipeline),
) -> ExecuteResponse:
    """
    Guard and optionally execute an action.

    This is the HTTP facade used by testsactionexecute.py as `client.post('/guard/execute')`
    (or similar alias), and it delegates to the guardandexecuteaction facade which in turn
    calls executeguardedaction and the SecureRuntimePipeline.[file:1]
    """
    effective_filepath = payload.filepath or _DEFAULT_FILEPATH

    # Delegate to facade; this returns an ActionExecuteResult instance.
    responsepayload = guardandexecuteaction(
        actiontype=payload.actiontype,
        target=payload.target,
        content=payload.content,
        riskscore=payload.riskscore,
        clientid=payload.clientid,
        sessionid=payload.sessionid,
        filepath=effective_filepath,
        pipeline=pipeline,
    )

    # Extract raw fields from ActionExecuteResult / summary dict.
    # We access via getattr to tolerate both object-style and dict-style results.[file:1]
    def _get(field: str, default: Any = None) -> Any:
        if isinstance(responsepayload, dict):
            return responsepayload.get(field, default)
        return getattr(responsepayload, field, default)

    raw_status_code: int = int(_get("responsestatus", HTTPStatus.OK))
    mapped_status: ExecutionStatus = _map_http_status_to_execution_status(raw_status_code)

    raw_exec_state: Optional[str] = _get("executionstate")
    execution_state: ExecutionStatus = _normalize_execution_state(raw_exec_state, mapped_status)

    raw_policy_verdict: Optional[str] = _get("policyverdict")
    policy_verdict: PolicyVerdict = _normalize_policy_verdict(raw_policy_verdict)

    raw_response_action: Optional[str] = _get("responseaction")
    response_action: ResponseAction = _normalize_response_action(raw_response_action, policy_verdict)

    # Build the response with safe fallbacks where older components might omit fields.
    return ExecuteResponse(
        executionstate=execution_state,
        responseaction=response_action,
        responsestatus=mapped_status,
        policyverdict=policy_verdict,
        riskscore=int(_get("riskscore", payload.riskscore)),
        shouldexecute=bool(_get("shouldexecute", False)),
        haltedbyboundary=bool(_get("haltedbyboundary", False)),
        reviewitemid=_get("reviewitemid"),
        executionid=_get("executionid"),
        traceid=_get("traceid"),
        requestid=_get("requestid"),
        decisionid=_get("decisionid"),
        executorname=_get("executorname"),
        executorresult=_get("executorresult"),
        reason=_get("reason"),
        reasons=list(_get("reasons", [])) or [],
    )