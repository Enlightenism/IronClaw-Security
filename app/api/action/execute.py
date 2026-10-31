from __future__ import annotations

from http import HTTPStatus
from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.dependencies.action_execute import get_action_execute_pipeline
from app.facade import guardandexecuteaction
from app.models.action_execute import ExecuteRequest as FacadeExecuteRequest
from app.orchestrator.secure_runtime_pipeline import SecureRuntimePipeline

router = APIRouter()

# --------------------------------------------------------------------------------------
# Pydantic models
# --------------------------------------------------------------------------------------


class ExecuteRequest(BaseModel):
    """Incoming request for guarded action execution.
    Mirrors the payload used in testsactionexecute.py.
    """

    actiontype: str = Field(..., description="High-level action type, e.g. httpfetch or toolcall.")
    target: str = Field(..., description="Execution target, e.g. URL or tool identifier.")
    content: str = Field(..., description="Human-readable description or prompt text.")
    riskscore: int = Field(..., ge=0, le=100, description="Pre-computed risk score 0-100.")
    clientid: str = Field(..., description="Logical client identifier.")
    sessionid: str = Field(..., description="Execution/session correlation id.")
    filepath: str | None = Field(
        None,
        description="Logical source filepath for this action; defaults to app/api/action/execute.py.",
    )


ExecutionStatus = Literal["completed", "queuedforreview", "denied"]
ResponseAction = Literal["allow", "block"]
PolicyVerdict = Literal["allow", "block"]


class ExecuteResponse(BaseModel):
    """HTTP facade response for guarded execution.
    Constrained to the literals expected by tests and down‑stream callers.
    """

    # Core execution state
    executionstate: ExecutionStatus = Field(
        ...,
        description="High-level execution outcome: completed, queuedforreview, or denied.",
    )
    responseaction: ResponseAction = Field(
        ...,
        description="Binary action outcome recommended/applied by policy and boundary.",
    )
    responsestatus: ExecutionStatus = Field(
        ...,
        description="HTTP-style status mapped into the same execution status domain.",
    )

    # Decision / policy metadata
    policyverdict: PolicyVerdict = Field(
        ...,
        description="Final policy verdict: allow or block.",
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
    reviewitemid: str | None = Field(
        None,
        description="Identifier of a queued review item when queuedforreview.",
    )

    # Tracing / correlation
    executionid: str | None = Field(
        None,
        description="Opaque identifier for this guarded execution.",
    )
    traceid: str | None = Field(
        None,
        description="Distributed trace correlation id (if available).",
    )
    requestid: str | None = Field(
        None,
        description="Logical request id, may map to gateway / ingress id.",
    )
    decisionid: str | None = Field(
        None,
        description="Identifier for the policy decision entry.",
    )

    # Executor details
    executorname: str | None = Field(
        None,
        description="Name of the executor used: dryrunexecutor, real executor, etc.",
    )
    executorresult: dict[str, Any] | None = Field(
        default=None,
        description="Opaque executor result payload, if available.",
    )

    # Human-readable explanation
    reason: str | None = Field(
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
    """Map numeric HTTP-ish status into the literal status domain required
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


def _normalize_policy_verdict(raw: str | None) -> PolicyVerdict:
    """Normalize legacy or invalid outcomes to the binary verdict contract."""
    return "allow" if isinstance(raw, str) and raw.strip().lower() == "allow" else "block"


def _normalize_response_action(raw: str | None, verdict: PolicyVerdict) -> ResponseAction:
    """Normalize the action outcome and fail closed on non-binary values."""
    if verdict == "block":
        return "block"
    if raw is None:
        return "allow"
    return "allow" if isinstance(raw, str) and raw.strip().lower() == "allow" else "block"


def _normalize_execution_state(raw_state: str | None, status: ExecutionStatus) -> ExecutionStatus:
    """Normalize executionstate to the literal domain required by the tests,
    using either the raw state emitted by summarizeexecution or the
    mapped HTTPish status code.[file:1]
    """
    if isinstance(raw_state, str) and raw_state.strip():
        value = raw_state.strip().lower()
        if value in {"completed", "executed", "succeeded", "ok", "200", "201", "202"}:
            return "completed"
        if value in {"queuedforreview", "queued_for_review", "queued", "pending_review", "pending"}:
            return "queuedforreview"
        if value in {"denied", "blocked", "failed", "error"}:
            return "denied"
    elif raw_state is None:
        return status

    return "denied"


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
    pipeline: SecureRuntimePipeline = Depends(get_action_execute_pipeline),
) -> ExecuteResponse:
    """Guard and optionally execute an action.

    This is the HTTP facade used by testsactionexecute.py as `client.post('/guard/execute')`
    (or similar alias), and it delegates to the guardandexecuteaction facade which in turn
    calls executeguardedaction and the SecureRuntimePipeline.[file:1]
    """
    effective_filepath = payload.filepath or _DEFAULT_FILEPATH

    facade_request = FacadeExecuteRequest(
        action_type=payload.actiontype,
        target=payload.target,
        content=payload.content,
        risk_score=payload.riskscore,
        client_id=payload.clientid,
        session_id=payload.sessionid,
        file_path=effective_filepath,
    )

    # Delegate to the runtime facade; this returns an ActionExecuteResult mapping.
    responsepayload = guardandexecuteaction(facade_request, pipeline=pipeline)

    # Extract raw fields from ActionExecuteResult / summary dict.
    # We access via getattr to tolerate both object-style and dict-style results.[file:1]
    def _get(field: str, default: Any = None) -> Any:
        if isinstance(responsepayload, dict):
            return responsepayload.get(field, default)
        return getattr(responsepayload, field, default)

    raw_exec_state: str | None = _get("execution_state", _get("executionstate"))
    raw_status_value = _get("response_status", _get("responsestatus"))
    if isinstance(raw_status_value, str):
        mapped_status = _normalize_execution_state(raw_status_value, "denied")
    elif raw_status_value is None:
        mapped_status = _normalize_execution_state(raw_exec_state, "denied")
    elif isinstance(raw_status_value, int) and not isinstance(raw_status_value, bool):
        mapped_status = _map_http_status_to_execution_status(raw_status_value)
    else:
        mapped_status = "denied"

    execution_state: ExecutionStatus = _normalize_execution_state(raw_exec_state, mapped_status)

    raw_policy_verdict: str | None = _get("policy_verdict", _get("policyverdict"))
    policy_verdict: PolicyVerdict = _normalize_policy_verdict(raw_policy_verdict)
    invalid_policy_verdict = not isinstance(raw_policy_verdict, str) or raw_policy_verdict.strip().lower() not in {"allow", "block"}

    raw_response_action: str | None = _get("response_action", _get("responseaction"))
    response_action: ResponseAction = _normalize_response_action(raw_response_action, policy_verdict)
    invalid_response_action = raw_response_action is not None and (not isinstance(raw_response_action, str) or raw_response_action.strip().lower() not in {"allow", "block"})
    if response_action == "block":
        policy_verdict = "block"

    raw_halted_by_boundary = _get("halted_by_boundary", _get("haltedbyboundary", False))
    if raw_halted_by_boundary is not False:
        policy_verdict = "block"
        response_action = "block"

    raw_risk_score = _get("riskscore", payload.riskscore)
    if isinstance(raw_risk_score, int) and not isinstance(raw_risk_score, bool) and 0 <= raw_risk_score <= 100:
        risk_score = raw_risk_score
        invalid_risk_score = False
    else:
        policy_verdict = "block"
        response_action = "block"
        risk_score = RISK_THRESHOLD_BLOCK_MIN
        invalid_risk_score = True
    risk_score_exceeded_allow = risk_score > RISK_THRESHOLD_ALLOW_MAX
    if risk_score_exceeded_allow:
        policy_verdict = "block"
        response_action = "block"
    if policy_verdict == "block":
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)

    halted_by_boundary = raw_halted_by_boundary is not False or policy_verdict == "block" or response_action == "block"
    raw_should_execute = _get("should_execute", _get("shouldexecute", False))
    should_execute = raw_should_execute is True and policy_verdict == "allow" and response_action == "allow" and mapped_status == "completed" and execution_state == "completed" and not halted_by_boundary
    reason = _get("reason")
    if invalid_risk_score:
        reason = "Invalid execution risk score; action blocked."
    elif invalid_policy_verdict or invalid_response_action:
        reason = "Invalid or legacy execution verdict; action blocked."
    elif policy_verdict == "block" and _normalize_policy_verdict(raw_policy_verdict) == "allow":
        reason = "Execution boundary or risk policy blocked the action."

    # Build the response with safe fallbacks where older components might omit fields.
    return ExecuteResponse(
        executionstate=execution_state,
        responseaction=response_action,
        responsestatus=mapped_status,
        policyverdict=policy_verdict,
        riskscore=risk_score,
        shouldexecute=should_execute,
        haltedbyboundary=halted_by_boundary,
        reviewitemid=_get("reviewitemid"),
        executionid=_get("executionid"),
        traceid=_get("traceid"),
        requestid=_get("requestid"),
        decisionid=_get("decisionid"),
        executorname=_get("executorname"),
        executorresult=_get("executorresult"),
        reason=reason,
        reasons=list(_get("reasons", [])) or [],
    )
