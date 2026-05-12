from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services import action_decision as action_decision_svc
from app.services import action_guard as action_guard_svc
from app.services import action_policy as action_policy_svc
from app.services import history as history_svc
from app.services import scanner as scanner_svc

router = APIRouter()

Verdict = Literal["allow", "warn", "quarantine", "block"]


class ScanRequest(BaseModel):
    target_type: str = Field(..., min_length=1)
    target_value: str = Field(..., min_length=1)


class ScanResponse(BaseModel):
    scan_id: str
    verdict: Verdict
    summary: str
    risk_score: int
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    review_status: str | None = None
    untrusted: bool | None = None
    quarantine_reason: str | None = None


class HistoryItem(BaseModel):
    scan_id: str
    target_type: str
    target_value: str
    verdict: Verdict
    summary: str
    risk_score: int
    matched_patterns: list[str] = Field(default_factory=list)
    review_status: str | None = None
    untrusted: bool | None = None
    quarantine_reason: str | None = None


class HistoryListResponse(BaseModel):
    items: list[HistoryItem]


class ReviewRequest(BaseModel):
    action: Literal["approve", "reject"]


class GuardActionRequest(BaseModel):
    action_type: str
    target: str
    content: str
    client_id: str
    session_id: str


class GuardActionResponse(BaseModel):
    action_type: str
    target: str
    content: str
    verdict: Verdict
    should_halt: bool
    should_warn: bool
    matched_patterns: list[str] = Field(default_factory=list)
    client_id: str
    session_id: str


class GuardPolicyResponse(BaseModel):
    action_type: str
    target: str
    content: str
    policy_mode: Literal["allow", "review", "block"]
    verdict: Verdict
    should_halt: bool
    should_warn: bool
    client_id: str
    session_id: str


class GuardDecisionResponse(BaseModel):
    action_type: str
    target: str
    content: str
    policy_mode: Literal["allow", "review", "block"]
    verdict: Verdict
    decision_source: Literal["policy", "scan"]
    should_halt: bool
    should_warn: bool
    matched_patterns: list[str] = Field(default_factory=list)
    client_id: str
    session_id: str


@router.post("/scan/", response_model=ScanResponse)
def scan_target(request: ScanRequest) -> ScanResponse:
    ttype = request.target_type
    tvalue = request.target_value

    normalized_value = " ".join(tvalue.split())
    if ttype == "text" and not normalized_value:
        raise HTTPException(status_code=400, detail="target_value is empty after normalization")

    if ttype == "text":
        result = scanner_svc.scan_text(normalized_value)
    elif ttype == "url":
        result = scanner_svc.scan_url(tvalue)
    elif ttype == "github_repo":
        result = scanner_svc.scan_github_repo(tvalue)
    elif ttype == "archive":
        result = scanner_svc.scan_archive(tvalue)
    else:
        raise HTTPException(status_code=400, detail=f"unsupported target_type={ttype}")

    stored = history_svc.record_scan_result(
        target_type=ttype,
        target_value=tvalue,
        result=result,
    )

    return ScanResponse(
        scan_id=stored.scan_id,
        verdict=stored.verdict,  # type: ignore[assignment]
        summary=stored.summary,
        risk_score=stored.riskscore,
        matched_patterns=list(getattr(stored, "matchedpatterns", [])),
        risky_files=list(getattr(stored, "riskyfiles", [])),
        checks_loaded=list(getattr(stored, "checksloaded", [])),
        failed_checks=list(getattr(stored, "failedchecks", [])),
        review_status=getattr(stored, "reviewstatus", None),
        untrusted=getattr(stored, "untrusted", None),
        quarantine_reason=getattr(stored, "quarantinereason", None),
    )


@router.get("/history/", response_model=HistoryListResponse)
def list_history() -> HistoryListResponse:
    items = history_svc.get_history_items()
    return HistoryListResponse(
        items=[
            HistoryItem(
                scan_id=i.scan_id,
                target_type=i.targettype,
                target_value=i.targetvalue,
                verdict=i.verdict,  # type: ignore[assignment]
                summary=i.summary,
                risk_score=i.riskscore,
                matched_patterns=list(getattr(i, "matchedpatterns", [])),
                review_status=getattr(i, "reviewstatus", None),
                untrusted=getattr(i, "untrusted", None),
                quarantine_reason=getattr(i, "quarantinereason", None),
            )
            for i in items
        ]
    )


@router.get("/history/{scan_id}", response_model=HistoryItem)
def get_history(scan_id: str) -> HistoryItem:
    item = history_svc.get_history_item(scan_id)
    if item is None:
        raise HTTPException(status_code=404, detail="scan_id not found")

    return HistoryItem(
        scan_id=item.scan_id,
        target_type=item.targettype,
        target_value=item.targetvalue,
        verdict=item.verdict,  # type: ignore[assignment]
        summary=item.summary,
        risk_score=item.riskscore,
        matched_patterns=list(getattr(item, "matchedpatterns", [])),
        review_status=getattr(item, "reviewstatus", None),
        untrusted=getattr(item, "untrusted", None),
        quarantine_reason=getattr(item, "quarantinereason", None),
    )


@router.post("/history/{scan_id}/review")
def review_history_item(scan_id: str, request: ReviewRequest) -> dict[str, Any]:
    try:
        updated = history_svc.review_scan(scan_id=scan_id, action=request.action)
    except KeyError:
        raise HTTPException(status_code=404, detail="scan_id not found")

    if updated is None:
        raise HTTPException(status_code=400, detail="review not applicable for this scan")

    history_svc.apply_review_action(updated, request.action)
    return {"status": "ok", "scan_id": scan_id, "action": request.action}


@router.post("/guard/action", response_model=GuardActionResponse)
def guard_action(request: GuardActionRequest) -> GuardActionResponse:
    # delegate to existing service; it should return verdict + patterns
    scan_result = action_guard_svc.evaluate_action(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
    )

    verdict: Verdict = scan_result.verdict  # type: ignore[assignment]
    matched_patterns = list(getattr(scan_result, "matchedpatterns", []))

    should_halt = verdict in ("block", "quarantine")
    should_warn = verdict in ("warn", "quarantine")

    return GuardActionResponse(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        verdict=verdict,
        should_halt=bool(should_halt),
        should_warn=bool(should_warn),
        matched_patterns=matched_patterns,
        client_id=request.client_id,
        session_id=request.session_id,
    )


@router.post("/guard/action-policy", response_model=GuardPolicyResponse)
def guard_action_policy(request: GuardActionRequest) -> GuardPolicyResponse:
    policy = action_policy_svc.evaluate_policy(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
    )

    return GuardPolicyResponse(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        policy_mode=policy.mode,  # "allow" | "review" | "block"
        verdict=policy.verdict,  # type: ignore[assignment]
        should_halt=policy.should_halt,
        should_warn=policy.should_warn,
        client_id=request.client_id,
        session_id=request.session_id,
    )


@router.post("/guard/action-decision", response_model=GuardDecisionResponse)
def guard_action_decision(request: GuardActionRequest) -> GuardDecisionResponse:
    decision = action_decision_svc.evaluate_action_decision(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
    )

    return GuardDecisionResponse(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        policy_mode=decision.policy_mode,  # type: ignore[assignment]
        verdict=decision.verdict,  # type: ignore[assignment]
        decision_source=decision.source,  # "policy" | "scan"
        should_halt=decision.should_halt,
        should_warn=decision.should_warn,
        matched_patterns=list(getattr(decision, "matchedpatterns", [])),
        client_id=request.client_id,
        session_id=request.session_id,
    )