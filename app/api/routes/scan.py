from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.C_gen1 import scan_text, scan_url, scan_github_repo, scan_archive
from app.C_gen1service import (
    apply_review_action,
    get_history_items,
    get_history_item,
    record_scan_result,
    review_scan,
)

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
    target_type = request.target_type
    target_value = request.target_value

    normalized_value = " ".join(target_value.split())
    if target_type == "text" and not normalized_value:
        raise HTTPException(status_code=400, detail="target_value is empty after normalization")

    if target_type == "text":
        result = scan_text(normalized_value)
    elif target_type == "url":
        result = scan_url(target_value)
    elif target_type == "github_repo":
        result = scan_github_repo(target_value)
    elif target_type == "archive":
        result = scan_archive(target_value)
    else:
        raise HTTPException(status_code=400, detail=f"unsupported target_type={target_type}")

    stored = record_scan_result(
        target_type=target_type,
        target_value=target_value,
        result=result,
    )

    return ScanResponse(
        scan_id=stored.scan_id,
        verdict=stored.verdict,
        summary=stored.summary,
        risk_score=stored.risk_score,
        matched_patterns=list(stored.matchedpatterns),
        risky_files=list(getattr(stored, "riskyfiles", [])),
        checks_loaded=list(getattr(stored, "checksloaded", [])),
        failed_checks=list(getattr(stored, "failedchecks", [])),
        review_status=getattr(stored, "reviewstatus", None),
        untrusted=getattr(stored, "untrusted", None),
        quarantine_reason=getattr(stored, "quarantinereason", None),
    )


@router.get("/history/", response_model=HistoryListResponse)
def list_history() -> HistoryListResponse:
    items = get_history_items()
    return HistoryListResponse(
        items=[
            HistoryItem(
                scan_id=i.scan_id,
                target_type=i.targettype,
                target_value=i.targetvalue,
                verdict=i.verdict,
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
    item = get_history_item(scan_id)
    if item is None:
        raise HTTPException(status_code=404, detail="scan_id not found")

    return HistoryItem(
        scan_id=item.scan_id,
        target_type=item.targettype,
        target_value=item.targetvalue,
        verdict=item.verdict,
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
        updated = review_scan(scan_id=scan_id, action=request.action)
    except KeyError:
        raise HTTPException(status_code=404, detail="scan_id not found")

    if updated is None:
        raise HTTPException(status_code=400, detail="review not applicable for this scan")

    apply_review_action(updated, request.action)
    return {"status": "ok", "scan_id": scan_id, "action": request.action}


@router.post("/guard/action", response_model=GuardActionResponse)
def guard_action(request: GuardActionRequest) -> GuardActionResponse:
    scan_result = scan_text(request.content)
    verdict: Verdict = scan_result.verdict  # type: ignore[assignment]

    should_halt = verdict in ("block", "quarantine")
    should_warn = verdict in ("warn", "quarantine")

    return GuardActionResponse(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        verdict=verdict,
        should_halt=bool(should_halt),
        should_warn=bool(should_warn),
        matched_patterns=list(scan_result.matchedpatterns),
        client_id=request.client_id,
        session_id=request.session_id,
    )


@router.post("/guard/action-policy", response_model=GuardPolicyResponse)
def guard_action_policy(request: GuardActionRequest) -> GuardPolicyResponse:
    content = request.content.lower()
    if "powershell" in content:
        policy_mode: Literal["review", "allow", "block"] = "review"
        verdict: Verdict = "warn"
        should_halt = False
        should_warn = True
    else:
        policy_mode = "allow"
        verdict = "allow"
        should_halt = False
        should_warn = False

    return GuardPolicyResponse(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        policy_mode=policy_mode,
        verdict=verdict,
        should_halt=should_halt,
        should_warn=should_warn,
        client_id=request.client_id,
        session_id=request.session_id,
    )


@router.post("/guard/action-decision", response_model=GuardDecisionResponse)
def guard_action_decision(request: GuardActionRequest) -> GuardDecisionResponse:
    scan_result = scan_text(request.content)
    scan_verdict: Verdict = scan_result.verdict  # type: ignore[assignment]

    policy_resp = guard_action_policy(request)
    policy_mode = policy_resp.policy_mode

    matched_patterns = list(scan_result.matchedpatterns)

    if scan_verdict in ("block", "quarantine"):
        final_verdict = "block"
        decision_source: Literal["scan", "policy"] = "scan"
        should_halt = True
        should_warn = False
    else:
        final_verdict = policy_resp.verdict
        decision_source = "policy"
        should_halt = policy_resp.should_halt
        should_warn = policy_resp.should_warn

    return GuardDecisionResponse(
        action_type=request.action_type,
        target=request.target,
        content=request.content,
        policy_mode=policy_mode,
        verdict=final_verdict,
        decision_source=decision_source,
        should_halt=should_halt,
        should_warn=should_warn,
        matched_patterns=matched_patterns,
        client_id=request.client_id,
        session_id=request.session_id,
    )