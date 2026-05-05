from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from client import IronClawClient, ScanResult
from supabaseclient import (
    SupabaseAPIError,
    SupabaseClient,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    createsupabaseclient,
)

TargetType = Literal["text", "url", "githubrepo", "archive"]
SandboxLane = Literal[
    "none",
    "prompt_injection",
    "code_execution",
    "exfiltration",
    "high_risk_misc",
]
ActionType = Literal["allow", "warn", "block", "quarantine"]
ScanMode = Literal["enforce", "monitor", "strict"]

app = FastAPI(title="IronClaw-Security API")

# NOTE: keep this aligned with the real local engine port for IronClaw-Security.
engine_client = IronClawClient(base_url="http://127.0.0.1:8010")


class ScanRequest(BaseModel):
    target_type: TargetType
    target_value: str
    mode: ScanMode = "enforce"
    source: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    context: str | None = None


class ScanResponse(BaseModel):
    scan_id: str | None = None
    verdict: str
    action: ActionType
    mode: ScanMode = "enforce"
    summary: str
    target_type: str
    target_value: str
    risk_score: int
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    quarantine_reason: str | None = None
    review_status: Literal["none", "pending", "approved", "rejected"] = "none"
    reviewer: str | None = None
    reviewed_at: str | None = None
    untrusted: bool = False
    sandbox_lane: SandboxLane = "none"
    timestamp: str | None = None
    max_severity: Literal["low", "medium", "high", "critical"] | None = None
    primary_category: str | None = None
    explanation: str | None = None
    source: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    context: str | None = None


class ScanHistoryItem(ScanResponse):
    id: str | None = None
    created_at: str | None = None


class ScanHistoryResponse(BaseModel):
    count: int
    items: list[ScanHistoryItem] = Field(default_factory=list)


class ReviewUpdateRequest(BaseModel):
    review_status: Literal["approved", "rejected"]
    reviewer: str | None = None


class ReviewUpdateResponse(BaseModel):
    id: str
    review_status: Literal["none", "pending", "approved", "rejected"]
    reviewer: str | None = None
    reviewed_at: str | None = None


class StatsResponse(BaseModel):
    total_scans: int
    total_threats_blocked: int
    total_quarantined: int
    total_blocked: int
    threats_blocked_last_24h: int


class ScanBatchItem(BaseModel):
    client_id: str
    target_type: TargetType
    target_value: str
    mode: ScanMode = "enforce"
    source: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    context: str | None = None


class ScanBatchRequest(BaseModel):
    items: list[ScanBatchItem] = Field(default_factory=list)


class ScanBatchItemResponse(ScanResponse):
    client_id: str


class ScanBatchResponse(BaseModel):
    items: list[ScanBatchItemResponse] = Field(default_factory=list)


class BrainDecisionRequest(BaseModel):
    target_type: TargetType
    target_value: str
    mode: ScanMode = "enforce"
    source: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    context: str | None = None
    use_history: bool = True
    max_history: int = 20


class BrainDecision(BaseModel):
    final_action: ActionType
    confidence: float = 1.0
    reason: str
    recommended_mode: ScanMode = "enforce"


class BrainDecisionResponse(BaseModel):
    decision: BrainDecision
    scan: ScanResponse
    related_history: list[ScanHistoryItem] = Field(default_factory=list)


# --- Supabase wiring for history (using SupabaseClient) ---


def _get_supabase_client() -> SupabaseClient | None:
    """
    Build a SupabaseClient for history operations.

    History is best-effort; if configuration is missing or Supabase is down,
    we return None and treat history as disabled rather than failing scans.
    """
    try:
        return createsupabaseclient()
    except SupabaseConfigurationError:
        # Supabase not configured; history disabled.
        return None
    except Exception:
        # Any other bootstrap failure should not break the service path.
        return None


def _insert_scan_history_row(row: dict[str, Any]) -> None:
    client = _get_supabase_client()
    if client is None:
        return
    try:
        client.insert("scanhistory", row)
    except (SupabaseConnectionError, SupabaseAPIError):
        # History is non-critical; logging is handled inside the client.
        return
    except Exception:
        return


def _list_scan_history_rows(
    *,
    limit: int = 50,
    verdict: str | None = None,
    sandbox_lane: str | None = None,
    review_status: str | None = None,
) -> list[dict[str, Any]]:
    client = _get_supabase_client()
    if client is None:
        return []

    filters: dict[str, Any] = {}
    if verdict:
        filters["verdict"] = verdict
    if sandbox_lane:
        filters["sandbox_lane"] = sandbox_lane
    if review_status:
        filters["review_status"] = review_status

    try:
        rows = client.select(
            "scanhistory",
            filters=filters or None,
            limit=limit,
            order=("timestamp", "desc"),
        )
    except (SupabaseConnectionError, SupabaseAPIError):
        return []
    except Exception:
        return []

    # Ensure dict[str, Any] shape
    return [dict(r) for r in rows]


def _update_scan_history_status_row(
    *,
    id: str,
    review_status: str,
    reviewer: str,
    reviewed_at: str,
) -> dict[str, Any] | None:
    client = _get_supabase_client()
    if client is None:
        return None
    try:
        rows = client.update(
            "scanhistory",
            payload={
                "review_status": review_status,
                "reviewer": reviewer,
                "reviewed_at": reviewed_at,
            },
            filters={"id": id},
        )
    except (SupabaseConnectionError, SupabaseAPIError):
        return None
    except Exception:
        return None

    if not rows:
        return None
    return dict(rows[0])


# --- Local decision helpers ---


def _normalize_action(verdict: str) -> ActionType:
    v = verdict.lower()
    if v in ("allow",):
        return "allow"
    if v in ("warn", "warning"):
        return "warn"
    if v in ("quarantine", "quarantined"):
        return "quarantine"
    return "block"


def _apply_mode_to_action(action: ActionType, mode: ScanMode) -> ActionType:
    if mode == "monitor":
        if action in ("block", "quarantine"):
            return "warn"
        return action

    if mode == "strict":
        if action == "warn":
            return "quarantine"
        return action

    return action


def _record_history_from_result(result: ScanResult, meta: dict | None = None) -> None:
    meta = meta or {}
    history_row: dict[str, Any] = {
        "scan_id": getattr(result, "scan_id", None),
        "target_type": result.target_type,
        "target_value": result.target_value[:5000],
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "matched_patterns": getattr(result, "matched_patterns", []),
        "summary": result.summary,
        "sandbox_lane": getattr(result, "sandbox_lane", "none"),
        "quarantine_reason": getattr(result, "quarantine_reason", None),
        "review_status": getattr(result, "review_status", "none"),
        "untrusted": getattr(result, "untrusted", False),
        "max_severity": getattr(result, "max_severity", None),
        "primary_category": getattr(result, "primary_category", None),
        "explanation": getattr(result, "explanation", None),
        "risky_files": getattr(result, "risky_files", []),
        "checks_loaded": getattr(result, "checks_loaded", []),
        "failed_checks": getattr(result, "failed_checks", []),
        "timestamp": getattr(result, "timestamp", None),
        "source": meta.get("source"),
        "session_id": meta.get("session_id"),
        "user_id": meta.get("user_id"),
        "context": meta.get("context"),
    }
    _insert_scan_history_row(history_row)


def _scan_result_to_response(
    result: ScanResult,
    mode: ScanMode,
    source: str | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    context: str | None = None,
) -> ScanResponse:
    base_action = _normalize_action(result.verdict)
    final_action = _apply_mode_to_action(base_action, mode)

    return ScanResponse(
        scan_id=getattr(result, "scan_id", None),
        verdict=result.verdict,
        action=final_action,
        mode=mode,
        summary=result.summary,
        target_type=result.target_type,
        target_value=result.target_value,
        risk_score=result.risk_score,
        matched_patterns=getattr(result, "matched_patterns", []),
        risky_files=getattr(result, "risky_files", []),
        checks_loaded=getattr(result, "checks_loaded", []),
        failed_checks=getattr(result, "failed_checks", []),
        quarantine_reason=getattr(result, "quarantine_reason", None),
        review_status=getattr(result, "review_status", "none"),
        reviewer=None,
        reviewed_at=None,
        untrusted=getattr(result, "untrusted", False),
        sandbox_lane=getattr(result, "sandbox_lane", "none"),
        timestamp=getattr(result, "timestamp", None),
        max_severity=getattr(result, "max_severity", None),
        primary_category=getattr(result, "primary_category", None),
        explanation=getattr(result, "explanation", None),
        source=source,
        session_id=session_id,
        user_id=user_id,
        context=context,
    )


def _fetch_related_history(
    session_id: str | None,
    user_id: str | None,
    max_history: int,
) -> list[ScanHistoryItem]:
    rows = _list_scan_history_rows(limit=max_history)
    if not rows:
        return []

    related_rows: list[dict[str, Any]] = []
    for row in rows:
        if session_id and row.get("session_id") == session_id:
            related_rows.append(row)
        elif user_id and row.get("user_id") == user_id:
            related_rows.append(row)

    items = [
        ScanHistoryItem(
            id=row.get("id"),
            created_at=row.get("created_at"),
            scan_id=row.get("scan_id"),
            verdict=row["verdict"],
            action=_normalize_action(row["verdict"]),
            mode="enforce",
            summary=row["summary"],
            target_type=row["target_type"],
            target_value=row["target_value"],
            risk_score=row["risk_score"],
            matched_patterns=row.get("matched_patterns", []),
            risky_files=row.get("risky_files", []),
            checks_loaded=row.get("checks_loaded", []),
            failed_checks=row.get("failed_checks", []),
            quarantine_reason=row.get("quarantine_reason"),
            review_status=row.get("review_status", "none"),
            reviewer=row.get("reviewer"),
            reviewed_at=row.get("reviewed_at"),
            untrusted=row.get("untrusted", False),
            sandbox_lane=row.get("sandbox_lane", "none"),
            timestamp=row.get("timestamp"),
            max_severity=row.get("max_severity"),
            primary_category=row.get("primary_category"),
            explanation=row.get("explanation"),
            source=row.get("source"),
            session_id=row.get("session_id"),
            user_id=row.get("user_id"),
            context=row.get("context"),
        )
        for row in related_rows
    ]
    return items


def _compute_brain_decision(
    scan: ScanResponse,
    related_history: list[ScanHistoryItem],
) -> BrainDecision:
    if scan.action == "allow":
        base = BrainDecision(
            final_action="allow",
            confidence=0.95,
            reason="No risky patterns detected; content appears safe to use.",
            recommended_mode=scan.mode,
        )
    elif scan.action == "warn":
        base = BrainDecision(
            final_action="warn",
            confidence=0.85,
            reason="Low to moderate risk patterns detected; proceed with caution and consider user confirmation.",
            recommended_mode=scan.mode,
        )
    elif scan.action == "quarantine":
        base = BrainDecision(
            final_action="quarantine",
            confidence=0.9,
            reason="Risky patterns detected; content was quarantined by the engine and should not be executed directly.",
            recommended_mode="enforce",
        )
    else:
        base = BrainDecision(
            final_action="block",
            confidence=0.95,
            reason="High risk detected; execution or use of this content should be blocked.",
            recommended_mode="enforce",
        )

    if not related_history:
        return base

    prior_high_risk = [
        h
        for h in related_history
        if h.verdict in ("quarantine", "block")
        or h.sandbox_lane in ("prompt_injection", "code_execution", "exfiltration")
    ]

    if not prior_high_risk:
        return base

    count = len(prior_high_risk)
    boosted_confidence = min(1.0, base.confidence + 0.05)
    extra_reason = (
        f" There are {count} prior high-risk events for this session or user, "
        "indicating potential ongoing prompt abuse or malicious behavior."
    )

    if base.final_action == "warn" and count >= 2:
        return BrainDecision(
            final_action="quarantine",
            confidence=min(1.0, boosted_confidence + 0.05),
            reason=(
                "Repeated suspicious activity was observed across related history. "
                "The current event should be quarantined pending further review."
                + extra_reason
            ),
            recommended_mode="enforce",
        )

    if base.final_action == "allow" and count >= 3:
        return BrainDecision(
            final_action="warn",
            confidence=0.85,
            reason=(
                "The current content appears safe on its own, but related history shows repeated "
                "high-risk activity. Proceed with caution."
                + extra_reason
            ),
            recommended_mode="enforce",
        )

    return BrainDecision(
        final_action=base.final_action,
        confidence=boosted_confidence,
        reason=base.reason + extra_reason,
        recommended_mode=base.recommended_mode,
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "IronClaw-Security"}


@app.get("/history", response_model=ScanHistoryResponse)
async def history_endpoint(
    limit: int = 50,
    verdict: str | None = None,
    sandbox_lane: str | None = None,
    review_status: str | None = None,
) -> ScanHistoryResponse:
    rows = _list_scan_history_rows(
        limit=limit,
        verdict=verdict,
        sandbox_lane=sandbox_lane,
        review_status=review_status,
    )
    if rows is None:
        raise HTTPException(status_code=502, detail="History query failed")

    items = [
        ScanHistoryItem(
            id=row.get("id"),
            created_at=row.get("created_at"),
            scan_id=row.get("scan_id"),
            verdict=row["verdict"],
            action=_normalize_action(row["verdict"]),
            mode="enforce",
            summary=row["summary"],
            target_type=row["target_type"],
            target_value=row["target_value"],
            risk_score=row["risk_score"],
            matched_patterns=row.get("matched_patterns", []),
            risky_files=row.get("risky_files", []),
            checks_loaded=row.get("checks_loaded", []),
            failed_checks=row.get("failed_checks", []),
            quarantine_reason=row.get("quarantine_reason"),
            review_status=row.get("review_status", "none"),
            reviewer=row.get("reviewer"),
            reviewed_at=row.get("reviewed_at"),
            untrusted=row.get("untrusted", False),
            sandbox_lane=row.get("sandbox_lane", "none"),
            timestamp=row.get("timestamp"),
            max_severity=row.get("max_severity"),
            primary_category=row.get("primary_category"),
            explanation=row.get("explanation"),
            source=row.get("source"),
            session_id=row.get("session_id"),
            user_id=row.get("user_id"),
            context=row.get("context"),
        )
        for row in rows
    ]

    return ScanHistoryResponse(count=len(items), items=items)


@app.post("/history/{id}/review", response_model=ReviewUpdateResponse)
async def review_history_item(id: str, body: ReviewUpdateRequest) -> ReviewUpdateResponse:
    rows = _list_scan_history_rows(limit=500)
    if rows is None:
        raise HTTPException(status_code=502, detail="Review lookup failed")

    existing = next((row for row in rows if row.get("id") == id), None)
    if not existing:
        raise HTTPException(status_code=404, detail="Scan history item not found")

    current_status = existing.get("review_status", "none")
    if current_status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot review item with status '{current_status}'. Only 'pending' items can be reviewed.",
        )

    reviewer = (body.reviewer or "manual-review").strip() or "manual-review"
    reviewed_at = datetime.now(timezone.utc).isoformat()

    row = _update_scan_history_status_row(
        id=id,
        review_status=body.review_status,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
    )
    if not row or "id" not in row:
        raise HTTPException(status_code=404, detail="Scan history item not found")

    return ReviewUpdateResponse(
        id=row["id"],
        review_status=row.get("review_status", "none"),
        reviewer=row.get("reviewer"),
        reviewed_at=row.get("reviewed_at"),
    )


@app.get("/stats", response_model=StatsResponse)
async def stats_endpoint() -> StatsResponse:
    rows = _list_scan_history_rows(limit=500)
    if rows is None:
        raise HTTPException(status_code=502, detail="Stats query failed")

    total_scans = len(rows)
    total_quarantined = sum(1 for r in rows if r.get("verdict") == "quarantine")
    total_blocked = sum(1 for r in rows if r.get("verdict") == "block")
    total_threats_blocked = total_quarantined + total_blocked

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    threats_blocked_last_24h = 0
    for r in rows:
        if r.get("verdict") not in ("block", "quarantine"):
            continue
        ts = r.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            continue
        if dt >= cutoff:
            threats_blocked_last_24h += 1

    return StatsResponse(
        total_scans=total_scans,
        total_threats_blocked=total_threats_blocked,
        total_quarantined=total_quarantined,
        total_blocked=total_blocked,
        threats_blocked_last_24h=threats_blocked_last_24h,
    )


@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest) -> ScanResponse:
    result: ScanResult = engine_client.scan(
        target_type=request.target_type,
        target_value=request.target_value,
    )

    _record_history_from_result(
        result,
        meta={
            "source": request.source,
            "session_id": request.session_id,
            "user_id": request.user_id,
            "context": request.context,
        },
    )

    return _scan_result_to_response(
        result=result,
        mode=request.mode,
        source=request.source,
        session_id=request.session_id,
        user_id=request.user_id,
        context=request.context,
    )


@app.post("/scan/batch", response_model=ScanBatchResponse)
async def scan_batch_endpoint(request: ScanBatchRequest) -> ScanBatchResponse:
    responses: list[ScanBatchItemResponse] = []

    for item in request.items:
        result: ScanResult = engine_client.scan(
            target_type=item.target_type,
            target_value=item.target_value,
        )

        _record_history_from_result(
            result,
            meta={
                "source": item.source,
                "session_id": item.session_id,
                "user_id": item.user_id,
                "context": item.context,
            },
        )

        scan_response = _scan_result_to_response(
            result=result,
            mode=item.mode,
            source=item.source,
            session_id=item.session_id,
            user_id=item.user_id,
            context=item.context,
        )

        responses.append(
            ScanBatchItemResponse(
                client_id=item.client_id,
                **scan_response.model_dump(),
            )
        )

    return ScanBatchResponse(items=responses)


@app.post("/brain/decision", response_model=BrainDecisionResponse)
async def brain_decision_endpoint(body: BrainDecisionRequest) -> BrainDecisionResponse:
    scan_result: ScanResult = engine_client.scan(
        target_type=body.target_type,
        target_value=body.target_value,
    )

    _record_history_from_result(
        scan_result,
        meta={
            "source": body.source,
            "session_id": body.session_id,
            "user_id": body.user_id,
            "context": body.context,
        },
    )

    scan_response = _scan_result_to_response(
        result=scan_result,
        mode=body.mode,
        source=body.source,
        session_id=body.session_id,
        user_id=body.user_id,
        context=body.context,
    )

    related_history: list[ScanHistoryItem] = []
    if body.use_history and (body.session_id or body.user_id):
        related_history = _fetch_related_history(
            session_id=body.session_id,
            user_id=body.user_id,
            max_history=body.max_history,
        )

    decision = _compute_brain_decision(scan_response, related_history)

    return BrainDecisionResponse(
        decision=decision,
        scan=scan_response,
        related_history=related_history,
    )