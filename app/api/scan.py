from __future__ import annotations

from collections import defaultdict, deque
import time

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response

from app.core.auth import AuthContext, require_auth_context
from app.core.errors import AppError
from app.schemas.scan import (
    BatchScanRequest,
    BatchScanResponse,
    ScanRequest,
    ScanResult,
)
from app.services.history import append_scan_result
from app.services.intake_service import prepare_intake
from app.services.sandbox_service import apply_sandbox_policy, evaluate_sandbox
from app.services.scanner import RULE_INDEX, get_rule_severities, perform_scan
from app.services.telemetry import append_telemetry_event
from app.services.telemetry_service import (
    TelemetryEventInput,
    build_agent_event,
    post_telemetry_batch_async,
)

router = APIRouter()

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = 30
_rate_limit_buckets: dict[str, deque[float]] = defaultdict(deque)

_VALID_VERDICTS = {"allow", "warn", "quarantine", "block"}
_VALID_REVIEW_STATUSES = {"none", "pending", "approved", "rejected"}


def _apply_scan_security_headers(response: Response) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"


def _client_rate_limit_key(request: Request, payload: ScanRequest | None = None) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded.strip():
        first_ip = forwarded.split(",")[0].strip()
        if first_ip:
            return first_ip

    if payload is not None and payload.client_id:
        client_id = str(payload.client_id).strip()
        if client_id:
            return f"client:{client_id}"

    host = request.client.host if request.client else "unknown"
    return f"ip:{host}"


def _enforce_scan_rate_limit(key: str) -> tuple[int, int]:
    now = time.time()
    bucket = _rate_limit_buckets[key]

    while bucket and now - bucket[0] > _RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= _RATE_LIMIT_MAX_REQUESTS:
        retry_after = max(1, int(_RATE_LIMIT_WINDOW_SECONDS - (now - bucket[0])))
        raise AppError(
            error="scan_rate_limit_exceeded",
            message="Too many scan requests. Please retry shortly.",
            status_code=429,
            details={
                "rate_limit_key": key,
                "window_seconds": _RATE_LIMIT_WINDOW_SECONDS,
                "max_requests": _RATE_LIMIT_MAX_REQUESTS,
                "retry_after_seconds": retry_after,
            },
        )

    bucket.append(now)
    remaining = max(0, _RATE_LIMIT_MAX_REQUESTS - len(bucket))
    return _RATE_LIMIT_MAX_REQUESTS, remaining


def _sandbox_decision_to_dict(sandbox_decision):
    if hasattr(sandbox_decision, "model_dump"):
        return sandbox_decision.model_dump()
    if hasattr(sandbox_decision, "dict"):
        return sandbox_decision.dict()
    return getattr(sandbox_decision, "__dict__", sandbox_decision)


def _severity_rank(severity: str) -> int:
    order = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return order.get(severity, 0)


def _max_severity(matched_patterns: list[str]) -> str | None:
    severities = get_rule_severities(matched_patterns)
    if not severities:
        return None
    return max(severities, key=_severity_rank)


def _primary_category(matched_patterns: list[str]) -> str | None:
    for match in matched_patterns:
        if match in RULE_INDEX:
            return RULE_INDEX[match]["category"]
    return None


def _build_explanation(result: dict) -> str:
    matched_patterns = result.get("matched_patterns", [])
    verdict = result.get("verdict", "allow")
    max_severity = _max_severity(matched_patterns)
    primary_category = _primary_category(matched_patterns)

    if not matched_patterns:
        return "No risky patterns were matched."

    parts = [f"Matched {len(matched_patterns)} pattern(s)"]
    if primary_category:
        parts.append(f"primary category: {primary_category}")
    if max_severity:
        parts.append(f"max severity: {max_severity}")
    parts.append(f"final verdict: {verdict}")
    return "; ".join(parts) + "."


def _coerce_result_scalars(result: dict) -> dict:
    verdict = result.get("verdict")
    if not isinstance(verdict, str) or verdict not in _VALID_VERDICTS:
        result["verdict"] = "allow"

    review_status = result.get("review_status")
    if not isinstance(review_status, str) or review_status not in _VALID_REVIEW_STATUSES:
        result["review_status"] = "none"

    quarantine_reason = result.get("quarantine_reason")
    if quarantine_reason is not None and not isinstance(quarantine_reason, str):
        result["quarantine_reason"] = str(quarantine_reason)

    failed_checks = result.get("failed_checks")
    if isinstance(failed_checks, list):
        result["failed_checks"] = [item if isinstance(item, str) else str(item) for item in failed_checks]
    elif failed_checks is not None:
        result["failed_checks"] = []

    return result


def _build_scan_completed_event(saved: dict, client_id: str | None) -> TelemetryEventInput:
    scan_id = str(saved.get("scan_id") or "")
    verdict = str(saved.get("verdict") or "allow")
    target_type = str(saved.get("target_type") or "")
    risk_score = saved.get("risk_score")

    return build_agent_event(
        source="ironclaw.scan",
        metric_name="scan_completed",
        metric_type="event",
        org_id=str(client_id) if client_id else None,
        value_text=verdict,
        value_numeric=float(risk_score) if risk_score is not None else None,
        dimensions={
            "scan_id": scan_id,
            "verdict": verdict,
            "target_type": target_type,
            "untrusted": saved.get("untrusted"),
            "max_severity": saved.get("max_severity"),
            "primary_category": saved.get("primary_category"),
            "client_id": client_id,
        },
        extra_key_seed=f"{scan_id}:{verdict}",
    )


async def _flush_scan_event_async(event: TelemetryEventInput) -> None:
    try:
        await post_telemetry_batch_async([event])
    except Exception:  # noqa: BLE001
        pass


def _run_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanResult:
    try:
        intake = prepare_intake(request.target_type, request.target_value)
    except ValueError as exc:
        append_telemetry_event(
            "scan_intake_error",
            {
                "target_type": request.target_type,
                "target_value": request.target_value,
                "client_id": request.client_id,
                "error": str(exc),
            },
        )
        raise AppError(
            error="invalid_scan_input",
            message=str(exc),
            status_code=400,
            details={
                "target_type": request.target_type,
                "target_value": request.target_value,
            },
        ) from exc

    append_telemetry_event(
        "scan_intake_prepared",
        {
            "target_type": intake.target_type,
            "target_value": intake.target_value,
            "client_id": request.client_id,
            "route_mode": intake.route_mode,
            "requires_sandbox": intake.requires_sandbox,
        },
    )

    result = perform_scan(intake.target_type, intake.target_value)

    sandbox_decision = evaluate_sandbox(
        intake.target_type,
        intake.route_mode,
        intake.requires_sandbox,
    )

    append_telemetry_event(
        "scan_sandbox_evaluated",
        {
            "target_type": intake.target_type,
            "route_mode": intake.route_mode,
            "requires_sandbox": intake.requires_sandbox,
            "client_id": request.client_id,
            "sandbox_decision": _sandbox_decision_to_dict(sandbox_decision),
        },
    )

    result = apply_sandbox_policy(result, sandbox_decision)
    result = _coerce_result_scalars(result)
    result["client_id"] = request.client_id

    saved = append_scan_result(result)

    matched_patterns = result.get("matched_patterns", [])
    saved["client_id"] = request.client_id
    saved["max_severity"] = _max_severity(matched_patterns)
    saved["primary_category"] = _primary_category(matched_patterns)
    saved["explanation"] = _build_explanation(result)

    append_telemetry_event(
        "scan_completed",
        {
            "scan_id": saved.get("scan_id"),
            "verdict": saved.get("verdict"),
            "risk_score": saved.get("risk_score"),
            "target_type": saved.get("target_type"),
            "untrusted": saved.get("untrusted"),
            "client_id": request.client_id,
            "max_severity": saved.get("max_severity"),
            "primary_category": saved.get("primary_category"),
        },
    )

    scan_event = _build_scan_completed_event(saved, request.client_id)
    background_tasks.add_task(_flush_scan_event_async, scan_event)

    return ScanResult(**saved)


@router.post("/", response_model=ScanResult)
def create_scan(
    request: ScanRequest,
    http_request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    _auth: AuthContext = Depends(require_auth_context),
):
    key = _client_rate_limit_key(http_request, request)
    limit, remaining = _enforce_scan_rate_limit(key)

    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    _apply_scan_security_headers(response)

    append_telemetry_event(
        "scan_rate_limit_checked",
        {
            "rate_limit_key": key,
            "limit": limit,
            "remaining": remaining,
            "client_id": request.client_id,
        },
    )

    return _run_scan(request, background_tasks)


@router.post("/batch", response_model=BatchScanResponse)
def create_scan_batch(
    request: BatchScanRequest,
    http_request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    _auth: AuthContext = Depends(require_auth_context),
):
    key = _client_rate_limit_key(http_request)
    limit, remaining = _enforce_scan_rate_limit(key)

    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    _apply_scan_security_headers(response)

    append_telemetry_event(
        "scan_batch_rate_limit_checked",
        {
            "rate_limit_key": key,
            "limit": limit,
            "remaining": remaining,
            "item_count": len(request.items),
        },
    )

    results = [_run_scan(item, background_tasks) for item in request.items]
    return BatchScanResponse(
        count=len(results),
        items=results,
    )
