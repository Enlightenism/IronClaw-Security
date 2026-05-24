from __future__ import annotations

from datetime import UTC, datetime
import logging
import time
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from app.core.auth import AuthContext, get_auth_context
from app.schemas.threat_detection import (
    CorrelationSignal,
    DetectionRequest,
    DetectionResult,
    DetectionSummary,
    DetectionVerdict,
    ThreatSeverityLevel,
)
from app.services.threat_detection_engine import get_detection_engine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router — prefix /threat/detect (single detection entry point)
# Distinct from app.routers.threat_detection which owns /threat/feeds,
# /threat/hunt, /threat/detections, and /threat/correlations.
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/threat",
    tags=["threat-detection-core"],
)

_TABLE_DETECTIONS = "threat_detections"

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_BLOCK_STATUSES: frozenset[str] = frozenset({DetectionVerdict.BLOCK.value, DetectionVerdict.REVIEW.value})


# ---------------------------------------------------------------------------
# Supabase client — single canonical accessor, graceful degradation
# ---------------------------------------------------------------------------


def _get_supabase_client() -> Any | None:
    try:
        from app.clients.supabase import get_supabase_client as _get  # noqa: PLC0415

        return _get()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# UTC helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _elapsed_ms(start: float) -> int:
    return max(0, int((time.monotonic() - start) * 1000))


# ---------------------------------------------------------------------------
# Persistence — background-safe, fail-open
# ---------------------------------------------------------------------------


def _persist_detection(result: DetectionResult) -> None:
    """
    Upsert the DetectionResult into threat_detections.
    Called from BackgroundTasks — never raises; logs and returns on failure.
    """
    client = _get_supabase_client()
    if client is None:
        logger.warning(
            "threat_detection.api.persist: supabase unavailable — skipping event_id=%s",
            result.event_id,
        )
        return
    try:
        row: dict[str, Any] = {
            "event_id": result.event_id,
            "org_id": result.org_id,
            "agent_id": result.agent_id,
            "session_id": result.session_id,
            "verdict": result.verdict.value,
            "score": result.score,
            "severity": result.severity.value,
            "ioc_match_count": result.ioc_match_count,
            "correlation_signal_count": result.correlation_signal_count,
            "risk_families": result.risk_families,
            "mitre_techniques": result.mitre_techniques,
            "extracted_indicators": result.extracted_indicators,
            "rationale": result.rationale,
            "context": result.context,
            "assessed_at": result.assessed_at,
            "detection_engine_version": result.detection_engine_version,
            "metadata": result.metadata,
        }
        client.table(_TABLE_DETECTIONS).upsert(row, on_conflict="event_id").execute()
        logger.debug(
            "threat_detection.api.persist: saved event_id=%s verdict=%s score=%.3f",
            result.event_id,
            result.verdict.value,
            result.score,
        )
    except Exception as exc:
        logger.error(
            "threat_detection.api.persist error event_id=%s: %s",
            result.event_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Alert bridging — background-safe, fail-open
# ---------------------------------------------------------------------------


def _emit_alert_if_needed(result: DetectionResult) -> None:
    """
    Bridge high-severity DetectionResults into the alert pipeline.
    Delegates to threat_alerts service when verdict is REVIEW or BLOCK.
    """
    if result.verdict not in (DetectionVerdict.REVIEW, DetectionVerdict.BLOCK):
        return
    try:
        from app.services.threat_alerts import emit_detection_alert  # noqa: PLC0415

        emit_detection_alert(result)
    except ImportError:
        pass
    except Exception as exc:
        logger.error(
            "threat_detection.api.emit_alert error event_id=%s: %s",
            result.event_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Telemetry emission — background-safe, fail-open
# ---------------------------------------------------------------------------


def _emit_telemetry(
    result: DetectionResult,
    *,
    elapsed_ms: int,
    caller_context: str | None,
) -> None:
    """
    Push a structured detection telemetry event.
    Delegates to telemetry service; never blocks the response path.
    """
    try:
        from app.services.telemetry import emit_event  # noqa: PLC0415

        emit_event(
            event_type="threat_detection",
            payload={
                "event_id": result.event_id,
                "org_id": result.org_id,
                "agent_id": result.agent_id,
                "session_id": result.session_id,
                "verdict": result.verdict.value,
                "score": result.score,
                "severity": result.severity.value,
                "ioc_match_count": result.ioc_match_count,
                "correlation_signal_count": result.correlation_signal_count,
                "elapsed_ms": elapsed_ms,
                "caller_context": caller_context,
            },
        )
    except ImportError:
        pass
    except Exception as exc:
        logger.error(
            "threat_detection.api.telemetry error event_id=%s: %s",
            result.event_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Internal detection dispatcher — callable by action_guard, action_execute
# ---------------------------------------------------------------------------


def run_detection(
    payload: DetectionRequest,
    *,
    org_id: str | None = None,
    caller_context: str | None = None,
) -> DetectionResult:
    """
    Synchronous detection dispatcher.

    Called by:
      - POST /threat/detect (this router)
      - app.api.action_guard — pre-execution threat screening
      - app.api.action_execute — post-plan threat screening
      - app.api.actionguard — legacy guard path

    Parameters
    ----------
    payload:
        DetectionRequest with at least one observable field set.
    org_id:
        Effective organization scope. Overrides payload.org_id when set.
    caller_context:
        Human-readable label identifying the caller (e.g. 'action_guard',
        'action_execute') — attached to telemetry and logs.

    Returns
    -------
    DetectionResult
        Fully populated result from ThreatDetectionEngine.run().
    """
    engine = get_detection_engine()

    effective_request = payload
    if org_id and org_id != payload.org_id:
        # Rebuild with caller-supplied org_id override
        effective_request = payload.model_copy(update={"org_id": org_id})

    start = time.monotonic()
    result: DetectionResult = engine.run(effective_request)
    elapsed = _elapsed_ms(start)

    logger.info(
        "threat_detection.run_detection event_id=%s org_id=%s verdict=%s " "score=%.3f severity=%s ioc_matches=%d signals=%d elapsed_ms=%d caller=%s",
        result.event_id,
        result.org_id,
        result.verdict.value,
        result.score,
        result.severity.value,
        result.ioc_match_count,
        result.correlation_signal_count,
        elapsed,
        caller_context or "api",
    )

    return result


# ---------------------------------------------------------------------------
# POST /threat/detect — primary detection endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/detect",
    response_model=DetectionResult,
    status_code=status.HTTP_200_OK,
    summary="Run threat detection on an event payload",
    description=(
        "Single entry point for all IronClaw threat detection calls. "
        "Accepts a DetectionRequest with any combination of text, url, domain, "
        "hashes, or ioc_values. Runs the full ThreatDetectionEngine pipeline: "
        "observable extraction → IOC resolution → correlation signal generation → "
        "composite scoring → verdict (allow/monitor/review/block). "
        "Persists the result to threat_detections and emits telemetry asynchronously. "
        "REVIEW and BLOCK verdicts trigger the alert bridge."
    ),
    responses={
        200: {"description": "Detection completed — verdict in [allow, monitor, review, block]"},
        400: {"description": "Invalid request — no observable payload provided"},
        500: {"description": "Detection engine error"},
    },
    operation_id="threat_detection_detect",
)
async def detect_threat(
    payload: DetectionRequest,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(get_auth_context),
) -> DetectionResult:
    effective_org_id = payload.org_id or auth.org_id

    try:
        result = run_detection(
            payload,
            org_id=effective_org_id,
            caller_context="api",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error(
            "threat_detection.detect_threat unhandled error org_id=%s: %s",
            effective_org_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="threat_detection_engine_error",
        ) from exc

    elapsed = _elapsed_ms(time.monotonic())

    background_tasks.add_task(_persist_detection, result)
    background_tasks.add_task(_emit_alert_if_needed, result)
    background_tasks.add_task(
        _emit_telemetry,
        result,
        elapsed_ms=elapsed,
        caller_context="api",
    )

    return result


# ---------------------------------------------------------------------------
# GET /threat/detect/{event_id} — fetch a stored detection by event_id
# ---------------------------------------------------------------------------


@router.get(
    "/detect/{event_id}",
    response_model=DetectionResult,
    status_code=status.HTTP_200_OK,
    summary="Retrieve a stored detection result by event ID",
    description=("Returns the full DetectionResult for a previously stored detection event. " "Returns 404 if the event_id is not found in threat_detections. " "Returns 503 if the Supabase client is unavailable."),
    operation_id="threat_detection_get_by_event_id",
)
async def get_detection_by_event_id(
    event_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "storage_unavailable"},
        )
    try:
        resp = client.table(_TABLE_DETECTIONS).select("*").eq("event_id", event_id).limit(1).execute()
        rows = resp.data or []
        if not rows:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "not_found", "event_id": event_id},
            )
        return JSONResponse(status_code=status.HTTP_200_OK, content=rows[0])
    except Exception as exc:
        logger.error(
            "threat_detection.get_detection_by_event_id error event_id=%s: %s",
            event_id,
            exc,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# GET /threat/detect/summary — paged DetectionSummary list
# ---------------------------------------------------------------------------


@router.get(
    "/detect/summary",
    response_model=list[DetectionSummary],
    status_code=status.HTTP_200_OK,
    summary="List stored detection summaries",
    description=("Returns lightweight DetectionSummary rows from threat_detections. " "Filterable by org_id, agent_id, session_id, verdict, and severity. " "Results ordered by assessed_at descending."),
    operation_id="threat_detection_list_summaries",
)
async def list_detection_summaries(
    org_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    verdict: DetectionVerdict | None = Query(default=None),
    severity: ThreatSeverityLevel | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
) -> list[DetectionSummary]:
    client = _get_supabase_client()
    if client is None:
        return []

    effective_org_id = org_id or auth.org_id

    try:
        query = client.table(_TABLE_DETECTIONS).select("event_id,org_id,agent_id,session_id,verdict,score,severity," "ioc_match_count,correlation_signal_count,assessed_at")
        if effective_org_id:
            query = query.eq("org_id", effective_org_id)
        if agent_id:
            query = query.eq("agent_id", agent_id)
        if session_id:
            query = query.eq("session_id", session_id)
        if verdict:
            query = query.eq("verdict", verdict.value)
        if severity:
            query = query.eq("severity", severity.value)
        query = query.order("assessed_at", desc=True).range(offset, offset + limit - 1)
        resp = query.execute()
        rows = resp.data or []
        return [DetectionSummary(**row) for row in rows]
    except Exception as exc:
        logger.error("threat_detection.list_detection_summaries error: %s", exc)
        return []


# ---------------------------------------------------------------------------
# POST /threat/detect/batch — multi-event detection sweep
# ---------------------------------------------------------------------------


@router.post(
    "/detect/batch",
    response_model=list[DetectionResult],
    status_code=status.HTTP_200_OK,
    summary="Run threat detection on multiple event payloads",
    description=(
        "Accepts a list of DetectionRequest payloads (max 50) and returns a "
        "DetectionResult for each. Each event is detected independently through "
        "the full ThreatDetectionEngine pipeline. Useful for bulk screening of "
        "tool call plans, session histories, or multi-step agent outputs. "
        "Results are persisted and telemetry is emitted asynchronously."
    ),
    responses={
        200: {"description": "All detections completed — individual verdicts per event"},
        400: {"description": "Batch exceeds 50 events or contains invalid requests"},
        500: {"description": "Detection engine error on one or more events"},
    },
    operation_id="threat_detection_detect_batch",
)
async def detect_threat_batch(
    payloads: list[DetectionRequest],
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(get_auth_context),
) -> list[DetectionResult]:
    if not payloads:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="batch_empty: at least one DetectionRequest is required",
        )
    if len(payloads) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"batch_too_large: max 50 events per batch, got {len(payloads)}",
        )

    results: list[DetectionResult] = []
    errors: list[str] = []

    for idx, payload in enumerate(payloads):
        effective_org_id = payload.org_id or auth.org_id
        try:
            result = run_detection(
                payload,
                org_id=effective_org_id,
                caller_context="api_batch",
            )
            results.append(result)
            background_tasks.add_task(_persist_detection, result)
            background_tasks.add_task(_emit_alert_if_needed, result)
        except Exception as exc:
            logger.error(
                "threat_detection.detect_batch error idx=%d org_id=%s: %s",
                idx,
                effective_org_id,
                exc,
            )
            errors.append(f"event[{idx}]: {exc}")

    if errors and not results:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"batch_errors": errors},
        )

    return results


# ---------------------------------------------------------------------------
# GET /threat/detect/correlation/signals — active correlation signal summary
# ---------------------------------------------------------------------------


@router.get(
    "/detect/correlation/signals",
    response_model=list[CorrelationSignal],
    status_code=status.HTTP_200_OK,
    summary="List active correlation signals",
    description=(
        "Returns the most recently generated CorrelationSignal objects from the "
        "ThreatCorrelationEngine. Useful for real-time monitoring of multi-IOC "
        "patterns, attack chains, and temporal clusters. "
        "Delegates to ThreatDetectionEngine.list_correlation_signals() when available; "
        "returns empty list on degraded engine."
    ),
    operation_id="threat_detection_list_correlation_signals",
)
async def list_correlation_signals(
    org_id: str | None = Query(default=None),
    pattern_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    auth: AuthContext = Depends(get_auth_context),
) -> list[CorrelationSignal]:
    engine = get_detection_engine()
    effective_org_id = org_id or auth.org_id

    list_signals = getattr(engine, "list_correlation_signals", None)
    if not callable(list_signals):
        logger.debug("threat_detection.list_correlation_signals: engine does not expose " "list_correlation_signals — returning empty")
        return []

    try:
        return list_signals(
            org_id=effective_org_id,
            pattern_type=pattern_type,
            limit=limit,
        )
    except Exception as exc:
        logger.error("threat_detection.list_correlation_signals error: %s", exc)
        return []


# ---------------------------------------------------------------------------
# GET /threat/detect/health — detection engine health probe
# ---------------------------------------------------------------------------


@router.get(
    "/detect/health",
    status_code=status.HTTP_200_OK,
    summary="Detection engine health probe",
    description=("Lightweight liveness check for the ThreatDetectionEngine and its " "dependent services (ioc_store, threat_correlation). " "Returns engine version, dependency availability, and UTC timestamp."),
    operation_id="threat_detection_health",
)
async def detection_health(
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    engine = get_detection_engine()

    ioc_store_ok = False
    try:
        from app.services.ioc_store import get_ioc_store  # noqa: PLC0415

        _ = get_ioc_store()
        ioc_store_ok = True
    except Exception:
        pass

    correlation_ok = False
    try:
        from app.services.threat_correlation import get_correlation_engine  # noqa: PLC0415

        _ = get_correlation_engine()
        correlation_ok = True
    except Exception:
        pass

    supabase_ok = _get_supabase_client() is not None

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "ok",
            "engine": "ThreatDetectionEngine",
            "engine_version": getattr(engine, "_scoring_engine", None) and "1.0.0",
            "ioc_store": "ok" if ioc_store_ok else "unavailable",
            "threat_correlation": "ok" if correlation_ok else "unavailable",
            "supabase": "ok" if supabase_ok else "unavailable",
            "timestamp": _utcnow_iso(),
        },
    )


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = [
    "router",
    "run_detection",
]
