from __future__ import annotations

from datetime import UTC, datetime
import logging
import time
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from app.core.auth import AuthContext, get_auth_context
from app.schemas.threat_detection import (
    HuntMatch,
    HuntQuery,
    HuntResult,
    HuntStatusEnum,
)
from app.services.threat_hunt_service import ThreatHuntService, get_threat_hunt_service

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router — prefix /threat
# Owns POST /threat/hunt and its supporting endpoints.
# Distinct from app.api.threat_detection which owns /threat/detect.
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/threat",
    tags=["threat-hunt"],
)

# ---------------------------------------------------------------------------
# UTC / timing helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _elapsed_ms(start: float) -> int:
    return max(0, int((time.monotonic() - start) * 1000))


# ---------------------------------------------------------------------------
# Supabase client — graceful degradation
# ---------------------------------------------------------------------------


def _get_supabase_client() -> Any | None:
    try:
        from app.clients.supabase import get_supabase_client as _get  # noqa: PLC0415

        return _get()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Telemetry emission — background-safe, fail-open
# ---------------------------------------------------------------------------


def _emit_hunt_telemetry(
    result: HuntResult,
    *,
    elapsed_ms: int,
) -> None:
    try:
        from app.services.telemetry import emit_event  # noqa: PLC0415

        emit_event(
            event_type="threat_hunt",
            payload={
                "hunt_id": result.hunt_id,
                "org_id": result.org_id,
                "status": result.status.value,
                "total_matches": result.total_matches,
                "duration_ms": result.duration_ms,
                "elapsed_ms": elapsed_ms,
                "query_summary": result.query_summary,
            },
        )
    except ImportError:
        pass
    except Exception as exc:
        logger.error(
            "threat_hunt.api.telemetry error hunt_id=%s: %s",
            result.hunt_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Alert bridging — background-safe, fail-open
# Emits an alert when a hunt completes with one or more matches above threshold.
# ---------------------------------------------------------------------------


def _emit_hunt_alert_if_needed(result: HuntResult) -> None:
    if result.status != HuntStatusEnum.COMPLETED:
        return
    if result.total_matches == 0:
        return
    try:
        from app.services.threat_alerts import emit_hunt_alert  # noqa: PLC0415

        emit_hunt_alert(result)
    except ImportError:
        pass
    except Exception as exc:
        logger.error(
            "threat_hunt.api.emit_alert error hunt_id=%s: %s",
            result.hunt_id,
            exc,
        )


# ---------------------------------------------------------------------------
# POST /threat/hunt — primary threat hunt endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/hunt",
    response_model=HuntResult,
    status_code=status.HTTP_200_OK,
    summary="Run a retrospective threat hunt",
    description=(
        "Sweeps the threat_detections history for matching IOC values, MITRE technique IDs, "
        "CVE identifiers, or risk families within an optional time window. "
        "Accepts a HuntQuery with any combination of hunt criteria. "
        "Returns a HuntResult with status, total_matches, and a list of HuntMatch objects. "
        "Telemetry is emitted and alert bridge triggered asynchronously on completion with matches."
    ),
    responses={
        200: {"description": "Hunt completed — status in [completed, failed]"},
        400: {"description": "Invalid request — no hunt criteria provided"},
        500: {"description": "Hunt service error"},
    },
    operation_id="threat_hunt_run",
)
async def run_threat_hunt(
    payload: HuntQuery,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(get_auth_context),
    service: ThreatHuntService = Depends(get_threat_hunt_service),
) -> HuntResult:
    # At least one hunt criterion must be present
    if not any(
        [
            payload.ioc_value,
            payload.mitre_technique_id,
            payload.cve_id,
            payload.risk_family,
        ]
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="hunt_no_criteria: provide at least one of ioc_value, mitre_technique_id, cve_id, or risk_family",
        )

    effective_org_id = payload.org_id or auth.org_id
    effective_payload = payload
    if effective_org_id and effective_org_id != payload.org_id:
        effective_payload = payload.model_copy(update={"org_id": effective_org_id})

    t0 = time.monotonic()

    try:
        result = service.run_hunt(effective_payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error(
            "threat_hunt.run_threat_hunt unhandled error org_id=%s: %s",
            effective_org_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="threat_hunt_service_error",
        ) from exc

    elapsed = _elapsed_ms(t0)

    logger.info(
        "threat_hunt.run_threat_hunt hunt_id=%s org_id=%s status=%s matches=%d duration_ms=%d elapsed_ms=%d",
        result.hunt_id,
        result.org_id,
        result.status.value,
        result.total_matches,
        result.duration_ms,
        elapsed,
    )

    background_tasks.add_task(
        _emit_hunt_telemetry,
        result,
        elapsed_ms=elapsed,
    )
    background_tasks.add_task(_emit_hunt_alert_if_needed, result)

    return result


# ---------------------------------------------------------------------------
# GET /threat/hunt/matches — list stored HuntMatch records
# ---------------------------------------------------------------------------


@router.get(
    "/hunt/matches",
    response_model=list[HuntMatch],
    status_code=status.HTTP_200_OK,
    summary="List stored hunt match records",
    description=("Returns lightweight HuntMatch records from the threat_detections table. " "Filterable by org_id, hunt_id, and minimum_score. " "Results ordered by assessed_at descending."),
    operation_id="threat_hunt_list_matches",
)
async def list_hunt_matches(
    org_id: str | None = Query(default=None),
    hunt_id: str | None = Query(default=None),
    minimum_score: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    client = _get_supabase_client()
    if client is None:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "storage_unavailable"},
        )

    effective_org_id = org_id or auth.org_id

    try:
        q = client.table("threat_detections").select("event_id,org_id,agent_id,session_id,verdict,score,severity," "matched_ioc_value,matched_ioc_type,matched_mitre_technique," "risk_families,context,assessed_at")
        if effective_org_id:
            q = q.eq("org_id", effective_org_id)
        if minimum_score > 0.0:
            q = q.gte("score", minimum_score)
        q = q.order("assessed_at", desc=True).range(offset, offset + limit - 1)
        resp = q.execute()
        rows = resp.data or []
        return JSONResponse(status_code=status.HTTP_200_OK, content=rows)
    except Exception as exc:
        logger.error("threat_hunt.list_hunt_matches error: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# GET /threat/hunt/health — hunt service health probe
# ---------------------------------------------------------------------------


@router.get(
    "/hunt/health",
    status_code=status.HTTP_200_OK,
    summary="Threat hunt service health probe",
    description=("Liveness check for the ThreatHuntService and its dependent services. " "Returns service availability and UTC timestamp."),
    operation_id="threat_hunt_health",
)
async def hunt_health(
    auth: AuthContext = Depends(get_auth_context),
) -> JSONResponse:
    supabase_ok = _get_supabase_client() is not None

    hunt_service_ok = False
    try:
        _ = get_threat_hunt_service()
        hunt_service_ok = True
    except Exception:
        pass

    telemetry_ok = False
    try:
        from app.services.telemetry import emit_event  # noqa: PLC0415

        telemetry_ok = callable(emit_event)
    except ImportError:
        pass

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "ok",
            "service": "ThreatHuntService",
            "hunt_service": "ok" if hunt_service_ok else "unavailable",
            "supabase": "ok" if supabase_ok else "unavailable",
            "telemetry": "ok" if telemetry_ok else "unavailable",
            "timestamp": _utcnow_iso(),
        },
    )


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = ["router"]
