from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import require_api_key
from app.services.behavioral_baseline import (
    get_behavioral_baseline_store,
)

router = APIRouter(
    prefix="/agents",
    tags=["behavioral-baseline"],
    dependencies=[Depends(require_api_key)],
)


# ---------------------------------------------------------------------------
# POST /agents/{agent_id}/observations
# Record a single behavioral observation for an agent.
# ---------------------------------------------------------------------------


@router.post(
    "/{agent_id}/observations",
    status_code=status.HTTP_201_CREATED,
)
def record_observation(agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    action_type = payload.get("action_type")
    target = payload.get("target", "")
    risk_score = payload.get("risk_score", 0)

    if not action_type:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="action_type is required.",
        )

    try:
        obs = get_behavioral_baseline_store().record_observation(
            agent_id=agent_id,
            action_type=str(action_type),
            target=str(target),
            risk_score=int(risk_score),
            session_id=payload.get("session_id"),
            client_id=payload.get("client_id"),
            matched_patterns=payload.get("matched_patterns"),
            metadata=payload.get("metadata"),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return obs.to_dict()


# ---------------------------------------------------------------------------
# POST /agents/{agent_id}/observations/bulk
# Record multiple observations in a single call.
# ---------------------------------------------------------------------------


@router.post(
    "/{agent_id}/observations/bulk",
    status_code=status.HTTP_201_CREATED,
)
def record_observations_bulk(agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    observations = payload.get("observations")
    if not isinstance(observations, list) or not observations:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="observations must be a non-empty list.",
        )

    client_id = payload.get("client_id")

    try:
        recorded = get_behavioral_baseline_store().record_observations_bulk(
            agent_id=agent_id,
            observations=observations,
            client_id=client_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return {
        "agent_id": agent_id,
        "recorded_count": len(recorded),
        "observations": [o.to_dict() for o in recorded],
    }


# ---------------------------------------------------------------------------
# GET /agents/{agent_id}/observations
# Retrieve recent observations for an agent.
# ---------------------------------------------------------------------------


@router.get("/{agent_id}/observations")
def get_observations(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    session_id: str | None = Query(default=None, alias="sessionId"),
) -> dict[str, Any]:
    try:
        obs = get_behavioral_baseline_store().get_observations(
            agent_id,
            limit=limit,
            session_id=session_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return {
        "agent_id": agent_id,
        "observation_count": len(obs),
        "observations": [o.to_dict() for o in obs],
    }


# ---------------------------------------------------------------------------
# GET /agents/{agent_id}/baseline
# Retrieve the current learned baseline profile for an agent.
# ---------------------------------------------------------------------------


@router.get("/{agent_id}/baseline")
def get_baseline(agent_id: str) -> dict[str, Any]:
    try:
        baseline = get_behavioral_baseline_store().get_baseline(agent_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if baseline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baseline found for agent '{agent_id}'.",
        )

    return baseline.to_dict()


# ---------------------------------------------------------------------------
# GET /agents/{agent_id}/drift
# Compute and return a real-time behavioral drift report.
# ---------------------------------------------------------------------------


@router.get("/{agent_id}/drift")
def compute_drift(
    agent_id: str,
    session_id: str | None = Query(default=None, alias="sessionId"),
    client_id: str | None = Query(default=None, alias="clientId"),
    window_seconds: int | None = Query(default=None, ge=60, le=86400, alias="windowSeconds"),
) -> dict[str, Any]:
    try:
        report = get_behavioral_baseline_store().compute_drift(
            agent_id,
            session_id=session_id,
            client_id=client_id,
            window_seconds=window_seconds,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return report.to_dict()


# ---------------------------------------------------------------------------
# POST /agents/{agent_id}/baseline/invalidate
# Mark the baseline as stale, forcing a rebuild on next observation.
# ---------------------------------------------------------------------------


@router.post("/{agent_id}/baseline/invalidate")
def invalidate_baseline(agent_id: str) -> dict[str, Any]:
    try:
        found = get_behavioral_baseline_store().invalidate_baseline(agent_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baseline found for agent '{agent_id}'.",
        )

    return {"agent_id": agent_id, "status": "stale"}


# ---------------------------------------------------------------------------
# POST /agents/{agent_id}/baseline/suspend
# Suspend an agent's profile pending operator review.
# ---------------------------------------------------------------------------


@router.post("/{agent_id}/baseline/suspend")
def suspend_baseline(agent_id: str) -> dict[str, Any]:
    try:
        found = get_behavioral_baseline_store().suspend_baseline(agent_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baseline found for agent '{agent_id}'.",
        )

    return {"agent_id": agent_id, "status": "suspended"}


# ---------------------------------------------------------------------------
# DELETE /agents/{agent_id}/baseline
# Purge all observations and the baseline for an agent.
# ---------------------------------------------------------------------------


@router.delete(
    "/{agent_id}/baseline",
    status_code=status.HTTP_200_OK,
)
def delete_baseline(agent_id: str) -> dict[str, Any]:
    try:
        found = get_behavioral_baseline_store().purge_agent(agent_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No data found for agent '{agent_id}'.",
        )

    return {"agent_id": agent_id, "purged": True}


# ---------------------------------------------------------------------------
# GET /agents/baselines
# List all known agent baselines with optional filters.
# ---------------------------------------------------------------------------


@router.get("/baselines")
def list_baselines(
    client_id: str | None = Query(default=None, alias="clientId"),
    baseline_status: str | None = Query(
        default=None,
        alias="status",
        pattern="^(learning|active|stale|suspended)$",
    ),
) -> dict[str, Any]:
    baselines = get_behavioral_baseline_store().list_baselines(
        client_id=client_id,
        status=baseline_status,  # type: ignore[arg-type]
    )
    return {
        "count": len(baselines),
        "baselines": [b.to_dict() for b in baselines],
    }
