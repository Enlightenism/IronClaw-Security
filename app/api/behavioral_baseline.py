from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from app.services.behavioral_baseline import (
    AgentBaseline,
    AgentObservation,
    DriftReport,
    get_behavioral_baseline_store,
)

router = APIRouter(tags=["behavioral-baseline"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ObservationRequest(BaseModel):
    action_type: str = Field(..., min_length=1, description="Type of action performed by the agent.")
    target: str = Field(default="", description="Resource or target the action operated on.")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score for this action (0–100).")
    session_id: str | None = Field(default=None, description="Session identifier, if applicable.")
    client_id: str | None = Field(default=None, description="Client identifier, if applicable.")
    matched_patterns: list[str] = Field(default_factory=list, description="Security patterns matched during this action.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary additional context.")

    @field_validator("action_type")
    @classmethod
    def _validate_action_type(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("action_type must be a non-empty string")
        return stripped


class BulkObservationItem(BaseModel):
    action_type: str = Field(..., min_length=1)
    target: str = Field(default="")
    risk_score: int = Field(..., ge=0, le=100)
    session_id: str | None = Field(default=None)
    matched_patterns: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BulkObservationRequest(BaseModel):
    observations: list[BulkObservationItem] = Field(..., min_length=1, description="List of observations to ingest.")
    client_id: str | None = Field(default=None, description="Client identifier applied to all observations.")


class ObservationResponse(BaseModel):
    observation_id: str
    agent_id: str
    session_id: str | None
    client_id: str | None
    timestamp: str
    action_type: str
    target: str
    risk_score: int
    matched_patterns: list[str]
    metadata: dict[str, Any]

    @classmethod
    def from_observation(cls, obs: AgentObservation) -> ObservationResponse:
        return cls(**obs.to_dict())


class BaselineResponse(BaseModel):
    baseline_id: str
    agent_id: str
    client_id: str | None
    status: str
    schema_version: int
    sample_count: int
    created_at: str
    updated_at: str
    mean_action_rate: float
    stdev_action_rate: float
    action_type_distribution: dict[str, float]
    mean_risk_score: float
    stdev_risk_score: float
    mean_target_breadth: float
    stdev_target_breadth: float
    mean_tool_call_rate: float
    metadata: dict[str, Any]

    @classmethod
    def from_baseline(cls, b: AgentBaseline) -> BaselineResponse:
        return cls(**b.to_dict())


class DriftSignalResponse(BaseModel):
    category: str
    observed_value: float
    baseline_value: float
    deviation_score: float
    severity: str
    detail: str


class DriftReportResponse(BaseModel):
    report_id: str
    agent_id: str
    client_id: str | None
    session_id: str | None
    timestamp: str
    window_seconds: int
    observation_count: int
    baseline_sample_count: int
    baseline_status: str
    overall_drift_score: float
    overall_severity: str
    signals: list[DriftSignalResponse]
    recommendations: list[str]
    should_alert: bool
    should_suspend: bool

    @classmethod
    def from_report(cls, r: DriftReport) -> DriftReportResponse:
        d = r.to_dict()
        d["signals"] = [DriftSignalResponse(**s) for s in d["signals"]]
        return cls(**d)


class BaselineActionResponse(BaseModel):
    agent_id: str
    success: bool
    detail: str


class BulkObservationResponse(BaseModel):
    agent_id: str
    ingested: int
    observations: list[ObservationResponse]


class BaselineListResponse(BaseModel):
    total: int
    baselines: list[BaselineResponse]


class ObservationListResponse(BaseModel):
    agent_id: str
    total: int
    observations: list[ObservationResponse]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/behavioral/agents/{agent_id}/observations",
    response_model=ObservationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record a single agent behavioral observation",
    description=("Ingest one behavioral observation for a specific agent. " "Each ingestion automatically triggers baseline recompute. " "Once enough samples are collected, drift detection becomes active."),
)
def record_observation(
    agent_id: str,
    body: ObservationRequest,
) -> ObservationResponse:
    store = get_behavioral_baseline_store()
    try:
        obs = store.record_observation(
            agent_id=agent_id,
            action_type=body.action_type,
            target=body.target,
            risk_score=body.risk_score,
            session_id=body.session_id,
            client_id=body.client_id,
            matched_patterns=body.matched_patterns,
            metadata=body.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ObservationResponse.from_observation(obs)


@router.post(
    "/behavioral/agents/{agent_id}/observations/bulk",
    response_model=BulkObservationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk ingest agent behavioral observations",
    description=("Ingest multiple behavioral observations for a specific agent in one request. " "Baseline recompute is triggered incrementally after each ingestion."),
)
def record_observations_bulk(
    agent_id: str,
    body: BulkObservationRequest,
) -> BulkObservationResponse:
    store = get_behavioral_baseline_store()
    items = [
        {
            "action_type": item.action_type,
            "target": item.target,
            "risk_score": item.risk_score,
            "session_id": item.session_id,
            "matched_patterns": item.matched_patterns,
            "metadata": item.metadata,
        }
        for item in body.observations
    ]
    try:
        recorded = store.record_observations_bulk(
            agent_id=agent_id,
            observations=items,
            client_id=body.client_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return BulkObservationResponse(
        agent_id=agent_id,
        ingested=len(recorded),
        observations=[ObservationResponse.from_observation(o) for o in recorded],
    )


@router.get(
    "/behavioral/agents/{agent_id}/baseline",
    response_model=BaselineResponse,
    summary="Get the learned behavioral baseline for an agent",
    description=("Returns the current learned baseline profile for the specified agent. " "Returns 404 if no baseline has been established yet."),
)
def get_baseline(agent_id: str) -> BaselineResponse:
    store = get_behavioral_baseline_store()
    try:
        baseline = store.get_baseline(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if baseline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baseline established for agent '{agent_id}'. Record observations first.",
        )
    return BaselineResponse.from_baseline(baseline)


@router.get(
    "/behavioral/agents/{agent_id}/drift",
    response_model=DriftReportResponse,
    summary="Compute behavioral drift for an agent",
    description=("Computes a full behavioral drift report comparing recent agent activity " "against the established baseline. Returns severity signals, recommendations, " "and suspension/alert flags."),
)
def compute_drift(
    agent_id: str,
    session_id: str | None = Query(default=None, description="Scope drift analysis to a specific session."),
    client_id: str | None = Query(default=None, description="Client identifier for context."),
    window_seconds: int | None = Query(
        default=None,
        ge=60,
        le=86400,
        description="Observation window in seconds (60–86400). Defaults to 3600.",
    ),
) -> DriftReportResponse:
    store = get_behavioral_baseline_store()
    try:
        report = store.compute_drift(
            agent_id=agent_id,
            session_id=session_id,
            client_id=client_id,
            window_seconds=window_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return DriftReportResponse.from_report(report)


@router.get(
    "/behavioral/agents/{agent_id}/observations",
    response_model=ObservationListResponse,
    summary="List recorded observations for an agent",
    description="Returns recent behavioral observations for the specified agent, optionally filtered by session.",
)
def get_observations(
    agent_id: str,
    session_id: str | None = Query(default=None, description="Filter observations by session ID."),
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum number of observations to return."),
) -> ObservationListResponse:
    store = get_behavioral_baseline_store()
    try:
        obs_list = store.get_observations(agent_id, limit=limit, session_id=session_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ObservationListResponse(
        agent_id=agent_id,
        total=len(obs_list),
        observations=[ObservationResponse.from_observation(o) for o in obs_list],
    )


@router.delete(
    "/behavioral/agents/{agent_id}/baseline",
    response_model=BaselineActionResponse,
    summary="Invalidate or purge an agent baseline",
    description=("If `purge=true`, removes all observations and the baseline entirely. " "If `purge=false` (default), marks the baseline as stale so it will be rebuilt on next observation."),
)
def delete_baseline(
    agent_id: str,
    purge: bool = Query(default=False, description="If true, permanently removes all observations and the baseline."),
) -> BaselineActionResponse:
    store = get_behavioral_baseline_store()
    try:
        if purge:
            found = store.purge_agent(agent_id)
            if not found:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No baseline or observations found for agent '{agent_id}'.",
                )
            return BaselineActionResponse(
                agent_id=agent_id,
                success=True,
                detail=f"All observations and baseline for agent '{agent_id}' have been permanently removed.",
            )
        else:
            invalidated = store.invalidate_baseline(agent_id)
            if not invalidated:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No baseline found for agent '{agent_id}'.",
                )
            return BaselineActionResponse(
                agent_id=agent_id,
                success=True,
                detail=f"Baseline for agent '{agent_id}' marked as stale and will be rebuilt on next observation.",
            )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post(
    "/behavioral/agents/{agent_id}/baseline/suspend",
    response_model=BaselineActionResponse,
    summary="Suspend an agent's behavioral profile",
    description=("Suspends the agent's baseline profile. A suspended agent will receive a critical drift verdict " "on every subsequent drift check until manually cleared by an operator. " "Use after critical drift confirmation or adversarial action detection."),
)
def suspend_baseline(agent_id: str) -> BaselineActionResponse:
    store = get_behavioral_baseline_store()
    try:
        suspended = store.suspend_baseline(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not suspended:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baseline found for agent '{agent_id}'. Cannot suspend.",
        )
    return BaselineActionResponse(
        agent_id=agent_id,
        success=True,
        detail=f"Agent '{agent_id}' baseline suspended. Operator review required before resuming.",
    )


@router.get(
    "/behavioral/baselines",
    response_model=BaselineListResponse,
    summary="List all agent behavioral baselines",
    description="Returns all established agent baseline profiles, optionally filtered by client or status.",
)
def list_baselines(
    client_id: str | None = Query(default=None, description="Filter baselines by client ID."),
    baseline_status: str | None = Query(
        default=None,
        alias="status",
        description="Filter by status: learning, active, stale, suspended.",
    ),
) -> BaselineListResponse:
    valid_statuses = {"learning", "active", "stale", "suspended"}
    if baseline_status is not None and baseline_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status '{baseline_status}'. Must be one of: {sorted(valid_statuses)}.",
        )
    store = get_behavioral_baseline_store()
    baselines = store.list_baselines(
        client_id=client_id,
        status=baseline_status,  # type: ignore[arg-type]
    )
    return BaselineListResponse(
        total=len(baselines),
        baselines=[BaselineResponse.from_baseline(b) for b in baselines],
    )
