from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import get_current_organization_id
from app.services.attackcorrelation import AttackCorrelationService
from app.services.notification_service import (
    NotificationChannel,
    NotificationEngine,
    NotificationEvent,
    NotificationSeverity,
    build_notification_engine,
    default_channels_for_severity,
    default_severity_for_event,
    dispatch_incident_notification,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-alerts", tags=["threat-alerts"])

# ---------------------------------------------------------------------------
# Singleton notification engine (dry-run default; replaced via /configure)
# ---------------------------------------------------------------------------

_engine: NotificationEngine = build_notification_engine(dry_run=True)


def _get_engine() -> NotificationEngine:
    return _engine


def _get_correlation_service() -> AttackCorrelationService:
    return AttackCorrelationService()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AlertEscalationRequest(BaseModel):
    """Escalate a correlated incident to the notification layer."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=200)
    incident_title: str = Field(min_length=1, max_length=500)
    event: NotificationEvent = NotificationEvent.INCIDENT_ESCALATED
    severity: NotificationSeverity | None = None
    org_id: str | None = Field(default=None, min_length=1, max_length=120)
    trace_id: str | None = Field(default=None, min_length=1, max_length=200)
    channels: list[NotificationChannel] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertEscalationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    event: str
    severity: NotificationSeverity
    channels_attempted: list[NotificationChannel]
    all_succeeded: bool
    any_failed: bool
    dispatched_at: str


class BulkEscalationRequest(BaseModel):
    """Escalate multiple incidents in one call."""

    model_config = ConfigDict(extra="forbid")

    escalations: list[AlertEscalationRequest] = Field(min_length=1, max_length=50)


class BulkEscalationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int
    succeeded: int
    failed: int
    results: list[AlertEscalationResponse | dict[str, Any]]


class AlertSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal_id: str = Field(min_length=1, max_length=200)
    signal_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    severity: str = Field(min_length=1, max_length=40)
    summary: str = Field(min_length=1, max_length=2000)
    score: int | None = Field(default=None, ge=0, le=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelateAndEscalateRequest(BaseModel):
    """Correlate signals and immediately escalate if threshold is met."""

    model_config = ConfigDict(extra="forbid")

    signals: list[AlertSignal] = Field(min_length=1)
    session_id: str | None = Field(default=None, min_length=1, max_length=120)
    actor_id: str | None = Field(default=None, min_length=1, max_length=120)
    request_id: str | None = Field(default=None, min_length=1, max_length=200)
    escalation_threshold: int = Field(
        default=60,
        ge=0,
        le=100,
        description="Minimum risk_score that triggers automatic escalation.",
    )
    channels: list[NotificationChannel] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelateAndEscalateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int
    risk_band: str
    confidence: float
    incident_id: str
    escalated: bool
    escalation_result: AlertEscalationResponse | None = None


class AlertChannelStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    channels_configured: list[NotificationChannel]
    suppression_rules_count: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INCIDENT_EVENTS = {
    NotificationEvent.INCIDENT_OPENED,
    NotificationEvent.INCIDENT_ESCALATED,
    NotificationEvent.INCIDENT_RESOLVED,
}


def _validate_incident_event(event: NotificationEvent) -> None:
    if event not in _INCIDENT_EVENTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"event must be one of {[e.value for e in _INCIDENT_EVENTS]}.",
        )


def _build_escalation_response(
    incident_id: str,
    result: Any,
) -> AlertEscalationResponse:
    payload = result.payload
    return AlertEscalationResponse(
        incident_id=incident_id,
        event=payload.event.value if isinstance(payload.event, NotificationEvent) else str(payload.event),
        severity=payload.severity,
        channels_attempted=result.channels_attempted,
        all_succeeded=result.all_succeeded,
        any_failed=result.any_failed,
        dispatched_at=result.dispatched_at,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/escalate",
    summary="Escalate a correlated incident via the notification engine",
    status_code=status.HTTP_200_OK,
    response_model=AlertEscalationResponse,
)
def escalate_incident(
    body: Annotated[AlertEscalationRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
    organization_id: str = Depends(get_current_organization_id),
) -> AlertEscalationResponse:
    _validate_incident_event(body.event)

    result = dispatch_incident_notification(
        engine,
        incident_id=body.incident_id,
        incident_title=body.incident_title,
        event=body.event,
        severity=body.severity,
        org_id=body.org_id or organization_id,
        trace_id=body.trace_id,
        channels=body.channels,
    )

    logger.info(
        "threat_alerts | escalate | incident_id=%s event=%s severity=%s succeeded=%s",
        body.incident_id,
        body.event.value,
        result.payload.severity,
        result.all_succeeded,
    )

    return _build_escalation_response(body.incident_id, result)


@router.post(
    "/escalate/bulk",
    summary="Escalate multiple correlated incidents in a single call",
    status_code=status.HTTP_200_OK,
    response_model=BulkEscalationResponse,
)
def bulk_escalate_incidents(
    body: Annotated[BulkEscalationRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
    organization_id: str = Depends(get_current_organization_id),
) -> BulkEscalationResponse:
    results: list[AlertEscalationResponse | dict[str, Any]] = []
    succeeded = 0
    failed = 0

    for req in body.escalations:
        try:
            _validate_incident_event(req.event)
            result = dispatch_incident_notification(
                engine,
                incident_id=req.incident_id,
                incident_title=req.incident_title,
                event=req.event,
                severity=req.severity,
                org_id=req.org_id or organization_id,
                trace_id=req.trace_id,
                channels=req.channels,
            )
            results.append(_build_escalation_response(req.incident_id, result))
            succeeded += 1
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "threat_alerts | bulk_escalate | incident_id=%s error=%s",
                req.incident_id,
                exc,
            )
            results.append({"incident_id": req.incident_id, "error": str(exc)})
            failed += 1

    return BulkEscalationResponse(
        total=len(body.escalations),
        succeeded=succeeded,
        failed=failed,
        results=results,
    )


@router.post(
    "/correlate-and-escalate",
    summary="Correlate signals and auto-escalate if risk score meets threshold",
    status_code=status.HTTP_200_OK,
    response_model=CorrelateAndEscalateResponse,
)
def correlate_and_escalate(
    body: Annotated[CorrelateAndEscalateRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
    correlation_service: Annotated[AttackCorrelationService, Depends(_get_correlation_service)],
    organization_id: str = Depends(get_current_organization_id),
) -> CorrelateAndEscalateResponse:
    correlation = correlation_service.correlate(
        [s.model_dump() for s in body.signals],
        session_id=body.session_id,
        actor_id=body.actor_id,
        organization_id=organization_id,
        request_id=body.request_id,
        metadata=body.metadata,
    )

    risk_score: int = correlation.get("risk_score", 0)
    risk_band: str = correlation.get("risk_band", "unknown")
    confidence: float = correlation.get("confidence", 0.0)
    incident: dict[str, Any] = correlation.get("incident", {})
    incident_id: str = incident.get("incident_id", "unknown")

    escalated = False
    escalation_result: AlertEscalationResponse | None = None

    if risk_score >= body.escalation_threshold:
        severity = default_severity_for_event(NotificationEvent.INCIDENT_ESCALATED)
        dispatch_result = dispatch_incident_notification(
            engine,
            incident_id=incident_id,
            incident_title=f"Auto-escalation: risk_score={risk_score} band={risk_band}",
            event=NotificationEvent.INCIDENT_ESCALATED,
            severity=severity,
            org_id=organization_id,
            channels=body.channels,
        )
        escalation_result = _build_escalation_response(incident_id, dispatch_result)
        escalated = True

        logger.info(
            "threat_alerts | correlate_and_escalate | incident_id=%s risk_score=%d escalated=True",
            incident_id,
            risk_score,
        )
    else:
        logger.info(
            "threat_alerts | correlate_and_escalate | incident_id=%s risk_score=%d threshold=%d escalated=False",
            incident_id,
            risk_score,
            body.escalation_threshold,
        )

    return CorrelateAndEscalateResponse(
        risk_score=risk_score,
        risk_band=risk_band,
        confidence=confidence,
        incident_id=incident_id,
        escalated=escalated,
        escalation_result=escalation_result,
    )


@router.get(
    "/channels/status",
    summary="Get current notification engine status for threat alert escalation",
    status_code=status.HTTP_200_OK,
    response_model=AlertChannelStatusResponse,
)
def get_alert_channel_status(
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> AlertChannelStatusResponse:
    configured: list[NotificationChannel] = []
    if getattr(engine, "email_config", None) is not None:
        configured.append("email")
    if getattr(engine, "slack_config", None) is not None:
        configured.append("slack")
    if getattr(engine, "pagerduty_config", None) is not None:
        configured.append("pagerduty")

    return AlertChannelStatusResponse(
        dry_run=engine.dry_run,
        channels_configured=configured,
        suppression_rules_count=len(engine.suppression_rules),
    )


@router.get(
    "/severity-defaults",
    summary="Get default notification severity and channels for a given incident event",
    status_code=status.HTTP_200_OK,
)
def get_severity_defaults(
    event: Annotated[
        NotificationEvent,
        Query(description="Incident notification event type"),
    ] = NotificationEvent.INCIDENT_ESCALATED,
) -> dict[str, Any]:
    _validate_incident_event(event)
    severity = default_severity_for_event(event)
    channels = default_channels_for_severity(severity)
    return {
        "event": event.value,
        "default_severity": severity,
        "default_channels": channels,
    }
