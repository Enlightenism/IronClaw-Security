from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.notification_service import (
    DispatchResult,
    EmailConfig,
    NotificationChannel,
    NotificationEngine,
    NotificationEvent,
    NotificationSeverity,
    PagerDutyConfig,
    SlackConfig,
    SuppressionRule,
    build_notification_engine,
    build_notification_payload,
    default_channels_for_severity,
    default_severity_for_event,
    dispatch_incident_notification,
    dispatch_notification,
    dispatch_policy_block,
    dispatch_review_event,
    dispatch_sandbox_threat,
    dispatch_system_health,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])

# ---------------------------------------------------------------------------
# Singleton engine (dry-run by default; reconfigured at runtime via /configure)
# ---------------------------------------------------------------------------

_engine: NotificationEngine = build_notification_engine(dry_run=True)


def _get_engine() -> NotificationEngine:
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class EmailConfigRequest(BaseModel):
    smtp_host: str = Field(..., min_length=1)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    sender_address: str = Field(..., min_length=1)
    recipients: list[str] = Field(..., min_items=1)
    use_tls: bool = True
    username: str | None = None
    password: str | None = None


class SlackConfigRequest(BaseModel):
    webhook_url: str = Field(..., min_length=1)
    channel: str = Field(..., min_length=1)
    username: str = "IronClaw-Security"
    icon_emoji: str = ":shield:"
    mention_on_critical: str | None = None


class PagerDutyConfigRequest(BaseModel):
    routing_key: str = Field(..., min_length=1)
    service_name: str = "IronClaw-Security"
    default_severity: NotificationSeverity = "critical"
    dedup_key_prefix: str = "ironclaw"


class EngineConfigRequest(BaseModel):
    dry_run: bool = False
    email: EmailConfigRequest | None = None
    slack: SlackConfigRequest | None = None
    pagerduty: PagerDutyConfigRequest | None = None


class EngineConfigResponse(BaseModel):
    dry_run: bool
    channels_configured: list[NotificationChannel]
    suppression_rules_count: int


class DispatchRequest(BaseModel):
    event: NotificationEvent
    title: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)
    source_id: str = Field(..., min_length=1)
    source_type: str = Field(..., min_length=1)
    severity: NotificationSeverity | None = None
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    channels: list[NotificationChannel] | None = None


class DispatchResponse(BaseModel):
    event: str
    severity: NotificationSeverity
    source_id: str
    source_type: str
    channels_attempted: list[NotificationChannel]
    all_succeeded: bool
    any_failed: bool
    results: list[dict[str, Any]]
    dispatched_at: str


class PolicyBlockRequest(BaseModel):
    decision_id: str = Field(..., min_length=1)
    verdict: str = Field(..., pattern=r"^(block|quarantine)$")
    summary: str = Field(..., min_length=1)
    agent_id: str | None = None
    session_id: str | None = None
    trace_id: str | None = None
    org_id: str | None = None
    channels: list[NotificationChannel] | None = None


class IncidentNotifyRequest(BaseModel):
    incident_id: str = Field(..., min_length=1)
    incident_title: str = Field(..., min_length=1)
    event: NotificationEvent
    severity: NotificationSeverity | None = None
    org_id: str | None = None
    trace_id: str | None = None
    channels: list[NotificationChannel] | None = None


class SandboxThreatRequest(BaseModel):
    task_id: str = Field(..., min_length=1)
    threat_summary: str = Field(..., min_length=1)
    agent_id: str | None = None
    session_id: str | None = None
    trace_id: str | None = None
    org_id: str | None = None
    channels: list[NotificationChannel] | None = None


class ReviewEventRequest(BaseModel):
    item_id: str = Field(..., min_length=1)
    event: NotificationEvent
    reviewer_id: str | None = None
    org_id: str | None = None
    trace_id: str | None = None
    channels: list[NotificationChannel] | None = None


class SystemHealthRequest(BaseModel):
    component: str = Field(..., min_length=1)
    detail: str = Field(..., min_length=1)
    severity: NotificationSeverity = "critical"
    trace_id: str | None = None
    channels: list[NotificationChannel] | None = None


class SuppressionRuleRequest(BaseModel):
    rule_id: str = Field(..., min_length=1)
    event: NotificationEvent | None = None
    severity: NotificationSeverity | None = None
    channel: NotificationChannel | None = None
    reason: str = Field(..., min_length=1)
    active: bool = True


class SuppressionRuleResponse(BaseModel):
    rule_id: str
    event: str | None
    severity: str | None
    channel: str | None
    reason: str
    active: bool


class DeliveryLogResponse(BaseModel):
    total: int
    entries: list[dict[str, Any]]


class ChannelDefaultsResponse(BaseModel):
    severity: NotificationSeverity
    channels: list[NotificationChannel]


class EventSeverityResponse(BaseModel):
    event: str
    default_severity: NotificationSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dispatch_result_to_response(result: DispatchResult) -> DispatchResponse:
    return DispatchResponse(
        event=result.payload.event.value if isinstance(result.payload.event, NotificationEvent) else str(result.payload.event),
        severity=result.payload.severity,
        source_id=result.payload.source_id,
        source_type=result.payload.source_type,
        channels_attempted=result.channels_attempted,
        all_succeeded=result.all_succeeded,
        any_failed=result.any_failed,
        results=[r.to_dict() for r in result.results],
        dispatched_at=result.dispatched_at,
    )


def _validate_review_event(event: NotificationEvent) -> None:
    allowed = {
        NotificationEvent.REVIEW_ITEM_SUBMITTED,
        NotificationEvent.REVIEW_ITEM_APPROVED,
        NotificationEvent.REVIEW_ITEM_REJECTED,
    }
    if event not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"event must be one of {[e.value for e in allowed]} for review dispatch.",
        )


def _validate_incident_event(event: NotificationEvent) -> None:
    allowed = {
        NotificationEvent.INCIDENT_OPENED,
        NotificationEvent.INCIDENT_ESCALATED,
        NotificationEvent.INCIDENT_RESOLVED,
    }
    if event not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"event must be one of {[e.value for e in allowed]} for incident dispatch.",
        )


# ---------------------------------------------------------------------------
# Engine configuration
# ---------------------------------------------------------------------------


@router.post(
    "/configure",
    summary="Configure notification engine channels",
    status_code=status.HTTP_200_OK,
    response_model=EngineConfigResponse,
    tags=["notifications"],
)
def configure_engine(
    body: Annotated[EngineConfigRequest, Body()],
) -> EngineConfigResponse:
    global _engine  # noqa: PLW0603

    email_cfg: EmailConfig | None = None
    slack_cfg: SlackConfig | None = None
    pd_cfg: PagerDutyConfig | None = None

    if body.email is not None:
        email_cfg = EmailConfig(
            smtp_host=body.email.smtp_host,
            smtp_port=body.email.smtp_port,
            sender_address=body.email.sender_address,
            recipients=tuple(body.email.recipients),
            use_tls=body.email.use_tls,
            username=body.email.username,
            password=body.email.password,
        )

    if body.slack is not None:
        slack_cfg = SlackConfig(
            webhook_url=body.slack.webhook_url,
            channel=body.slack.channel,
            username=body.slack.username,
            icon_emoji=body.slack.icon_emoji,
            mention_on_critical=body.slack.mention_on_critical,
        )

    if body.pagerduty is not None:
        pd_cfg = PagerDutyConfig(
            routing_key=body.pagerduty.routing_key,
            service_name=body.pagerduty.service_name,
            default_severity=body.pagerduty.default_severity,
            dedup_key_prefix=body.pagerduty.dedup_key_prefix,
        )

    preserved_rules = list(_engine.suppression_rules)

    _engine = build_notification_engine(
        email_config=email_cfg,
        slack_config=slack_cfg,
        pagerduty_config=pd_cfg,
        dry_run=body.dry_run,
    )
    _engine.suppression_rules.extend(preserved_rules)

    configured: list[NotificationChannel] = []
    if email_cfg is not None:
        configured.append("email")
    if slack_cfg is not None:
        configured.append("slack")
    if pd_cfg is not None:
        configured.append("pagerduty")

    logger.info(
        "notification_service | engine reconfigured | dry_run=%s channels=%s",
        body.dry_run,
        configured,
    )

    return EngineConfigResponse(
        dry_run=body.dry_run,
        channels_configured=configured,
        suppression_rules_count=len(_engine.suppression_rules),
    )


@router.get(
    "/configure",
    summary="Get current notification engine configuration summary",
    status_code=status.HTTP_200_OK,
    response_model=EngineConfigResponse,
    tags=["notifications"],
)
def get_engine_config(
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> EngineConfigResponse:
    configured: list[NotificationChannel] = []
    if engine.email_config is not None:
        configured.append("email")
    if engine.slack_config is not None:
        configured.append("slack")
    if engine.pagerduty_config is not None:
        configured.append("pagerduty")

    return EngineConfigResponse(
        dry_run=engine.dry_run,
        channels_configured=configured,
        suppression_rules_count=len(engine.suppression_rules),
    )


# ---------------------------------------------------------------------------
# Generic dispatch
# ---------------------------------------------------------------------------


@router.post(
    "/dispatch",
    summary="Dispatch a notification to one or more channels",
    status_code=status.HTTP_200_OK,
    response_model=DispatchResponse,
    tags=["notifications"],
)
def dispatch(
    body: Annotated[DispatchRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> DispatchResponse:
    payload = build_notification_payload(
        event=body.event,
        title=body.title,
        body=body.body,
        source_id=body.source_id,
        source_type=body.source_type,
        severity=body.severity,
        org_id=body.org_id,
        agent_id=body.agent_id,
        session_id=body.session_id,
        trace_id=body.trace_id,
        metadata=body.metadata,
    )
    result = dispatch_notification(engine, payload, channels=body.channels)
    return _dispatch_result_to_response(result)


# ---------------------------------------------------------------------------
# Typed security event dispatchers
# ---------------------------------------------------------------------------


@router.post(
    "/dispatch/policy-block",
    summary="Dispatch notification for a policy block or quarantine decision",
    status_code=status.HTTP_200_OK,
    response_model=DispatchResponse,
    tags=["notifications"],
)
def dispatch_policy_block_route(
    body: Annotated[PolicyBlockRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> DispatchResponse:
    result = dispatch_policy_block(
        engine,
        decision_id=body.decision_id,
        verdict=body.verdict,
        summary=body.summary,
        agent_id=body.agent_id,
        session_id=body.session_id,
        trace_id=body.trace_id,
        org_id=body.org_id,
        channels=body.channels,
    )
    return _dispatch_result_to_response(result)


@router.post(
    "/dispatch/incident",
    summary="Dispatch notification for an incident lifecycle event",
    status_code=status.HTTP_200_OK,
    response_model=DispatchResponse,
    tags=["notifications"],
)
def dispatch_incident_route(
    body: Annotated[IncidentNotifyRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> DispatchResponse:
    _validate_incident_event(body.event)
    result = dispatch_incident_notification(
        engine,
        incident_id=body.incident_id,
        incident_title=body.incident_title,
        event=body.event,
        severity=body.severity,
        org_id=body.org_id,
        trace_id=body.trace_id,
        channels=body.channels,
    )
    return _dispatch_result_to_response(result)


@router.post(
    "/dispatch/sandbox-threat",
    summary="Dispatch notification for a sandbox-detected threat",
    status_code=status.HTTP_200_OK,
    response_model=DispatchResponse,
    tags=["notifications"],
)
def dispatch_sandbox_threat_route(
    body: Annotated[SandboxThreatRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> DispatchResponse:
    result = dispatch_sandbox_threat(
        engine,
        task_id=body.task_id,
        threat_summary=body.threat_summary,
        agent_id=body.agent_id,
        session_id=body.session_id,
        trace_id=body.trace_id,
        org_id=body.org_id,
        channels=body.channels,
    )
    return _dispatch_result_to_response(result)


@router.post(
    "/dispatch/review-event",
    summary="Dispatch notification for a review queue item lifecycle event",
    status_code=status.HTTP_200_OK,
    response_model=DispatchResponse,
    tags=["notifications"],
)
def dispatch_review_event_route(
    body: Annotated[ReviewEventRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> DispatchResponse:
    _validate_review_event(body.event)
    result = dispatch_review_event(
        engine,
        item_id=body.item_id,
        event=body.event,
        reviewer_id=body.reviewer_id,
        org_id=body.org_id,
        trace_id=body.trace_id,
        channels=body.channels,
    )
    return _dispatch_result_to_response(result)


@router.post(
    "/dispatch/system-health",
    summary="Dispatch notification for a system health degradation event",
    status_code=status.HTTP_200_OK,
    response_model=DispatchResponse,
    tags=["notifications"],
)
def dispatch_system_health_route(
    body: Annotated[SystemHealthRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> DispatchResponse:
    result = dispatch_system_health(
        engine,
        component=body.component,
        detail=body.detail,
        severity=body.severity,
        trace_id=body.trace_id,
        channels=body.channels,
    )
    return _dispatch_result_to_response(result)


# ---------------------------------------------------------------------------
# Suppression rules
# ---------------------------------------------------------------------------


@router.post(
    "/suppression",
    summary="Register a suppression rule on the notification engine",
    status_code=status.HTTP_201_CREATED,
    response_model=SuppressionRuleResponse,
    tags=["notifications"],
)
def add_suppression_rule(
    body: Annotated[SuppressionRuleRequest, Body()],
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> SuppressionRuleResponse:
    existing_ids = {r.rule_id for r in engine.suppression_rules}
    if body.rule_id in existing_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Suppression rule '{body.rule_id}' already exists.",
        )

    rule = SuppressionRule(
        rule_id=body.rule_id,
        event=body.event,
        severity=body.severity,
        channel=body.channel,
        reason=body.reason,
        active=body.active,
    )
    engine.register_suppression(rule)

    return SuppressionRuleResponse(
        rule_id=rule.rule_id,
        event=rule.event.value if isinstance(rule.event, NotificationEvent) else rule.event,
        severity=rule.severity,
        channel=rule.channel,
        reason=rule.reason,
        active=rule.active,
    )


@router.get(
    "/suppression",
    summary="List all active suppression rules",
    status_code=status.HTTP_200_OK,
    response_model=list[SuppressionRuleResponse],
    tags=["notifications"],
)
def list_suppression_rules(
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
    active_only: Annotated[bool, Query(description="Filter to active rules only")] = False,
) -> list[SuppressionRuleResponse]:
    rules = engine.suppression_rules
    if active_only:
        rules = [r for r in rules if r.active]
    return [
        SuppressionRuleResponse(
            rule_id=r.rule_id,
            event=r.event.value if isinstance(r.event, NotificationEvent) else r.event,
            severity=r.severity,
            channel=r.channel,
            reason=r.reason,
            active=r.active,
        )
        for r in rules
    ]


@router.delete(
    "/suppression/{rule_id}",
    summary="Remove a suppression rule by rule_id",
    status_code=status.HTTP_200_OK,
    tags=["notifications"],
)
def remove_suppression_rule(
    rule_id: str,
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> dict[str, str]:
    before = len(engine.suppression_rules)
    engine.suppression_rules[:] = [r for r in engine.suppression_rules if r.rule_id != rule_id]
    after = len(engine.suppression_rules)
    if before == after:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suppression rule '{rule_id}' not found.",
        )
    return {"rule_id": rule_id, "status": "removed"}


# ---------------------------------------------------------------------------
# Delivery log
# ---------------------------------------------------------------------------


@router.get(
    "/log",
    summary="Retrieve the in-memory notification delivery log",
    status_code=status.HTTP_200_OK,
    response_model=DeliveryLogResponse,
    tags=["notifications"],
)
def get_delivery_log(
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
    channel: Annotated[
        NotificationChannel | None,
        Query(description="Filter by channel"),
    ] = None,
    status_filter: Annotated[
        str | None,
        Query(alias="status", description="Filter by delivery status"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> DeliveryLogResponse:
    entries = engine.delivery_log()
    if channel is not None:
        entries = [e for e in entries if e.channel == channel]
    if status_filter is not None:
        entries = [e for e in entries if e.status == status_filter]
    entries = entries[-limit:]
    return DeliveryLogResponse(
        total=len(entries),
        entries=[e.to_dict() for e in entries],
    )


@router.delete(
    "/log",
    summary="Clear the in-memory notification delivery log",
    status_code=status.HTTP_200_OK,
    tags=["notifications"],
)
def clear_delivery_log(
    engine: Annotated[NotificationEngine, Depends(_get_engine)],
) -> dict[str, str]:
    engine.clear_log()
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# Channel / event metadata
# ---------------------------------------------------------------------------


@router.get(
    "/channels/defaults",
    summary="Get default channels for a given severity level",
    status_code=status.HTTP_200_OK,
    response_model=ChannelDefaultsResponse,
    tags=["notifications"],
)
def get_channel_defaults(
    severity: Annotated[NotificationSeverity, Query(description="Severity level")],
) -> ChannelDefaultsResponse:
    return ChannelDefaultsResponse(
        severity=severity,
        channels=default_channels_for_severity(severity),
    )


@router.get(
    "/events/severity",
    summary="Get the default severity for a notification event type",
    status_code=status.HTTP_200_OK,
    response_model=EventSeverityResponse,
    tags=["notifications"],
)
def get_event_default_severity(
    event: Annotated[NotificationEvent, Query(description="Notification event type")],
) -> EventSeverityResponse:
    return EventSeverityResponse(
        event=event.value,
        default_severity=default_severity_for_event(event),
    )


@router.get(
    "/events",
    summary="List all supported notification event types",
    status_code=status.HTTP_200_OK,
    tags=["notifications"],
)
def list_events() -> dict[str, list[str]]:
    return {"events": [e.value for e in NotificationEvent]}


@router.get(
    "/channels",
    summary="List all supported notification channels",
    status_code=status.HTTP_200_OK,
    tags=["notifications"],
)
def list_channels() -> dict[str, list[str]]:
    return {"channels": ["email", "slack", "pagerduty"]}
