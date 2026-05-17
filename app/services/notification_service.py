from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

NotificationChannel = Literal["email", "slack", "pagerduty"]
NotificationSeverity = Literal["info", "warning", "critical"]
NotificationStatus = Literal["sent", "failed", "suppressed", "simulated"]


class NotificationEvent(str, Enum):
    ALERT_CREATED = "alert_created"
    ALERT_ESCALATED = "alert_escalated"
    INCIDENT_OPENED = "incident_opened"
    INCIDENT_ESCALATED = "incident_escalated"
    INCIDENT_RESOLVED = "incident_resolved"
    POLICY_BLOCK = "policy_block"
    POLICY_QUARANTINE = "policy_quarantine"
    REVIEW_ITEM_SUBMITTED = "review_item_submitted"
    REVIEW_ITEM_APPROVED = "review_item_approved"
    REVIEW_ITEM_REJECTED = "review_item_rejected"
    SANDBOX_THREAT_DETECTED = "sandbox_threat_detected"
    AUDIT_ANOMALY = "audit_anomaly"
    SYSTEM_HEALTH_DEGRADED = "system_health_degraded"


# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmailConfig:
    smtp_host: str
    smtp_port: int
    sender_address: str
    recipients: tuple[str, ...]
    use_tls: bool = True
    username: str | None = None
    password: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "sender_address": self.sender_address,
            "recipients": list(self.recipients),
            "use_tls": self.use_tls,
            "username": self.username,
        }


@dataclass(frozen=True)
class SlackConfig:
    webhook_url: str
    channel: str
    username: str = "IronClaw-Security"
    icon_emoji: str = ":shield:"
    mention_on_critical: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "mention_on_critical": self.mention_on_critical,
        }


@dataclass(frozen=True)
class PagerDutyConfig:
    routing_key: str
    service_name: str = "IronClaw-Security"
    default_severity: NotificationSeverity = "critical"
    dedup_key_prefix: str = "ironclaw"

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_name": self.service_name,
            "default_severity": self.default_severity,
            "dedup_key_prefix": self.dedup_key_prefix,
        }


# ---------------------------------------------------------------------------
# Notification payload
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NotificationPayload:
    event: NotificationEvent
    severity: NotificationSeverity
    title: str
    body: str
    source_id: str
    source_type: str
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.value if isinstance(self.event, NotificationEvent) else self.event,
            "severity": self.severity,
            "title": self.title,
            "body": self.body,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "org_id": self.org_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Delivery result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeliveryResult:
    channel: NotificationChannel
    status: NotificationStatus
    payload_event: str
    payload_severity: NotificationSeverity
    source_id: str
    detail: str = ""
    error: str | None = None
    delivered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "status": self.status,
            "payload_event": self.payload_event,
            "payload_severity": self.payload_severity,
            "source_id": self.source_id,
            "detail": self.detail,
            "error": self.error,
            "delivered_at": self.delivered_at,
        }

    @property
    def succeeded(self) -> bool:
        return self.status in ("sent", "simulated")

    @property
    def failed(self) -> bool:
        return self.status == "failed"


# ---------------------------------------------------------------------------
# Dispatch result (aggregate across channels)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DispatchResult:
    payload: NotificationPayload
    results: list[DeliveryResult]
    dispatched_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def all_succeeded(self) -> bool:
        return all(r.succeeded for r in self.results)

    @property
    def any_failed(self) -> bool:
        return any(r.failed for r in self.results)

    @property
    def channels_attempted(self) -> list[NotificationChannel]:
        return [r.channel for r in self.results]

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload.to_dict(),
            "results": [r.to_dict() for r in self.results],
            "all_succeeded": self.all_succeeded,
            "any_failed": self.any_failed,
            "channels_attempted": self.channels_attempted,
            "dispatched_at": self.dispatched_at,
        }

    def summary(self) -> dict[str, Any]:
        return {
            "event": self.payload.event.value if isinstance(self.payload.event, NotificationEvent) else self.payload.event,
            "severity": self.payload.severity,
            "source_id": self.payload.source_id,
            "all_succeeded": self.all_succeeded,
            "any_failed": self.any_failed,
            "channels": self.channels_attempted,
            "dispatched_at": self.dispatched_at,
        }


# ---------------------------------------------------------------------------
# Suppression rule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SuppressionRule:
    rule_id: str
    event: NotificationEvent | None
    severity: NotificationSeverity | None
    channel: NotificationChannel | None
    reason: str
    active: bool = True

    def matches(
        self,
        payload: NotificationPayload,
        channel: NotificationChannel,
    ) -> bool:
        if not self.active:
            return False
        payload_event = payload.event.value if isinstance(payload.event, NotificationEvent) else payload.event
        rule_event = self.event.value if isinstance(self.event, NotificationEvent) else self.event
        if self.event is not None and rule_event != payload_event:
            return False
        if self.severity is not None and self.severity != payload.severity:
            return False
        if self.channel is not None and self.channel != channel:
            return False
        return True


# ---------------------------------------------------------------------------
# Channel drivers (thin I/O boundary — no real network calls here)
# ---------------------------------------------------------------------------


def _deliver_email(
    config: EmailConfig,
    payload: NotificationPayload,
    *,
    dry_run: bool = False,
) -> DeliveryResult:
    event_str = payload.event.value if isinstance(payload.event, NotificationEvent) else payload.event
    recipients = list(config.recipients)
    detail = f"[DRY-RUN] Email to={recipients} subject='{payload.title}' event={event_str}" if dry_run else f"Email queued to={recipients} subject='{payload.title}' event={event_str}"
    status: NotificationStatus = "simulated" if dry_run else "sent"
    logger.info("notification_service | email | %s | source_id=%s", status, payload.source_id)
    return DeliveryResult(
        channel="email",
        status=status,
        payload_event=event_str,
        payload_severity=payload.severity,
        source_id=payload.source_id,
        detail=detail,
    )


def _deliver_slack(
    config: SlackConfig,
    payload: NotificationPayload,
    *,
    dry_run: bool = False,
) -> DeliveryResult:
    event_str = payload.event.value if isinstance(payload.event, NotificationEvent) else payload.event
    mention = ""
    if payload.severity == "critical" and config.mention_on_critical:
        mention = f" {config.mention_on_critical}"
    text = f"*[{payload.severity.upper()}]* {payload.title}{mention}\n{payload.body}"
    detail = f"[DRY-RUN] Slack channel={config.channel} text_len={len(text)} event={event_str}" if dry_run else f"Slack posted channel={config.channel} event={event_str}"
    status: NotificationStatus = "simulated" if dry_run else "sent"
    logger.info("notification_service | slack | %s | source_id=%s", status, payload.source_id)
    return DeliveryResult(
        channel="slack",
        status=status,
        payload_event=event_str,
        payload_severity=payload.severity,
        source_id=payload.source_id,
        detail=detail,
    )


def _deliver_pagerduty(
    config: PagerDutyConfig,
    payload: NotificationPayload,
    *,
    dry_run: bool = False,
) -> DeliveryResult:
    event_str = payload.event.value if isinstance(payload.event, NotificationEvent) else payload.event
    dedup_key = f"{config.dedup_key_prefix}-{payload.source_id}"
    detail = f"[DRY-RUN] PagerDuty trigger dedup_key={dedup_key} severity={payload.severity} event={event_str}" if dry_run else f"PagerDuty triggered dedup_key={dedup_key} severity={payload.severity} event={event_str}"
    status: NotificationStatus = "simulated" if dry_run else "sent"
    logger.info("notification_service | pagerduty | %s | source_id=%s", status, payload.source_id)
    return DeliveryResult(
        channel="pagerduty",
        status=status,
        payload_event=event_str,
        payload_severity=payload.severity,
        source_id=payload.source_id,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Notification engine
# ---------------------------------------------------------------------------


@dataclass
class NotificationEngine:
    email_config: EmailConfig | None = None
    slack_config: SlackConfig | None = None
    pagerduty_config: PagerDutyConfig | None = None
    suppression_rules: list[SuppressionRule] = field(default_factory=list)
    dry_run: bool = False
    _delivery_log: list[DeliveryResult] = field(default_factory=list, repr=False)

    def register_suppression(self, rule: SuppressionRule) -> None:
        self.suppression_rules.append(rule)

    def _is_suppressed(
        self,
        payload: NotificationPayload,
        channel: NotificationChannel,
    ) -> tuple[bool, str]:
        for rule in self.suppression_rules:
            if rule.matches(payload, channel):
                return True, rule.reason
        return False, ""

    def _run_channel(
        self,
        channel: NotificationChannel,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        suppressed, reason = self._is_suppressed(payload, channel)
        if suppressed:
            event_str = payload.event.value if isinstance(payload.event, NotificationEvent) else payload.event
            logger.debug(
                "notification_service | %s | suppressed | source_id=%s reason=%s",
                channel,
                payload.source_id,
                reason,
            )
            return DeliveryResult(
                channel=channel,
                status="suppressed",
                payload_event=event_str,
                payload_severity=payload.severity,
                source_id=payload.source_id,
                detail=f"Suppressed: {reason}",
            )

        try:
            if channel == "email":
                if self.email_config is None:
                    raise ValueError("EmailConfig not registered on NotificationEngine.")
                return _deliver_email(self.email_config, payload, dry_run=self.dry_run)
            if channel == "slack":
                if self.slack_config is None:
                    raise ValueError("SlackConfig not registered on NotificationEngine.")
                return _deliver_slack(self.slack_config, payload, dry_run=self.dry_run)
            if channel == "pagerduty":
                if self.pagerduty_config is None:
                    raise ValueError("PagerDutyConfig not registered on NotificationEngine.")
                return _deliver_pagerduty(self.pagerduty_config, payload, dry_run=self.dry_run)
            raise ValueError(f"Unsupported channel: {channel!r}")
        except Exception as exc:  # noqa: BLE001
            event_str = payload.event.value if isinstance(payload.event, NotificationEvent) else payload.event
            logger.error(
                "notification_service | %s | failed | source_id=%s error=%s",
                channel,
                payload.source_id,
                exc,
            )
            return DeliveryResult(
                channel=channel,
                status="failed",
                payload_event=event_str,
                payload_severity=payload.severity,
                source_id=payload.source_id,
                detail="Delivery failed — see error field.",
                error=str(exc),
            )

    def dispatch(
        self,
        payload: NotificationPayload,
        channels: list[NotificationChannel],
    ) -> DispatchResult:
        results: list[DeliveryResult] = []
        for channel in channels:
            result = self._run_channel(channel, payload)
            results.append(result)
            self._delivery_log.append(result)
        return DispatchResult(payload=payload, results=results)

    def delivery_log(self) -> list[DeliveryResult]:
        return list(self._delivery_log)

    def clear_log(self) -> None:
        self._delivery_log.clear()


# ---------------------------------------------------------------------------
# Channel routing helpers
# ---------------------------------------------------------------------------


_SEVERITY_CHANNEL_MAP: dict[NotificationSeverity, list[NotificationChannel]] = {
    "info": ["slack"],
    "warning": ["slack", "email"],
    "critical": ["slack", "email", "pagerduty"],
}


def default_channels_for_severity(
    severity: NotificationSeverity,
) -> list[NotificationChannel]:
    return list(_SEVERITY_CHANNEL_MAP.get(severity, ["slack"]))


_EVENT_SEVERITY_MAP: dict[str, NotificationSeverity] = {
    NotificationEvent.ALERT_CREATED.value: "warning",
    NotificationEvent.ALERT_ESCALATED.value: "critical",
    NotificationEvent.INCIDENT_OPENED.value: "warning",
    NotificationEvent.INCIDENT_ESCALATED.value: "critical",
    NotificationEvent.INCIDENT_RESOLVED.value: "info",
    NotificationEvent.POLICY_BLOCK.value: "critical",
    NotificationEvent.POLICY_QUARANTINE.value: "warning",
    NotificationEvent.REVIEW_ITEM_SUBMITTED.value: "info",
    NotificationEvent.REVIEW_ITEM_APPROVED.value: "info",
    NotificationEvent.REVIEW_ITEM_REJECTED.value: "warning",
    NotificationEvent.SANDBOX_THREAT_DETECTED.value: "critical",
    NotificationEvent.AUDIT_ANOMALY.value: "warning",
    NotificationEvent.SYSTEM_HEALTH_DEGRADED.value: "critical",
}


def default_severity_for_event(event: NotificationEvent) -> NotificationSeverity:
    key = event.value if isinstance(event, NotificationEvent) else event
    return _EVENT_SEVERITY_MAP.get(key, "warning")


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def build_notification_engine(
    *,
    email_config: EmailConfig | None = None,
    slack_config: SlackConfig | None = None,
    pagerduty_config: PagerDutyConfig | None = None,
    dry_run: bool = False,
) -> NotificationEngine:
    return NotificationEngine(
        email_config=email_config,
        slack_config=slack_config,
        pagerduty_config=pagerduty_config,
        dry_run=dry_run,
    )


def build_notification_payload(
    *,
    event: NotificationEvent,
    title: str,
    body: str,
    source_id: str,
    source_type: str,
    severity: NotificationSeverity | None = None,
    org_id: str | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> NotificationPayload:
    resolved_severity: NotificationSeverity = severity or default_severity_for_event(event)
    return NotificationPayload(
        event=event,
        severity=resolved_severity,
        title=title,
        body=body,
        source_id=source_id,
        source_type=source_type,
        org_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        trace_id=trace_id,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Convenience dispatch functions
# ---------------------------------------------------------------------------


def dispatch_notification(
    engine: NotificationEngine,
    payload: NotificationPayload,
    *,
    channels: list[NotificationChannel] | None = None,
) -> DispatchResult:
    resolved_channels = channels or default_channels_for_severity(payload.severity)
    return engine.dispatch(payload, resolved_channels)


def dispatch_policy_block(
    engine: NotificationEngine,
    *,
    decision_id: str,
    verdict: str,
    summary: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    org_id: str | None = None,
    channels: list[NotificationChannel] | None = None,
) -> DispatchResult:
    event = NotificationEvent.POLICY_BLOCK if verdict == "block" else NotificationEvent.POLICY_QUARANTINE
    payload = build_notification_payload(
        event=event,
        title=f"IronClaw Policy {verdict.upper()}: {decision_id}",
        body=summary,
        source_id=decision_id,
        source_type="policy_decision",
        agent_id=agent_id,
        session_id=session_id,
        trace_id=trace_id,
        org_id=org_id,
        metadata={"verdict": verdict},
    )
    return dispatch_notification(engine, payload, channels=channels)


def dispatch_incident_notification(
    engine: NotificationEngine,
    *,
    incident_id: str,
    incident_title: str,
    event: NotificationEvent,
    severity: NotificationSeverity | None = None,
    org_id: str | None = None,
    trace_id: str | None = None,
    channels: list[NotificationChannel] | None = None,
) -> DispatchResult:
    payload = build_notification_payload(
        event=event,
        title=f"IronClaw Incident: {incident_title}",
        body=f"Incident ID: {incident_id} | Event: {event.value}",
        source_id=incident_id,
        source_type="incident",
        severity=severity,
        org_id=org_id,
        trace_id=trace_id,
    )
    return dispatch_notification(engine, payload, channels=channels)


def dispatch_sandbox_threat(
    engine: NotificationEngine,
    *,
    task_id: str,
    threat_summary: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    org_id: str | None = None,
    channels: list[NotificationChannel] | None = None,
) -> DispatchResult:
    payload = build_notification_payload(
        event=NotificationEvent.SANDBOX_THREAT_DETECTED,
        title=f"IronClaw Sandbox Threat Detected: {task_id}",
        body=threat_summary,
        source_id=task_id,
        source_type="sandbox_task",
        agent_id=agent_id,
        session_id=session_id,
        trace_id=trace_id,
        org_id=org_id,
    )
    return dispatch_notification(engine, payload, channels=channels)


def dispatch_review_event(
    engine: NotificationEngine,
    *,
    item_id: str,
    event: NotificationEvent,
    reviewer_id: str | None = None,
    org_id: str | None = None,
    trace_id: str | None = None,
    channels: list[NotificationChannel] | None = None,
) -> DispatchResult:
    title_map: dict[NotificationEvent, str] = {
        NotificationEvent.REVIEW_ITEM_SUBMITTED: f"Review Item Submitted: {item_id}",
        NotificationEvent.REVIEW_ITEM_APPROVED: f"Review Item Approved: {item_id}",
        NotificationEvent.REVIEW_ITEM_REJECTED: f"Review Item Rejected: {item_id}",
    }
    title = title_map.get(event, f"Review Event: {item_id}")
    body = f"Item ID: {item_id} | Reviewer: {reviewer_id or 'system'} | Event: {event.value}"
    payload = build_notification_payload(
        event=event,
        title=title,
        body=body,
        source_id=item_id,
        source_type="review_item",
        org_id=org_id,
        trace_id=trace_id,
        metadata={"reviewer_id": reviewer_id},
    )
    return dispatch_notification(engine, payload, channels=channels)


def dispatch_system_health(
    engine: NotificationEngine,
    *,
    component: str,
    detail: str,
    severity: NotificationSeverity = "critical",
    trace_id: str | None = None,
    channels: list[NotificationChannel] | None = None,
) -> DispatchResult:
    source_id = f"health-{component}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    payload = build_notification_payload(
        event=NotificationEvent.SYSTEM_HEALTH_DEGRADED,
        title=f"IronClaw System Health Degraded: {component}",
        body=detail,
        source_id=source_id,
        source_type="system_health",
        severity=severity,
        trace_id=trace_id,
        metadata={"component": component},
    )
    return dispatch_notification(engine, payload, channels=channels)


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------


def summarize_dispatch_result(result: DispatchResult) -> dict[str, Any]:
    return {
        "event": result.payload.event.value if isinstance(result.payload.event, NotificationEvent) else result.payload.event,
        "severity": result.payload.severity,
        "source_id": result.payload.source_id,
        "source_type": result.payload.source_type,
        "channels_attempted": result.channels_attempted,
        "all_succeeded": result.all_succeeded,
        "any_failed": result.any_failed,
        "result_count": len(result.results),
        "dispatched_at": result.dispatched_at,
    }
