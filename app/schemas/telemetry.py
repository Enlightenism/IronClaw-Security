from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ─── Event Type Enum ──────────────────────────────────────────────────────────


class TelemetryEventType(str, Enum):
    # Prompt / scan layer
    PROMPT_RECEIVED = "prompt.received"
    PROMPT_SCANNED = "prompt.scanned"
    PROMPT_INJECTION_DETECTED = "prompt.injection_detected"
    PROMPT_BLOCKED = "prompt.blocked"
    PROMPT_ALLOWED = "prompt.allowed"
    PROMPT_QUARANTINED = "prompt.quarantined"
    PROMPT_FLAGGED = "prompt.flagged"
    PROMPT_REDACTED = "prompt.redacted"

    # Tool call layer
    TOOL_CALL_RECEIVED = "tool_call.received"
    TOOL_CALL_EVALUATED = "tool_call.evaluated"
    TOOL_CALL_ALLOWED = "tool_call.allowed"
    TOOL_CALL_BLOCKED = "tool_call.blocked"
    TOOL_CALL_QUARANTINED = "tool_call.quarantined"
    TOOL_CALL_SANDBOXED = "tool_call.sandboxed"
    TOOL_CALL_FAILED = "tool_call.failed"

    # Action / execution layer
    ACTION_SUBMITTED = "action.submitted"
    ACTION_DECISION_MADE = "action.decision_made"
    ACTION_EXECUTED = "action.executed"
    ACTION_BLOCKED = "action.blocked"
    ACTION_QUARANTINED = "action.quarantined"
    ACTION_FAILED = "action.failed"
    ACTION_SANDBOXED = "action.sandboxed"
    ACTION_REVIEWED = "action.reviewed"
    ACTION_REVIEW_APPROVED = "action.review_approved"
    ACTION_REVIEW_REJECTED = "action.review_rejected"

    # Policy layer
    POLICY_EVALUATED = "policy.evaluated"
    POLICY_VIOLATION = "policy.violation"
    POLICY_UPDATED = "policy.updated"
    POLICY_CREATED = "policy.created"
    POLICY_DELETED = "policy.deleted"

    # Agent / session layer
    AGENT_SESSION_STARTED = "agent.session_started"
    AGENT_SESSION_ENDED = "agent.session_ended"
    AGENT_TRUST_DEGRADED = "agent.trust_degraded"
    AGENT_TRUST_RESTORED = "agent.trust_restored"
    AGENT_PROFILE_CREATED = "agent.profile_created"
    AGENT_PROFILE_UPDATED = "agent.profile_updated"

    # Auth layer
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTH_TOKEN_REVOKED = "auth.token_revoked"
    AUTH_RATE_LIMITED = "auth.rate_limited"

    # Data / access layer
    DATA_ACCESS = "data.access"
    DATA_EXPORT_ATTEMPTED = "data.export_attempted"
    DATA_EXPORT_BLOCKED = "data.export_blocked"
    DATA_REDACTED = "data.redacted"
    DATA_LEAKAGE_DETECTED = "data.leakage_detected"

    # Threat / attack layer
    THREAT_DETECTED = "threat.detected"
    THREAT_CORRELATED = "threat.correlated"
    ATTACK_SEQUENCE_IDENTIFIED = "attack.sequence_identified"
    IOC_MATCHED = "ioc.matched"

    # Audit layer
    AUDIT_LOG_WRITTEN = "audit.log_written"
    AUDIT_EXPORT_REQUESTED = "audit.export_requested"

    # System / health layer
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    SYSTEM_HEALTH_CHECK = "system.health_check"
    TELEMETRY_BATCH_INGESTED = "telemetry.batch_ingested"
    TELEMETRY_BATCH_FAILED = "telemetry.batch_failed"

    # Alert layer
    ALERT_CREATED = "alert.created"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_RESOLVED = "alert.resolved"

    # Webhook layer
    WEBHOOK_DELIVERED = "webhook.delivered"
    WEBHOOK_FAILED = "webhook.failed"

    # Generic fallback
    UNKNOWN = "unknown"


# ─── Verdict / Severity ───────────────────────────────────────────────────────


class TelemetryVerdict(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    UNKNOWN = "unknown"


class TelemetrySeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ─── Core Event Models ────────────────────────────────────────────────────────


class TelemetryEvent(BaseModel):
    """Read model — returned from the store / history endpoints."""

    id: str | None = None
    timestamp: str
    event_type: str
    source: str | None = None
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: TelemetryVerdict | None = None
    severity: TelemetrySeverity | None = None
    tags: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    dimensions: dict[str, Any] = Field(default_factory=dict)
    created_at: str | None = None


class TelemetryEventCreate(BaseModel):
    """Write model — submitted by callers to record a new event."""

    event_type: TelemetryEventType
    source: str = Field(min_length=1, max_length=256)
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: TelemetryVerdict | None = None
    severity: TelemetrySeverity | None = None
    tags: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    dimensions: dict[str, Any] = Field(default_factory=dict)
    timestamp: str | None = None


class TelemetryBatch(BaseModel):
    """Batch submission model — wraps multiple TelemetryEventCreate payloads."""

    events: list[TelemetryEventCreate] = Field(min_length=1)
    org_id: str | None = None
    source: str | None = None


# ─── Query / Filter Models ────────────────────────────────────────────────────


class TelemetryQueryParams(BaseModel):
    """Query parameter model for filtering telemetry history."""

    event_type: TelemetryEventType | None = None
    source: str | None = None
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: TelemetryVerdict | None = None
    severity: TelemetrySeverity | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ─── Response Models ──────────────────────────────────────────────────────────


class TelemetryResponse(BaseModel):
    """Paginated response for telemetry event queries."""

    count: int
    total: int | None = None
    items: list[TelemetryEvent] = Field(default_factory=list)


class TelemetryIngestResponse(BaseModel):
    """Response returned after a batch ingest."""

    ok: bool
    received: int = 0
    inserted: int = 0
    duplicates: int = 0
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


# ─── Access Summary Models (preserved — existing contract) ───────────────────


class TelemetryAccessCountsSchema(BaseModel):
    totalevents: int = 0
    allowedreads: int = 0
    flaggedreads: int = 0
    deniedreads: int = 0
    sensitiveexports: int = 0
    latesteventat: str = "Not yet recorded"


class TelemetryAccessControlsSchema(BaseModel):
    retentiontracked: bool = False
    actorattributionrequired: bool = False
    sessioncorrelationenabled: bool = False
    requestcorrelationenabled: bool = False
    redactionguardavailable: bool = False


class TelemetryAccessSummaryResponse(BaseModel):
    pageid: str
    title: str
    path: str
    summary: str
    generatedat: str
    accessavailable: bool = False
    auditvisibilityenabled: bool = False
    recenteventsready: bool = False
    exportcontrolled: bool = False
    counts: TelemetryAccessCountsSchema = Field(default_factory=TelemetryAccessCountsSchema)
    controls: TelemetryAccessControlsSchema = Field(default_factory=TelemetryAccessControlsSchema)
    recentevents: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
