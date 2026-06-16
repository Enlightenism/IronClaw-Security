from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AuditEventType(str, Enum):
    # Prompt layer
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
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"
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
    AUTH_PERMISSION_DENIED = "auth.permission_denied"

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

    # Review layer
    REVIEW_ITEM_CREATED = "review.item_created"
    REVIEW_DECISION_MADE = "review.decision_made"
    REVIEW_ESCALATED = "review.escalated"
    REVIEW_APPROVED = "review.approved"
    REVIEW_REJECTED = "review.rejected"

    # Admin / config layer
    CONFIG_CHANGED = "config.changed"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    ROLE_ASSIGNED = "role.assigned"
    ROLE_REVOKED = "role.revoked"
    API_KEY_ISSUED = "api_key.issued"
    API_KEY_REVOKED = "api_key.revoked"

    # System layer
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    SYSTEM_HEALTH_CHECK = "system.health_check"

    # Audit meta
    AUDIT_EXPORT_REQUESTED = "audit.export_requested"
    AUDIT_LOG_CLEARED = "audit.log_cleared"

    # Generic fallback
    UNKNOWN = "unknown"


class AuditOutcome(str, Enum):
    """Result of the audited action."""

    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    ALLOWED = "allowed"
    QUARANTINED = "quarantined"
    WARNED = "warned"
    PENDING = "pending"
    ERROR = "error"
    UNKNOWN = "unknown"


class AuditSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditTargetType(str, Enum):
    """The type of entity that was the target of the audited action."""

    PROMPT = "prompt"
    TOOL_CALL = "tool_call"
    ACTION = "action"
    POLICY = "policy"
    POLICY_RULE = "policy_rule"
    AGENT = "agent"
    SESSION = "session"
    USER = "user"
    API_KEY = "api_key"
    SCAN = "scan"
    REVIEW_ITEM = "review_item"
    DATA_RECORD = "data_record"
    CONFIG = "config"
    SYSTEM = "system"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Core event models
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """Read model — returned from the audit history endpoints."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    event_type: AuditEventType
    actor: str = Field(
        ...,
        description="Principal that triggered this event (user ID, agent ID, api_key, or 'system')",
    )
    actor_type: str | None = Field(
        None,
        description="Type of actor: user, agent, api_key, system",
    )
    target_type: AuditTargetType
    target_id: str | None = Field(
        None,
        description="ID of the entity that was acted upon",
    )
    action: str = Field(
        ...,
        description="Human-readable description of the action performed",
    )
    outcome: AuditOutcome
    severity: AuditSeverity = AuditSeverity.INFO
    org_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    risk_score: int = Field(default=0, ge=0, le=100)
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    reasoning: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditEventCreate(BaseModel):
    """Write model — submitted to record a new audit event."""

    model_config = ConfigDict(from_attributes=True)

    event_type: AuditEventType
    actor: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Principal that triggered this event",
    )
    actor_type: str | None = Field(
        None,
        description="Type of actor: user, agent, api_key, system",
    )
    target_type: AuditTargetType
    target_id: str | None = None
    action: str = Field(..., min_length=1, max_length=1024)
    outcome: AuditOutcome
    severity: AuditSeverity = AuditSeverity.INFO
    org_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    risk_score: int = Field(default=0, ge=0, le=100)
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    reasoning: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


# ---------------------------------------------------------------------------
# Query / filter model
# ---------------------------------------------------------------------------


class AuditQueryParams(BaseModel):
    """Filter parameters for querying the audit log."""

    event_type: AuditEventType | None = None
    actor: str | None = None
    actor_type: str | None = None
    target_type: AuditTargetType | None = None
    target_id: str | None = None
    outcome: AuditOutcome | None = None
    severity: AuditSeverity | None = None
    org_id: str | None = None
    session_id: str | None = None
    risk_score_min: int | None = Field(default=None, ge=0, le=100)
    risk_score_max: int | None = Field(default=None, ge=0, le=100)
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class AuditListResponse(BaseModel):
    """Paginated response for audit event queries."""

    model_config = ConfigDict(from_attributes=True)

    count: int = Field(ge=0)
    total: int | None = None
    items: list[AuditEvent] = Field(default_factory=list)


class AuditEventResponse(BaseModel):
    """Single-event response wrapper."""

    model_config = ConfigDict(from_attributes=True)

    ok: bool
    event_id: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Access summary models (audit layer observability)
# ---------------------------------------------------------------------------


class AuditAccessCountsSchema(BaseModel):
    totalevents: int = 0
    allowedactions: int = 0
    blockedactions: int = 0
    quarantinedactions: int = 0
    policyviolations: int = 0
    authfailures: int = 0
    criticalevents: int = 0
    latesteventat: str = "Not yet recorded"


class AuditAccessControlsSchema(BaseModel):
    retentiontracked: bool = False
    actorattributionrequired: bool = False
    sessioncorrelationenabled: bool = False
    requestcorrelationenabled: bool = False
    exportcontrolled: bool = False
    tamperdetectionenabled: bool = False


class AuditAccessSummaryResponse(BaseModel):
    pageid: str
    title: str
    path: str
    summary: str
    generatedat: str
    accessavailable: bool = False
    auditvisibilityenabled: bool = False
    recenteventsready: bool = False
    exportcontrolled: bool = False
    counts: AuditAccessCountsSchema = Field(default_factory=AuditAccessCountsSchema)
    controls: AuditAccessControlsSchema = Field(default_factory=AuditAccessControlsSchema)
    recentevents: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
