from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TrustEventType(str, Enum):
    """Discrete events that cause trust score changes or profile state transitions."""

    # Positive / trust-building events
    ACTION_APPROVED = "action.approved"
    ACTION_COMPLETED_CLEANLY = "action.completed_cleanly"
    SCAN_PASSED = "scan.passed"
    POLICY_COMPLIANT = "policy.compliant"
    REVIEW_APPROVED = "review.approved"
    AUTH_SUCCESS = "auth.success"
    AGENT_REGISTERED = "agent.registered"
    SESSION_CLEAN = "session.clean"

    # Negative / trust-degrading events
    PROMPT_INJECTION_DETECTED = "prompt.injection_detected"
    TOOL_CALL_BLOCKED = "tool_call.blocked"
    TOOL_CALL_QUARANTINED = "tool_call.quarantined"
    ACTION_BLOCKED = "action.blocked"
    ACTION_QUARANTINED = "action.quarantined"
    ACTION_FAILED = "action.failed"
    POLICY_VIOLATION = "policy.violation"
    SCAN_BLOCKED = "scan.blocked"
    SCAN_QUARANTINED = "scan.quarantined"
    DATA_LEAKAGE_DETECTED = "data.leakage_detected"
    DATA_EXPORT_BLOCKED = "data.export_blocked"
    AUTH_FAILURE = "auth.failure"
    AUTH_RATE_LIMITED = "auth.rate_limited"
    REVIEW_REJECTED = "review.rejected"
    ANOMALY_DETECTED = "anomaly.detected"
    THREAT_DETECTED = "threat.detected"
    ATTACK_SEQUENCE_IDENTIFIED = "attack.sequence_identified"

    # Profile control events
    PROFILE_LOCKED = "profile.locked"
    PROFILE_UNLOCKED = "profile.unlocked"
    PROFILE_RESET = "profile.reset"
    TRUST_RESTORED = "trust.restored"
    TRUST_MANUALLY_ADJUSTED = "trust.manually_adjusted"
    DECAY_APPLIED = "decay.applied"
    SESSION_ENDED = "session.ended"

    # Meta
    UNKNOWN = "unknown"


class TrustTier(str, Enum):
    """Human-readable classification of the current trust score range."""

    CRITICAL = "critical"  # 0–19
    LOW = "low"  # 20–39
    MODERATE = "moderate"  # 40–59
    HIGH = "high"  # 60–79
    FULL = "full"  # 80–100


class TrustOutcome(str, Enum):
    INCREASED = "increased"
    DECREASED = "decreased"
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    RESET = "reset"
    UNCHANGED = "unchanged"
    DECAYED = "decayed"


class TrustDecayStrategy(str, Enum):
    """Algorithm used when applying passive trust decay."""

    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    STEP = "step"
    NONE = "none"


# ---------------------------------------------------------------------------
# Trust score helpers
# ---------------------------------------------------------------------------


def _score_to_tier(score: int) -> TrustTier:
    if score < 20:
        return TrustTier.CRITICAL
    if score < 40:
        return TrustTier.LOW
    if score < 60:
        return TrustTier.MODERATE
    if score < 80:
        return TrustTier.HIGH
    return TrustTier.FULL


# ---------------------------------------------------------------------------
# TrustScore — lightweight value object
# ---------------------------------------------------------------------------


class TrustScore(BaseModel):
    """Immutable snapshot of an agent's current trust score with derived tier."""

    model_config = ConfigDict(from_attributes=True)

    agent_id: str = Field(..., min_length=1, max_length=512)
    score: int = Field(..., ge=0, le=100, description="Current trust score 0–100")
    tier: TrustTier = Field(
        default=TrustTier.MODERATE,
        description="Derived classification from score range",
    )
    previous_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Score before the most recent event",
    )
    delta: int | None = Field(
        default=None,
        description="Score change from the most recent event (positive = increase)",
    )
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def derive_tier(self) -> TrustScore:
        self.tier = _score_to_tier(self.score)
        return self


# ---------------------------------------------------------------------------
# TrustDecayConfig — per-agent or system-wide decay configuration
# ---------------------------------------------------------------------------


class TrustDecayConfig(BaseModel):
    """Configures how an agent's trust score passively decays over time without activity."""

    model_config = ConfigDict(from_attributes=True)

    agent_id: str | None = Field(
        default=None,
        description="Agent this config applies to; None means system-wide default",
    )
    strategy: TrustDecayStrategy = TrustDecayStrategy.LINEAR
    decay_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=100.0,
        description="Points decayed per decay_interval_hours under LINEAR/STEP strategy",
    )
    decay_interval_hours: float = Field(
        default=24.0,
        gt=0.0,
        description="Hours between each decay application",
    )
    min_score_floor: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Trust score will never decay below this floor",
    )
    exponential_base: float = Field(
        default=0.99,
        gt=0.0,
        le=1.0,
        description="Multiplier per interval for EXPONENTIAL strategy (e.g. 0.99 = -1% per interval)",
    )
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("decay_rate")
    @classmethod
    def validate_decay_rate(cls, v: float) -> float:
        if v < 0:
            raise ValueError("decay_rate must be >= 0")
        return v


# ---------------------------------------------------------------------------
# TrustEvent — write model
# ---------------------------------------------------------------------------


class TrustEventCreate(BaseModel):
    """Payload submitted to record a trust-affecting event for an agent."""

    model_config = ConfigDict(from_attributes=True)

    agent_id: str = Field(..., min_length=1, max_length=512)
    event_type: TrustEventType
    score_delta: int = Field(
        ...,
        ge=-100,
        le=100,
        description="Change applied to trust score; negative = decrease",
    )
    outcome: TrustOutcome
    triggered_by: str | None = Field(
        default=None,
        description="ID of the action, scan, policy, or session that caused this event",
    )
    triggered_by_type: str | None = Field(
        default=None,
        description="Type of the triggering artifact: scan, tool_call, action, policy, session",
    )
    org_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    actor: str | None = Field(
        default=None,
        description="Principal that initiated the triggering action (user, system, agent)",
    )
    reasoning: str | None = Field(
        default=None,
        max_length=2048,
    )
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


# ---------------------------------------------------------------------------
# TrustEvent — read model
# ---------------------------------------------------------------------------


class TrustEvent(BaseModel):
    """Persisted trust event record returned from the trust history endpoints."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    agent_id: str
    event_type: TrustEventType
    score_before: int = Field(..., ge=0, le=100)
    score_after: int = Field(..., ge=0, le=100)
    score_delta: int = Field(..., ge=-100, le=100)
    outcome: TrustOutcome
    triggered_by: str | None = None
    triggered_by_type: str | None = None
    org_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    actor: str | None = None
    reasoning: str | None = None
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# TrustProfile — full agent trust profile
# ---------------------------------------------------------------------------


class TrustProfile(BaseModel):
    """Complete trust profile for an agent, including score, anomaly tracking, and lock state."""

    model_config = ConfigDict(from_attributes=True)

    agent_id: str = Field(..., min_length=1, max_length=512)
    trust_score: int = Field(
        default=100,
        ge=0,
        le=100,
        description="Current trust score 0–100; defaults to full trust on creation",
    )
    trust_tier: TrustTier = TrustTier.FULL
    anomaly_count: int = Field(
        default=0,
        ge=0,
        description="Cumulative count of anomalies detected for this agent",
    )
    last_anomaly_at: datetime | None = Field(
        default=None,
        description="Timestamp of the most recent anomaly event",
    )
    profile_locked: bool = Field(
        default=False,
        description="When True, the agent is suspended — no actions are permitted",
    )
    locked_at: datetime | None = Field(
        default=None,
        description="Timestamp when the profile was last locked",
    )
    locked_reason: str | None = Field(
        default=None,
        description="Human-readable reason for the lock",
    )
    lock_expires_at: datetime | None = Field(
        default=None,
        description="Optional expiry time for the lock; None means manual unlock required",
    )
    org_id: str | None = None
    session_id: str | None = None
    consecutive_clean_actions: int = Field(
        default=0,
        ge=0,
        description="Number of consecutive clean (unblocked) actions since last anomaly",
    )
    total_actions: int = Field(default=0, ge=0)
    total_blocked_actions: int = Field(default=0, ge=0)
    decay_config: TrustDecayConfig | None = Field(
        default=None,
        description="Override decay config; None means system default applies",
    )
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None

    @model_validator(mode="after")
    def derive_trust_tier(self) -> TrustProfile:
        self.trust_tier = _score_to_tier(self.trust_score)
        return self


class TrustProfileCreate(BaseModel):
    """Payload to register a new agent trust profile."""

    model_config = ConfigDict(from_attributes=True)

    agent_id: str = Field(..., min_length=1, max_length=512)
    initial_score: int = Field(
        default=100,
        ge=0,
        le=100,
        description="Starting trust score for the new profile",
    )
    org_id: str | None = None
    session_id: str | None = None
    decay_config: TrustDecayConfig | None = None
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrustProfileUpdate(BaseModel):
    """Partial update payload for an existing trust profile."""

    model_config = ConfigDict(from_attributes=True)

    trust_score: int | None = Field(default=None, ge=0, le=100)
    profile_locked: bool | None = None
    locked_reason: str | None = None
    lock_expires_at: datetime | None = None
    org_id: str | None = None
    session_id: str | None = None
    decay_config: TrustDecayConfig | None = None
    categories: list[str] | None = None
    tags: list[str] | None = None
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Query / filter model
# ---------------------------------------------------------------------------


class TrustQueryParams(BaseModel):
    """Filter parameters for querying trust profiles and trust event history."""

    agent_id: str | None = None
    org_id: str | None = None
    session_id: str | None = None
    trust_tier: TrustTier | None = None
    profile_locked: bool | None = None
    event_type: TrustEventType | None = None
    outcome: TrustOutcome | None = None
    trust_score_min: int | None = Field(default=None, ge=0, le=100)
    trust_score_max: int | None = Field(default=None, ge=0, le=100)
    anomaly_count_min: int | None = Field(default=None, ge=0)
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class TrustProfileResponse(BaseModel):
    """Single trust profile response wrapper."""

    model_config = ConfigDict(from_attributes=True)

    ok: bool
    agent_id: str | None = None
    profile: TrustProfile | None = None
    error: str | None = None


class TrustProfileListResponse(BaseModel):
    """Paginated list of trust profiles."""

    model_config = ConfigDict(from_attributes=True)

    count: int = Field(ge=0)
    total: int | None = None
    items: list[TrustProfile] = Field(default_factory=list)


class TrustEventListResponse(BaseModel):
    """Paginated list of trust events."""

    model_config = ConfigDict(from_attributes=True)

    count: int = Field(ge=0)
    total: int | None = None
    items: list[TrustEvent] = Field(default_factory=list)


class TrustEventResponse(BaseModel):
    """Single trust event write response."""

    model_config = ConfigDict(from_attributes=True)

    ok: bool
    event_id: str | None = None
    score_after: int | None = Field(default=None, ge=0, le=100)
    tier_after: TrustTier | None = None
    profile_locked: bool | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Access summary models (trust layer observability)
# ---------------------------------------------------------------------------


class TrustAccessCountsSchema(BaseModel):
    totalprofiles: int = 0
    lockedprofiles: int = 0
    criticaltiertprofiles: int = 0
    lowtiertprofiles: int = 0
    totaltrustevents: int = 0
    trustdegradations: int = 0
    trustrestorations: int = 0
    latesteventat: str = "Not yet recorded"


class TrustAccessControlsSchema(BaseModel):
    decayconfigured: bool = False
    lockenforcementenabled: bool = False
    anomalythresholdset: bool = False
    sessioncorrelationenabled: bool = False
    auditintegrationenabled: bool = False
    manualadjustmentcontrolled: bool = False


class TrustAccessSummaryResponse(BaseModel):
    pageid: str
    title: str
    path: str
    summary: str
    generatedat: str
    accessavailable: bool = False
    trustvisibilityenabled: bool = False
    recenteventsready: bool = False
    decayconfigured: bool = False
    counts: TrustAccessCountsSchema = Field(default_factory=TrustAccessCountsSchema)
    controls: TrustAccessControlsSchema = Field(default_factory=TrustAccessControlsSchema)
    recentevents: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
