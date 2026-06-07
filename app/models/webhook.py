from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_serializer,
    model_validator,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class WebhookEventType(StrEnum):
    # Guard / scan verdicts
    GUARD_ALLOW = "guard.allow"
    GUARD_WARN = "guard.warn"
    GUARD_QUARANTINE = "guard.quarantine"
    GUARD_BLOCK = "guard.block"

    # Review queue lifecycle
    REVIEW_SUBMITTED = "review.submitted"
    REVIEW_APPROVED = "review.approved"
    REVIEW_REJECTED = "review.rejected"
    REVIEW_ESCALATED = "review.escalated"
    REVIEW_REQUESTED = "review.requested"
    REVIEW_RESOLVED = "review.resolved"

    # Policy events
    POLICY_UPDATED = "policy.updated"
    POLICY_VIOLATION = "policy.violation"
    POLICY_BLOCK = "policy.block"
    POLICY_WARN = "policy.warn"
    POLICY_ALLOW = "policy.allow"

    # Alert events
    ALERT_CREATED = "alert.created"
    ALERT_RESOLVED = "alert.resolved"

    # Audit events
    AUDIT_EXPORTED = "audit.exported"
    AUDIT_ENTRY = "audit.entry"

    # Session events
    SESSION_STARTED = "session.started"
    SESSION_ENDED = "session.ended"
    SESSION_FLAGGED = "session.flagged"

    # Agent session events
    AGENT_SESSION_STARTED = "agent.session.started"
    AGENT_SESSION_ENDED = "agent.session.ended"

    # Hardening events
    HARDENING_FAIL = "hardening.fail"
    HARDENING_WARN = "hardening.warn"

    # Threat events
    THREAT_DETECTED = "threat.detected"
    THREAT_BLOCKED = "threat.blocked"
    THREAT_FEED_REFRESHED = "threat.feed.refreshed"
    THREAT_HUNT_COMPLETED = "threat.hunt.completed"

    # Quarantine events
    QUARANTINE_CREATED = "quarantine.created"
    QUARANTINE_RELEASED = "quarantine.released"

    # Incident events
    INCIDENT_CREATED = "incident.created"
    INCIDENT_ESCALATED = "incident.escalated"

    # Webhook lifecycle
    WEBHOOK_TEST = "webhook.test"

    # Catch-all for internal use only — never accepted in subscription create/update
    ALL = "*"


class WebhookStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    FAILING = "failing"


class WebhookDeliveryStatus(StrEnum):
    """
    Canonical delivery status enum — single source of truth.
    app/services/webhook_service.py imports this directly.
    """

    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"
    EXHAUSTED = "exhausted"


class WebhookSigningAlgorithm(StrEnum):
    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA512 = "hmac-sha512"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _validate_https_url(v: Any) -> Any:
    """Shared HTTPS enforcer — used by multiple request models."""
    if v is None:
        return v
    url = str(v)
    if not url.startswith("https://"):
        raise ValueError("target_url must use HTTPS.")
    return v


def _validate_event_list(v: list[str] | None) -> list[str] | None:
    """Validate that all event strings are known WebhookEventType values (excluding '*')."""
    if v is None:
        return v
    valid = {e.value for e in WebhookEventType if e.value != "*"}
    unknown = [e for e in v if e not in valid]
    if unknown:
        raise ValueError(f"Unsupported event types: {unknown}. " f"Supported: {sorted(valid)}")
    if "*" in v:
        raise ValueError("The '*' wildcard is not accepted in subscription event lists. " "Enumerate the specific event types you want to receive.")
    return v


# ---------------------------------------------------------------------------
# Base model config
# ---------------------------------------------------------------------------


class WebhookBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )


class _SecretExcludingMixin(WebhookBaseModel):
    """Mixin that strips secret_hash (and secret) from serialized output."""

    @model_serializer(mode="wrap")
    def _exclude_secret_fields(self, handler: Any) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        result.pop("secret_hash", None)
        result.pop("secret", None)
        return result


# ---------------------------------------------------------------------------
# Webhook registration — request / response (legacy full-options model)
# ---------------------------------------------------------------------------


class WebhookCreateRequest(WebhookBaseModel):
    """Register a new webhook endpoint (legacy model — full signing options)."""

    name: str = Field(..., min_length=1, max_length=128, description="Human-readable label for this webhook.")
    target_url: AnyHttpUrl = Field(..., description="HTTPS endpoint that will receive event payloads.")
    secret: str = Field(
        ...,
        min_length=16,
        max_length=512,
        description="Shared secret used to sign payloads (HMAC). Never returned in responses.",
    )
    event_types: list[WebhookEventType] = Field(
        ...,
        min_length=1,
        description="Ordered list of event types this webhook subscribes to. Use '*' for all events.",
    )
    org_id: str | None = Field(default=None, min_length=1, max_length=128, description="Optional organisation scope.")
    signing_algorithm: WebhookSigningAlgorithm = Field(
        default=WebhookSigningAlgorithm.HMAC_SHA256,
        description="Algorithm used for payload signature.",
    )
    active: bool = Field(default=True, description="Whether the webhook is active on creation.")
    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum delivery retry attempts.")
    timeout_seconds: int = Field(default=10, ge=1, le=60, description="HTTP timeout for delivery attempts.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary caller-supplied metadata.")

    @field_validator("target_url", mode="before")
    @classmethod
    def _require_https(cls, v: Any) -> Any:
        return _validate_https_url(v)

    @field_validator("event_types")
    @classmethod
    def _no_duplicate_events(cls, v: list[WebhookEventType]) -> list[WebhookEventType]:
        seen: set[str] = set()
        deduped: list[WebhookEventType] = []
        for item in v:
            key = str(item)
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped

    @model_validator(mode="after")
    def _wildcard_is_exclusive(self) -> WebhookCreateRequest:
        types = [str(e) for e in self.event_types]
        if WebhookEventType.ALL in types and len(types) > 1:
            raise ValueError("When subscribing to '*' (all events), no other event types may be specified.")
        return self


# ---------------------------------------------------------------------------
# WebhookSubscriptionCreate — canonical router-aligned subscription request
# ---------------------------------------------------------------------------


class WebhookSubscriptionCreate(WebhookBaseModel):
    """
    Canonical create request for POST /webhooks/subscriptions.
    Aligns with the router's Supabase row schema (tenant-scoped, auto-generated secret).
    secret_hash is server-generated and write-only — never accepted from the caller.
    The '*' wildcard is rejected; callers must enumerate specific event types.
    """

    target_url: AnyHttpUrl = Field(..., description="HTTPS endpoint to receive deliveries.")
    events: list[str] = Field(
        ...,
        min_length=1,
        description="List of IronClaw event types to subscribe to. '*' is not accepted.",
    )
    max_attempts: int = Field(default=5, ge=1, le=10, description="Maximum delivery retry attempts.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary caller-supplied metadata.")

    @field_validator("target_url", mode="before")
    @classmethod
    def _require_https(cls, v: Any) -> Any:
        return _validate_https_url(v)

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        return _validate_event_list(v) or v


# ---------------------------------------------------------------------------
# WebhookSubscriptionResponse — canonical read response (secret_hash excluded)
# ---------------------------------------------------------------------------


class WebhookSubscriptionResponse(_SecretExcludingMixin):
    """
    Read response for webhook subscription records.
    secret_hash is permanently excluded — only secret_hint is surfaced.
    """

    model_config = ConfigDict(
        extra="ignore",  # tolerate secret_hash from DB row without error
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )

    id: str
    tenant_id: str
    target_url: str
    events: list[str]
    active: bool
    max_attempts: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    secret_hint: str = Field(..., description="First 8 chars of the signing secret prefix — key never re-exposed.")


# ---------------------------------------------------------------------------
# WebhookDeliveryLogEntry — canonical delivery log read model
# ---------------------------------------------------------------------------


class WebhookDeliveryLogEntry(WebhookBaseModel):
    """
    Read model for a single delivery log row from the webhook_delivery_log table.
    Aligns with the column projection used in GET /webhooks/deliveries.
    """

    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )

    id: str
    subscription_id: str
    tenant_id: str
    event_type: str
    status: WebhookDeliveryStatus
    attempts: int = Field(default=0, ge=0)
    http_status: int | None = Field(default=None, description="HTTP response status code from the last attempt.")
    error_detail: str | None = Field(default=None, max_length=1024)
    delivered_at: str | None = None
    next_attempt_at: str | None = None
    created_at: str = Field(default_factory=_utc_now_iso)


# ---------------------------------------------------------------------------
# WebhookCreateResponse — one-time secret exposure on creation
# ---------------------------------------------------------------------------


class WebhookCreateResponse(_SecretExcludingMixin):
    """
    Response for POST /webhooks/subscriptions.
    signing_secret is returned exactly once — store it securely.
    """

    id: str
    tenant_id: str
    target_url: str
    events: list[str]
    active: bool
    max_attempts: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    secret_hint: str = Field(
        ...,
        description="First 8 chars of the signing secret — shown again on subsequent reads.",
    )
    signing_secret: str = Field(
        ...,
        description="Full HMAC-SHA256 signing secret — only returned once at creation. Store securely.",
    )


# ---------------------------------------------------------------------------
# WebhookUpdateRequest — legacy full-options partial update
# ---------------------------------------------------------------------------


class WebhookUpdateRequest(WebhookBaseModel):
    """Partial update — all fields optional."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    target_url: AnyHttpUrl | None = Field(default=None)
    secret: str | None = Field(default=None, min_length=16, max_length=512)
    event_types: list[WebhookEventType] | None = Field(default=None, min_length=1)
    org_id: str | None = Field(default=None, min_length=1, max_length=128)
    signing_algorithm: WebhookSigningAlgorithm | None = None
    active: bool | None = None
    max_retries: int | None = Field(default=None, ge=0, le=10)
    timeout_seconds: int | None = Field(default=None, ge=1, le=60)
    metadata: dict[str, Any] | None = None

    @field_validator("target_url", mode="before")
    @classmethod
    def _require_https(cls, v: Any) -> Any:
        return _validate_https_url(v)

    @field_validator("event_types")
    @classmethod
    def _no_duplicate_events(cls, v: list[WebhookEventType] | None) -> list[WebhookEventType] | None:
        if v is None:
            return v
        seen: set[str] = set()
        deduped: list[WebhookEventType] = []
        for item in v:
            key = str(item)
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped


# ---------------------------------------------------------------------------
# WebhookSubscriptionUpdateRequest — router-aligned partial update
# ---------------------------------------------------------------------------


class WebhookSubscriptionUpdateRequest(WebhookBaseModel):
    """
    Partial update for PATCH /webhooks/subscriptions/{id}.
    Aligns with router field names (events, active, max_attempts, metadata).
    secret_hash is never accepted from the caller.
    The '*' wildcard is rejected; callers must enumerate specific event types.
    """

    active: bool | None = Field(default=None, description="Enable or disable the subscription.")
    events: list[str] | None = Field(default=None, min_length=1, description="Replace the subscribed event list.")
    max_attempts: int | None = Field(default=None, ge=1, le=10)
    metadata: dict[str, Any] | None = None

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str] | None) -> list[str] | None:
        return _validate_event_list(v)


# ---------------------------------------------------------------------------
# WebhookResponse — full record response (legacy, signing options)
# ---------------------------------------------------------------------------


class WebhookResponse(_SecretExcludingMixin):
    """Public webhook record — secret is never included."""

    webhook_id: str
    name: str
    target_url: str
    event_types: list[str]
    org_id: str | None = None
    signing_algorithm: str
    status: WebhookStatus
    active: bool
    max_retries: int
    timeout_seconds: int
    failure_count: int = 0
    last_triggered_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utc_now_iso)
    updated_at: str = Field(default_factory=_utc_now_iso)


# ---------------------------------------------------------------------------
# WebhookSummaryResponse / WebhookListResponse
# ---------------------------------------------------------------------------


class WebhookSummaryResponse(WebhookBaseModel):
    """Lightweight record for list endpoints."""

    webhook_id: str
    name: str
    target_url: str
    status: WebhookStatus
    active: bool
    event_type_count: int
    org_id: str | None = None
    failure_count: int = 0
    created_at: str = Field(default_factory=_utc_now_iso)


class WebhookListResponse(WebhookBaseModel):
    total: int = 0
    items: list[WebhookSummaryResponse] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Webhook delivery record
# ---------------------------------------------------------------------------


class WebhookDeliveryAttempt(WebhookBaseModel):
    """Single delivery attempt record stored for audit."""

    attempt_id: str
    webhook_id: str
    event_type: str
    payload_hash: str = Field(description="SHA-256 hex of the delivered payload — payload itself is not stored.")
    status: WebhookDeliveryStatus
    http_status_code: int | None = None
    response_body_snippet: str | None = Field(
        default=None,
        max_length=512,
        description="First 512 chars of the response body, for debugging.",
    )
    attempt_number: int = Field(ge=1)
    duration_ms: int | None = Field(default=None, ge=0)
    error_message: str | None = None
    attempted_at: str = Field(default_factory=_utc_now_iso)


class WebhookDeliveryResponse(WebhookBaseModel):
    """Delivery history for a single webhook."""

    webhook_id: str
    total: int = 0
    attempts: list[WebhookDeliveryAttempt] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Webhook event payload envelope
# ---------------------------------------------------------------------------


class WebhookEventPayload(WebhookBaseModel):
    """
    Canonical outbound envelope delivered to target_url.
    The `data` field carries the event-specific body.
    The receiver must verify the X-IronClaw-Signature-256 header
    against HMAC-SHA256(secret, raw_body) before trusting this payload.
    """

    model_config = ConfigDict(
        extra="allow",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )

    ironclaw_delivery_id: str = Field(description="Unique delivery ID for idempotency checks.")
    webhook_id: str
    event_type: str
    org_id: str | None = None
    schema_version: str = Field(default="1.0", description="Payload schema version for forward-compat.")
    data: dict[str, Any] = Field(default_factory=dict, description="Event-specific payload body.")
    sent_at: str = Field(default_factory=_utc_now_iso)


# ---------------------------------------------------------------------------
# Webhook test / ping
# ---------------------------------------------------------------------------


class WebhookTestRequest(WebhookBaseModel):
    """Trigger a synthetic test delivery to verify connectivity."""

    webhook_id: str = Field(..., min_length=1)
    event_type: WebhookEventType = Field(
        default=WebhookEventType.GUARD_ALLOW,
        description="Event type to simulate.",
    )


class WebhookTestResponse(WebhookBaseModel):
    webhook_id: str
    event_type: str
    delivery_status: WebhookDeliveryStatus
    http_status_code: int | None = None
    duration_ms: int | None = None
    error_message: str | None = None
    tested_at: str = Field(default_factory=_utc_now_iso)


# ---------------------------------------------------------------------------
# Webhook filter / query
# ---------------------------------------------------------------------------


class WebhookFilterRequest(WebhookBaseModel):
    """Query parameters for filtering webhook lists."""

    org_id: str | None = Field(default=None, min_length=1, max_length=128)
    status: WebhookStatus | None = None
    event_type: WebhookEventType | None = None
    active: bool | None = None


# ---------------------------------------------------------------------------
# Webhook secret rotation
# ---------------------------------------------------------------------------


class WebhookRotateSecretRequest(WebhookBaseModel):
    """Request to rotate the signing secret for a webhook."""

    new_secret: str = Field(
        ...,
        min_length=16,
        max_length=512,
        description="New HMAC signing secret. Must differ from the current secret.",
    )


class WebhookRotateSecretResponse(_SecretExcludingMixin):
    webhook_id: str
    signing_algorithm: str
    rotated_at: str = Field(default_factory=_utc_now_iso)
    message: str = "Secret rotated successfully. Update your receiver immediately."


# ---------------------------------------------------------------------------
# Webhook status toggle
# ---------------------------------------------------------------------------


class WebhookStatusUpdateRequest(WebhookBaseModel):
    active: bool


class WebhookStatusUpdateResponse(WebhookBaseModel):
    webhook_id: str
    active: bool
    status: WebhookStatus
    updated_at: str = Field(default_factory=_utc_now_iso)


# ---------------------------------------------------------------------------
# Write-only secret container (internal use — service layer only)
# ---------------------------------------------------------------------------


class _WebhookSecretWrite(BaseModel):
    """
    Internal-only container for transporting a raw secret into the service layer.
    SecretStr prevents the value from appearing in logs, repr, or serialized output.
    Never instantiated in request/response paths.
    """

    secret: SecretStr
