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
# Shared constants
# ---------------------------------------------------------------------------

WEBHOOK_SECRET_MIN_LENGTH = 16
WEBHOOK_SECRET_MAX_LENGTH = 512
WEBHOOK_NAME_MAX_LENGTH = 128
WEBHOOK_ORG_ID_MAX_LENGTH = 128
WEBHOOK_EVENT_MAX_ITEMS = 128
WEBHOOK_RESPONSE_SNIPPET_MAX_LENGTH = 512
WEBHOOK_ERROR_MESSAGE_MAX_LENGTH = 1024
WEBHOOK_MAX_RETRIES_MAX = 10
WEBHOOK_TIMEOUT_SECONDS_MAX = 60
WEBHOOK_SCHEMA_VERSION = "1.0"


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

    # Internal catch-all only — never allowed in public create/update inputs
    ALL = "*"


class WebhookStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    FAILING = "failing"


class WebhookDeliveryStatus(StrEnum):
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
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_optional_str(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _require_https_url(value: Any) -> Any:
    if value is None:
        return value
    text = str(value).strip()
    if not text.startswith("https://"):
        raise ValueError("target_url must use HTTPS.")
    return value


def _normalize_secret_str(value: str) -> str:
    normalized = value.strip()
    if len(normalized) < WEBHOOK_SECRET_MIN_LENGTH:
        raise ValueError(f"Secret must be at least {WEBHOOK_SECRET_MIN_LENGTH} characters.")
    if len(normalized) > WEBHOOK_SECRET_MAX_LENGTH:
        raise ValueError(f"Secret must be at most {WEBHOOK_SECRET_MAX_LENGTH} characters.")
    return normalized


def _canonical_public_event_values() -> set[str]:
    return {event.value for event in WebhookEventType if event is not WebhookEventType.ALL}


def _normalize_event_value(value: Any) -> WebhookEventType:
    if isinstance(value, WebhookEventType):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        try:
            return WebhookEventType(candidate)
        except ValueError as exc:
            supported = ", ".join(sorted(_canonical_public_event_values()))
            raise ValueError(f"Unsupported event type '{value}'. Supported values: {supported}") from exc
    raise TypeError("Event type must be a string or WebhookEventType.")


def _normalize_event_list(
    values: list[Any] | tuple[Any, ...] | set[Any] | None,
    *,
    allow_all_wildcard: bool,
) -> list[WebhookEventType] | None:
    if values is None:
        return None

    normalized: list[WebhookEventType] = []
    seen: set[str] = set()

    for raw in values:
        event = _normalize_event_value(raw)
        if event is WebhookEventType.ALL and not allow_all_wildcard:
            raise ValueError("The '*' wildcard is not accepted in webhook subscription event lists. Enumerate specific event types instead.")
        key = event.value
        if key not in seen:
            seen.add(key)
            normalized.append(event)

    if not normalized:
        raise ValueError("At least one event type must be provided.")

    if WebhookEventType.ALL in normalized and len(normalized) > 1:
        raise ValueError("When subscribing to '*' (all events), no other event types may be specified.")

    if len(normalized) > WEBHOOK_EVENT_MAX_ITEMS:
        raise ValueError(f"At most {WEBHOOK_EVENT_MAX_ITEMS} event types may be provided.")

    return normalized


def _event_values(events: list[WebhookEventType]) -> list[str]:
    return [event.value for event in events]


def _secret_hint_from_secret(secret: str) -> str:
    return secret[:8]


# ---------------------------------------------------------------------------
# Base models
# ---------------------------------------------------------------------------


class WebhookBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=False,
        str_strip_whitespace=True,
    )


class WebhookPublicModel(WebhookBaseModel):
    @model_serializer(mode="wrap")
    def _exclude_secrets(self, handler: Any) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        data.pop("secret", None)
        data.pop("secret_hash", None)
        data.pop("signing_secret", None)
        return data


# ---------------------------------------------------------------------------
# Canonical request models
# ---------------------------------------------------------------------------


class WebhookCreateRequest(WebhookBaseModel):
    """
    Canonical public create request for webhook registration.

    This is the single source of truth for webhook creation used by the API,
    service layer, and OpenAPI generation. Raw secrets are accepted on create
    only and are never returned in read models.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=WEBHOOK_NAME_MAX_LENGTH,
        description="Human-readable label for this webhook.",
    )
    target_url: AnyHttpUrl = Field(
        ...,
        description="HTTPS endpoint that will receive webhook deliveries.",
    )
    secret: str = Field(
        ...,
        min_length=WEBHOOK_SECRET_MIN_LENGTH,
        max_length=WEBHOOK_SECRET_MAX_LENGTH,
        repr=False,
        description="Shared signing secret. Accepted on write, never exposed on read.",
    )
    event_types: list[WebhookEventType] = Field(
        ...,
        min_length=1,
        description="Explicit list of subscribed event types. '*' is not allowed in public create/update inputs.",
    )
    org_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=WEBHOOK_ORG_ID_MAX_LENGTH,
        description="Optional organization scope for this webhook.",
    )
    signing_algorithm: WebhookSigningAlgorithm = Field(
        default=WebhookSigningAlgorithm.HMAC_SHA256,
        description="HMAC algorithm used to sign outbound deliveries.",
    )
    active: bool = Field(
        default=True,
        description="Whether the webhook is active immediately after creation.",
    )
    max_retries: int = Field(
        default=3,
        ge=0,
        le=WEBHOOK_MAX_RETRIES_MAX,
        description="Maximum retry attempts after the initial delivery attempt fails.",
    )
    timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=WEBHOOK_TIMEOUT_SECONDS_MAX,
        description="Per-attempt outbound HTTP timeout in seconds.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary caller-supplied metadata stored with the webhook.",
    )

    @field_validator("target_url", mode="before")
    @classmethod
    def _validate_target_url(cls, value: Any) -> Any:
        return _require_https_url(value)

    @field_validator("secret", mode="before")
    @classmethod
    def _validate_secret(cls, value: str) -> str:
        return _normalize_secret_str(value)

    @field_validator("org_id", mode="before")
    @classmethod
    def _normalize_org_id(cls, value: str | None) -> str | None:
        return _normalize_optional_str(value)

    @field_validator("event_types", mode="before")
    @classmethod
    def _validate_event_types(cls, value: Any) -> list[WebhookEventType]:
        normalized = _normalize_event_list(value, allow_all_wildcard=False)
        assert normalized is not None
        return normalized


class WebhookUpdateRequest(WebhookBaseModel):
    """
    Canonical partial update request.

    All fields are optional, but when event_types is supplied it must pass the
    same validation rules as create.
    """

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=WEBHOOK_NAME_MAX_LENGTH,
    )
    target_url: AnyHttpUrl | None = None
    secret: str | None = Field(
        default=None,
        min_length=WEBHOOK_SECRET_MIN_LENGTH,
        max_length=WEBHOOK_SECRET_MAX_LENGTH,
        repr=False,
    )
    event_types: list[WebhookEventType] | None = Field(
        default=None,
        min_length=1,
    )
    org_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=WEBHOOK_ORG_ID_MAX_LENGTH,
    )
    signing_algorithm: WebhookSigningAlgorithm | None = None
    active: bool | None = None
    max_retries: int | None = Field(
        default=None,
        ge=0,
        le=WEBHOOK_MAX_RETRIES_MAX,
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=1,
        le=WEBHOOK_TIMEOUT_SECONDS_MAX,
    )
    metadata: dict[str, Any] | None = None

    @field_validator("target_url", mode="before")
    @classmethod
    def _validate_target_url(cls, value: Any) -> Any:
        return _require_https_url(value)

    @field_validator("secret", mode="before")
    @classmethod
    def _validate_secret(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalize_secret_str(value)

    @field_validator("org_id", mode="before")
    @classmethod
    def _normalize_org_id(cls, value: str | None) -> str | None:
        return _normalize_optional_str(value)

    @field_validator("event_types", mode="before")
    @classmethod
    def _validate_event_types(cls, value: Any) -> list[WebhookEventType] | None:
        return _normalize_event_list(value, allow_all_wildcard=False)


class WebhookFilterRequest(WebhookBaseModel):
    org_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=WEBHOOK_ORG_ID_MAX_LENGTH,
    )
    status: WebhookStatus | None = None
    event_type: WebhookEventType | None = None
    active: bool | None = None

    @field_validator("org_id", mode="before")
    @classmethod
    def _normalize_org_id(cls, value: str | None) -> str | None:
        return _normalize_optional_str(value)

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> WebhookEventType | None:
        if value is None:
            return None
        event = _normalize_event_value(value)
        if event is WebhookEventType.ALL:
            raise ValueError("The '*' wildcard is not valid as a filter event type.")
        return event


class WebhookTestRequest(WebhookBaseModel):
    webhook_id: str = Field(..., min_length=1)
    event_type: WebhookEventType = Field(
        default=WebhookEventType.GUARD_ALLOW,
        description="Event type to simulate for the test delivery.",
    )

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> WebhookEventType:
        event = _normalize_event_value(value)
        if event is WebhookEventType.ALL:
            raise ValueError("The '*' wildcard cannot be used for a test delivery.")
        return event


class WebhookRotateSecretRequest(WebhookBaseModel):
    new_secret: str = Field(
        ...,
        min_length=WEBHOOK_SECRET_MIN_LENGTH,
        max_length=WEBHOOK_SECRET_MAX_LENGTH,
        repr=False,
        description="Replacement signing secret. Must differ from the current secret.",
    )

    @field_validator("new_secret", mode="before")
    @classmethod
    def _validate_new_secret(cls, value: str) -> str:
        return _normalize_secret_str(value)


class WebhookStatusUpdateRequest(WebhookBaseModel):
    active: bool


# ---------------------------------------------------------------------------
# Canonical public response models
# ---------------------------------------------------------------------------


class WebhookResponse(WebhookPublicModel):
    """
    Canonical public webhook record.

    Never exposes raw signing secret material.
    """

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

    @field_validator("event_types", mode="before")
    @classmethod
    def _serialize_event_types(cls, value: Any) -> list[str]:
        normalized = _normalize_event_list(value, allow_all_wildcard=True)
        if normalized is None:
            return []
        return _event_values(normalized)


class WebhookSummaryResponse(WebhookBaseModel):
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


class WebhookCreateResponse(WebhookPublicModel):
    """
    One-time create response for flows that auto-generate the signing secret.

    Use this only for creation paths where the server generates the secret and
    returns it exactly once. Do not use as a normal read model.
    """

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
    secret_hint: str = Field(
        ...,
        description="First 8 characters of the signing secret for operator confirmation.",
    )
    signing_secret: str = Field(
        ...,
        repr=False,
        description="Full signing secret. Returned once at creation only; store securely.",
    )

    @field_validator("event_types", mode="before")
    @classmethod
    def _serialize_event_types(cls, value: Any) -> list[str]:
        normalized = _normalize_event_list(value, allow_all_wildcard=True)
        if normalized is None:
            return []
        return _event_values(normalized)

    @model_validator(mode="after")
    def _validate_secret_hint(self) -> WebhookCreateResponse:
        if not self.secret_hint:
            self.secret_hint = _secret_hint_from_secret(self.signing_secret)
        return self

    @model_serializer(mode="wrap")
    def _preserve_one_time_secret(self, handler: Any) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        data.pop("secret", None)
        data.pop("secret_hash", None)
        return data


class WebhookRotateSecretResponse(WebhookPublicModel):
    """
    Safe rotate response.

    Does not return the new secret. If you later implement one-time rotate-secret
    reveal semantics, use a separate dedicated response model instead of weakening
    this read-safe response.
    """

    webhook_id: str
    signing_algorithm: str
    rotated_at: str = Field(default_factory=_utc_now_iso)
    message: str = "Secret rotated successfully. Update your receiver immediately."


class WebhookStatusUpdateResponse(WebhookBaseModel):
    webhook_id: str
    active: bool
    status: WebhookStatus
    updated_at: str = Field(default_factory=_utc_now_iso)


# ---------------------------------------------------------------------------
# Delivery / audit models
# ---------------------------------------------------------------------------


class WebhookDeliveryAttempt(WebhookBaseModel):
    """
    Canonical single delivery attempt record.

    This model intentionally uses delivery-neutral audit fields and does not
    contain raw payload bodies or secrets.
    """

    attempt_id: str
    webhook_id: str
    event_type: str
    payload_hash: str = Field(description="SHA-256 hex digest of the delivered payload body.")
    status: WebhookDeliveryStatus
    http_status_code: int | None = None
    response_body_snippet: str | None = Field(
        default=None,
        max_length=WEBHOOK_RESPONSE_SNIPPET_MAX_LENGTH,
        description="Truncated response body snippet for debugging.",
    )
    attempt_number: int = Field(ge=1)
    duration_ms: int | None = Field(default=None, ge=0)
    error_message: str | None = Field(
        default=None,
        max_length=WEBHOOK_ERROR_MESSAGE_MAX_LENGTH,
    )
    attempted_at: str = Field(default_factory=_utc_now_iso)

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        event = _normalize_event_value(value)
        return event.value


class WebhookDeliveryResponse(WebhookBaseModel):
    webhook_id: str
    total: int = 0
    attempts: list[WebhookDeliveryAttempt] = Field(default_factory=list)


class WebhookTestResponse(WebhookBaseModel):
    webhook_id: str
    event_type: str
    delivery_status: WebhookDeliveryStatus
    http_status_code: int | None = None
    duration_ms: int | None = None
    error_message: str | None = None
    tested_at: str = Field(default_factory=_utc_now_iso)

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        event = _normalize_event_value(value)
        if event is WebhookEventType.ALL:
            raise ValueError("The '*' wildcard cannot be used for a test response event type.")
        return event.value


# ---------------------------------------------------------------------------
# Canonical outbound envelope
# ---------------------------------------------------------------------------


class WebhookEventPayload(WebhookBaseModel):
    """
    Canonical outbound webhook envelope delivered to target_url.
    """

    model_config = ConfigDict(
        extra="allow",
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=False,
        str_strip_whitespace=True,
    )

    ironclaw_delivery_id: str = Field(description="Unique delivery identifier for idempotency and tracing.")
    webhook_id: str
    event_type: str
    org_id: str | None = None
    schema_version: str = Field(
        default=WEBHOOK_SCHEMA_VERSION,
        description="Payload schema version for forward compatibility.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific payload body.",
    )
    sent_at: str = Field(default_factory=_utc_now_iso)

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        event = _normalize_event_value(value)
        return event.value

    @field_validator("org_id", mode="before")
    @classmethod
    def _normalize_org_id(cls, value: str | None) -> str | None:
        return _normalize_optional_str(value)


# ---------------------------------------------------------------------------
# Compatibility aliases for retiring schema drift
# ---------------------------------------------------------------------------


class WebhookSubscriptionCreate(WebhookBaseModel):
    """
    Compatibility input for older subscription-oriented naming.

    This exists to ease migration from app/schemas/webhook.py naming while
    keeping app/models/webhook.py as the canonical source of truth.
    """

    target_url: AnyHttpUrl
    events: list[WebhookEventType] = Field(min_length=1)
    max_attempts: int = Field(default=5, ge=1, le=WEBHOOK_MAX_RETRIES_MAX)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_url", mode="before")
    @classmethod
    def _validate_target_url(cls, value: Any) -> Any:
        return _require_https_url(value)

    @field_validator("events", mode="before")
    @classmethod
    def _validate_events(cls, value: Any) -> list[WebhookEventType]:
        normalized = _normalize_event_list(value, allow_all_wildcard=False)
        assert normalized is not None
        return normalized


class WebhookSubscriptionUpdateRequest(WebhookBaseModel):
    active: bool | None = None
    events: list[WebhookEventType] | None = Field(default=None, min_length=1)
    max_attempts: int | None = Field(default=None, ge=1, le=WEBHOOK_MAX_RETRIES_MAX)
    metadata: dict[str, Any] | None = None

    @field_validator("events", mode="before")
    @classmethod
    def _validate_events(cls, value: Any) -> list[WebhookEventType] | None:
        return _normalize_event_list(value, allow_all_wildcard=False)


class WebhookSubscriptionResponse(WebhookPublicModel):
    """
    Compatibility read model for older subscription-oriented naming.
    """

    id: str
    tenant_id: str
    target_url: str
    events: list[str]
    active: bool
    max_attempts: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    secret_hint: str

    @field_validator("events", mode="before")
    @classmethod
    def _validate_events(cls, value: Any) -> list[str]:
        normalized = _normalize_event_list(value, allow_all_wildcard=True)
        if normalized is None:
            return []
        return _event_values(normalized)


class WebhookDeliveryLogEntry(WebhookBaseModel):
    """
    Compatibility read model for persistence-layer delivery log rows.
    """

    id: str
    subscription_id: str
    tenant_id: str
    event_type: str
    status: WebhookDeliveryStatus
    attempts: int = Field(default=0, ge=0)
    http_status: int | None = None
    error_detail: str | None = Field(
        default=None,
        max_length=WEBHOOK_ERROR_MESSAGE_MAX_LENGTH,
    )
    delivered_at: str | None = None
    next_attempt_at: str | None = None
    created_at: str = Field(default_factory=_utc_now_iso)

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        event = _normalize_event_value(value)
        return event.value


# ---------------------------------------------------------------------------
# Internal-only secret transport
# ---------------------------------------------------------------------------


class _WebhookSecretWrite(BaseModel):
    """
    Internal-only write container.

    SecretStr prevents accidental disclosure via repr/logging/traceback display.
    Never use this model for public request/response contracts.
    """

    model_config = ConfigDict(extra="forbid")

    secret: SecretStr
