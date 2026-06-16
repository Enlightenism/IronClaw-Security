from __future__ import annotations

from typing import Any

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator

from app.models.webhook import (
    WebhookDeliveryStatus,
    WebhookEventType,
    WebhookSigningAlgorithm,
    WebhookStatus,
    _validate_event_list,
    _validate_https_url,
)

# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------


class _WebhookSchemaBase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )


class _WebhookReadBase(BaseModel):
    """Read-side base — tolerates extra DB columns (e.g. secret_hash) without error."""

    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )


# ---------------------------------------------------------------------------
# WebhookEventType re-export
# Consumers importing from app.schemas.webhook get the canonical enum.
# ---------------------------------------------------------------------------

__all__ = [
    "WebhookEventType",
    "WebhookDeliveryStatus",
    "WebhookStatus",
    "WebhookSigningAlgorithm",
    # Subscription
    "WebhookSubscriptionCreateSchema",
    "WebhookSubscriptionUpdateSchema",
    "WebhookSubscriptionResponseSchema",
    "WebhookSubscriptionCreateResponseSchema",
    "WebhookSubscriptionListResponseSchema",
    # Delivery log
    "WebhookDeliveryLogSchema",
    "WebhookDeliveryLogListResponseSchema",
    # Test / ping
    "WebhookTestRequestSchema",
    "WebhookTestResponseSchema",
    # Retry
    "WebhookRetryResponseSchema",
    # Event payload envelope
    "WebhookEventPayloadSchema",
]


# ---------------------------------------------------------------------------
# Subscription — Create
# ---------------------------------------------------------------------------


class WebhookSubscriptionCreateSchema(_WebhookSchemaBase):
    """
    POST /webhooks/subscriptions request body.

    - target_url: must be HTTPS.
    - events: must be valid WebhookEventType values; '*' wildcard is rejected.
    - max_attempts: delivery retry ceiling (1–10).
    - metadata: arbitrary caller key/value store.

    The signing secret is server-generated on creation and returned once.
    """

    target_url: AnyHttpUrl = Field(
        ...,
        description="HTTPS endpoint to receive IronClaw event deliveries.",
    )
    events: list[str] = Field(
        ...,
        min_length=1,
        description=("IronClaw event types to subscribe to. " "Enumerate specific types — the '*' wildcard is not accepted."),
    )
    max_attempts: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum delivery attempts before the subscription is marked EXHAUSTED.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary caller-supplied metadata attached to the subscription.",
    )

    @field_validator("target_url", mode="before")
    @classmethod
    def _require_https(cls, v: Any) -> Any:
        return _validate_https_url(v)

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        return _validate_event_list(v) or v


# ---------------------------------------------------------------------------
# Subscription — Partial Update
# ---------------------------------------------------------------------------


class WebhookSubscriptionUpdateSchema(_WebhookSchemaBase):
    """
    PATCH /webhooks/subscriptions/{subscription_id} request body.

    All fields are optional — only supplied fields are applied.
    secret_hash is never accepted from the caller.
    """

    active: bool | None = Field(
        default=None,
        description="Enable or disable the subscription.",
    )
    events: list[str] | None = Field(
        default=None,
        min_length=1,
        description="Replace the full subscribed event list.",
    )
    max_attempts: int | None = Field(default=None, ge=1, le=10)
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Replace the metadata map.",
    )

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str] | None) -> list[str] | None:
        return _validate_event_list(v)


# ---------------------------------------------------------------------------
# Subscription — Read Response (secret_hash excluded)
# ---------------------------------------------------------------------------


class WebhookSubscriptionResponseSchema(_WebhookReadBase):
    """
    Read response for a single webhook subscription record.
    secret_hash is permanently excluded — only secret_hint is surfaced.
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
        description="First 8 chars of the signing secret prefix — secret is never re-exposed.",
    )


# ---------------------------------------------------------------------------
# Subscription — Create Response (one-time signing secret exposure)
# ---------------------------------------------------------------------------


class WebhookSubscriptionCreateResponseSchema(_WebhookReadBase):
    """
    Response for POST /webhooks/subscriptions.
    signing_secret is returned exactly once at creation — store it securely.
    It will not appear on any subsequent read.
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
        description="First 8 chars of the signing secret prefix.",
    )
    signing_secret: str = Field(
        ...,
        description=("Full HMAC-SHA256 signing secret. " "Returned once at creation only — store it securely and do not log it."),
    )


# ---------------------------------------------------------------------------
# Subscription — List Response
# ---------------------------------------------------------------------------


class WebhookSubscriptionListResponseSchema(_WebhookReadBase):
    """Paginated list response for GET /webhooks/subscriptions."""

    count: int = Field(..., ge=0)
    subscriptions: list[WebhookSubscriptionResponseSchema] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Delivery Log — Single Entry
# ---------------------------------------------------------------------------


class WebhookDeliveryLogSchema(_WebhookReadBase):
    """
    Read model for a single row from the webhook_delivery_log table.
    Aligns with GET /webhooks/deliveries column projection.
    """

    id: str
    subscription_id: str
    tenant_id: str
    event_type: str
    status: WebhookDeliveryStatus
    attempts: int = Field(default=0, ge=0)
    http_status: int | None = Field(
        default=None,
        description="HTTP response status code from the last delivery attempt.",
    )
    error_detail: str | None = Field(default=None, max_length=1024)
    delivered_at: str | None = None
    next_attempt_at: str | None = None
    created_at: str


# ---------------------------------------------------------------------------
# Delivery Log — List Response
# ---------------------------------------------------------------------------


class WebhookDeliveryLogListResponseSchema(_WebhookReadBase):
    """Paginated list response for GET /webhooks/deliveries."""

    count: int = Field(..., ge=0)
    deliveries: list[WebhookDeliveryLogSchema] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Webhook Test / Ping
# ---------------------------------------------------------------------------


class WebhookTestRequestSchema(_WebhookSchemaBase):
    """
    POST /webhooks/subscriptions/{subscription_id}/test request body.
    Triggers a synthetic delivery to verify endpoint connectivity.
    """

    event_type: WebhookEventType = Field(
        default=WebhookEventType.WEBHOOK_TEST,
        description="IronClaw event type to simulate in the test delivery.",
    )


class WebhookTestResponseSchema(_WebhookReadBase):
    """Response confirming outcome of a synthetic test delivery."""

    subscription_id: str
    event_type: str
    delivery_status: WebhookDeliveryStatus
    http_status: int | None = None
    duration_ms: int | None = None
    error_message: str | None = None
    tested_at: str


# ---------------------------------------------------------------------------
# Retry Response
# ---------------------------------------------------------------------------


class WebhookRetryResponseSchema(_WebhookReadBase):
    """
    Response for POST /webhooks/deliveries/{delivery_id}/retry.
    Confirms that a failed delivery has been re-queued.
    """

    delivery_id: str
    subscription_id: str
    event_type: str
    previous_status: WebhookDeliveryStatus
    queued_at: str


# ---------------------------------------------------------------------------
# Outbound Event Payload Envelope (schema-layer mirror)
# ---------------------------------------------------------------------------


class WebhookEventPayloadSchema(_WebhookSchemaBase):
    """
    Schema-layer mirror of the outbound delivery envelope.
    Used for OpenAPI documentation and validation in test/dispatch endpoints.

    Receivers must verify X-IronClaw-Signature-256 against
    HMAC-SHA256(signing_secret, raw_request_body) before trusting any field.
    """

    model_config = ConfigDict(
        extra="allow",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )

    ironclaw_delivery_id: str = Field(
        ...,
        description="Unique delivery ID — use for idempotency deduplication.",
    )
    subscription_id: str
    event_type: str
    tenant_id: str | None = None
    schema_version: str = Field(
        default="1.0",
        description="Payload schema version for forward compatibility.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific payload body.",
    )
    sent_at: str
