from __future__ import annotations

from typing import Any

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator

from app.models.webhook import (
    WEBHOOK_ERROR_MESSAGE_MAX_LENGTH,
    WEBHOOK_MAX_RETRIES_MAX,
    WEBHOOK_SCHEMA_VERSION,
    WebhookDeliveryStatus,
    WebhookEventType,
    WebhookSigningAlgorithm,
    WebhookStatus,
    _normalize_event_list,
    _normalize_event_value,
    _require_https_url,
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
        str_strip_whitespace=True,
    )


class _WebhookReadBase(BaseModel):
    """Read-side base — tolerates extra DB columns (e.g. secret_hash) without error."""

    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------


def _validate_public_event_list(
    value: list[str] | list[WebhookEventType] | None,
) -> list[str] | None:
    normalized = _normalize_event_list(value, allow_all_wildcard=False)
    if normalized is None:
        return None
    return [event.value for event in normalized]


def _validate_read_event_list(
    value: list[str] | list[WebhookEventType] | None,
) -> list[str] | None:
    normalized = _normalize_event_list(value, allow_all_wildcard=True)
    if normalized is None:
        return None
    return [event.value for event in normalized]


def _validate_public_event_value(value: Any) -> str:
    event = _normalize_event_value(value)
    if event is WebhookEventType.ALL:
        raise ValueError("The '*' wildcard is not accepted here.")
    return event.value


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
    Compatibility request body for older subscription-oriented routes.

    This schema remains intentionally shaped like the legacy subscription API
    while delegating validation rules to the canonical webhook model helpers.
    """

    target_url: AnyHttpUrl = Field(
        ...,
        description="HTTPS endpoint to receive IronClaw event deliveries.",
    )
    events: list[str] = Field(
        ...,
        min_length=1,
        description=("IronClaw event types to subscribe to. Enumerate specific types — the '*' wildcard is not accepted."),
    )
    max_attempts: int = Field(
        default=5,
        ge=1,
        le=WEBHOOK_MAX_RETRIES_MAX,
        description="Maximum delivery attempts before the subscription is marked EXHAUSTED.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary caller-supplied metadata attached to the subscription.",
    )

    @field_validator("target_url", mode="before")
    @classmethod
    def _require_https(cls, value: Any) -> Any:
        return _require_https_url(value)

    @field_validator("events", mode="before")
    @classmethod
    def _validate_events(cls, value: Any) -> list[str]:
        normalized = _validate_public_event_list(value)
        assert normalized is not None
        return normalized


# ---------------------------------------------------------------------------
# Subscription — Partial Update
# ---------------------------------------------------------------------------


class WebhookSubscriptionUpdateSchema(_WebhookSchemaBase):
    """
    Compatibility PATCH request body for older subscription-oriented routes.

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
    max_attempts: int | None = Field(
        default=None,
        ge=1,
        le=WEBHOOK_MAX_RETRIES_MAX,
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Replace the metadata map.",
    )

    @field_validator("events", mode="before")
    @classmethod
    def _validate_events(cls, value: Any) -> list[str] | None:
        return _validate_public_event_list(value)


# ---------------------------------------------------------------------------
# Subscription — Read Response (secret_hash excluded)
# ---------------------------------------------------------------------------


class WebhookSubscriptionResponseSchema(_WebhookReadBase):
    """
    Compatibility read response for a single webhook subscription record.

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

    @field_validator("events", mode="before")
    @classmethod
    def _validate_events(cls, value: Any) -> list[str]:
        normalized = _validate_read_event_list(value)
        if normalized is None:
            return []
        return normalized


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
        description=("Full signing secret. Returned once at creation only — store it securely and do not log it."),
    )

    @field_validator("events", mode="before")
    @classmethod
    def _validate_events(cls, value: Any) -> list[str]:
        normalized = _validate_read_event_list(value)
        if normalized is None:
            return []
        return normalized


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
    Compatibility read model for a single row from the webhook delivery log table.

    Aligns legacy field names with canonical event and status validation.
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
    error_detail: str | None = Field(
        default=None,
        max_length=WEBHOOK_ERROR_MESSAGE_MAX_LENGTH,
    )
    delivered_at: str | None = None
    next_attempt_at: str | None = None
    created_at: str

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        return _normalize_event_value(value).value


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

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        return _validate_public_event_value(value)


class WebhookTestResponseSchema(_WebhookReadBase):
    """Response confirming outcome of a synthetic test delivery."""

    subscription_id: str
    event_type: str
    delivery_status: WebhookDeliveryStatus
    http_status: int | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    error_message: str | None = Field(
        default=None,
        max_length=WEBHOOK_ERROR_MESSAGE_MAX_LENGTH,
    )
    tested_at: str

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        return _validate_public_event_value(value)


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

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        return _normalize_event_value(value).value


# ---------------------------------------------------------------------------
# Outbound Event Payload Envelope (schema-layer mirror)
# ---------------------------------------------------------------------------


class WebhookEventPayloadSchema(_WebhookSchemaBase):
    """
    Schema-layer mirror of the outbound delivery envelope.

    Used for OpenAPI documentation and validation in test/dispatch endpoints.

    Receivers must verify the configured webhook signature header against the
    raw request body before trusting any field.
    """

    model_config = ConfigDict(
        extra="allow",
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    ironclaw_delivery_id: str = Field(
        ...,
        description="Unique delivery ID — use for idempotency deduplication.",
    )
    subscription_id: str
    event_type: str
    tenant_id: str | None = None
    schema_version: str = Field(
        default=WEBHOOK_SCHEMA_VERSION,
        description="Payload schema version for forward compatibility.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific payload body.",
    )
    sent_at: str

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> str:
        return _normalize_event_value(value).value
