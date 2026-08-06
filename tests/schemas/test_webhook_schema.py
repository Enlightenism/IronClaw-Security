from __future__ import annotations

from pydantic import ValidationError
import pytest

from app.schemas.webhook import (
    WebhookDeliveryLogListResponseSchema,
    WebhookDeliveryLogSchema,
    WebhookDeliveryStatus,
    WebhookEventPayloadSchema,
    WebhookEventType,
    WebhookRetryResponseSchema,
    WebhookSubscriptionCreateResponseSchema,
    WebhookSubscriptionCreateSchema,
    WebhookSubscriptionListResponseSchema,
    WebhookSubscriptionResponseSchema,
    WebhookSubscriptionUpdateSchema,
    WebhookTestRequestSchema,
    WebhookTestResponseSchema,
)

# ---------------------------------------------------------------------------
# Fixtures / shared builders
# ---------------------------------------------------------------------------

_VALID_EVENTS = ["guard.allow", "guard.block"]
_VALID_URL = "https://example.com/ironclaw-hook"
_NOW = "2026-06-16T12:00:00+00:00"


def _valid_create_payload(**overrides) -> dict:
    base = {
        "target_url": _VALID_URL,
        "events": _VALID_EVENTS,
    }
    base.update(overrides)
    return base


def _valid_subscription_response_row(**overrides) -> dict:
    base = {
        "id": "sub-001",
        "tenant_id": "tenant-abc",
        "target_url": _VALID_URL,
        "events": _VALID_EVENTS,
        "active": True,
        "max_attempts": 5,
        "metadata": {},
        "created_at": _NOW,
        "secret_hint": "deadbeef...",
    }
    base.update(overrides)
    return base


def _valid_delivery_log_row(**overrides) -> dict:
    base = {
        "id": "dlv-001",
        "subscription_id": "sub-001",
        "tenant_id": "tenant-abc",
        "event_type": "guard.block",
        "status": "success",
        "attempts": 1,
        "created_at": _NOW,
    }
    base.update(overrides)
    return base


def _valid_create_response(**overrides) -> dict:
    base = {
        "id": "sub-002",
        "tenant_id": "tenant-abc",
        "target_url": _VALID_URL,
        "events": _VALID_EVENTS,
        "active": True,
        "max_attempts": 5,
        "metadata": {},
        "created_at": _NOW,
        "secret_hint": "deadbeef...",
        "signing_secret": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    }
    base.update(overrides)
    return base


def _valid_event_payload(**overrides) -> dict:
    base = {
        "ironclaw_delivery_id": "del-abc123",
        "subscription_id": "sub-001",
        "event_type": "guard.block",
        "sent_at": _NOW,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# WebhookSubscriptionCreateSchema — URL validation
# ---------------------------------------------------------------------------


def test_create_schema_accepts_https_url():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload())
    assert str(schema.target_url).startswith("https://")


def test_create_schema_rejects_http_url():
    with pytest.raises(ValidationError, match="HTTPS"):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(target_url="http://example.com/hook"))


def test_create_schema_rejects_missing_url():
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateSchema(events=_VALID_EVENTS)


def test_create_schema_rejects_blank_url():
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(target_url=""))


# ---------------------------------------------------------------------------
# WebhookSubscriptionCreateSchema — event list validation
# ---------------------------------------------------------------------------


def test_create_schema_accepts_valid_events():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload(events=["guard.allow", "guard.warn"]))
    assert "guard.allow" in schema.events
    assert "guard.warn" in schema.events


def test_create_schema_deduplicates_duplicate_events():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload(events=["guard.allow", "guard.block", "guard.allow", "guard.block"]))
    assert schema.events == ["guard.allow", "guard.block"]


def test_create_schema_rejects_wildcard_event():
    with pytest.raises(ValidationError, match=r"\*"):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(events=["*"]))


def test_create_schema_rejects_wildcard_mixed_with_valid():
    with pytest.raises(ValidationError, match=r"\*"):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(events=["guard.allow", "*"]))


def test_create_schema_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="Unsupported event type"):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(events=["not.a.real.event"]))


def test_create_schema_rejects_empty_event_list():
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(events=[]))


def test_create_schema_rejects_missing_events_field():
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateSchema(target_url=_VALID_URL)


def test_create_schema_accepts_all_known_event_types():
    all_events = [event.value for event in WebhookEventType if event is not WebhookEventType.ALL]
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload(events=all_events))
    assert len(schema.events) == len(all_events)


# ---------------------------------------------------------------------------
# WebhookSubscriptionCreateSchema — field defaults
# ---------------------------------------------------------------------------


def test_create_schema_default_max_attempts():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload())
    assert schema.max_attempts == 5


def test_create_schema_default_metadata_empty_dict():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload())
    assert schema.metadata == {}


def test_create_schema_max_attempts_lower_bound():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload(max_attempts=1))
    assert schema.max_attempts == 1


def test_create_schema_max_attempts_upper_bound():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload(max_attempts=10))
    assert schema.max_attempts == 10


def test_create_schema_max_attempts_zero_rejected():
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(max_attempts=0))


def test_create_schema_max_attempts_over_limit_rejected():
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(max_attempts=11))


def test_create_schema_accepts_metadata():
    schema = WebhookSubscriptionCreateSchema(**_valid_create_payload(metadata={"env": "prod", "owner": "team-a"}))
    assert schema.metadata["env"] == "prod"


def test_create_schema_extra_fields_rejected():
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateSchema(**_valid_create_payload(secret_hash="should_not_be_accepted"))


# ---------------------------------------------------------------------------
# WebhookSubscriptionUpdateSchema — partial update
# ---------------------------------------------------------------------------


def test_update_schema_all_none_is_valid():
    schema = WebhookSubscriptionUpdateSchema()
    assert schema.active is None
    assert schema.events is None
    assert schema.max_attempts is None
    assert schema.metadata is None


def test_update_schema_active_only():
    schema = WebhookSubscriptionUpdateSchema(active=False)
    assert schema.active is False
    assert schema.events is None


def test_update_schema_events_only():
    schema = WebhookSubscriptionUpdateSchema(events=["guard.block"])
    assert schema.events == ["guard.block"]


def test_update_schema_deduplicates_duplicate_events():
    schema = WebhookSubscriptionUpdateSchema(events=["guard.block", "guard.block", "guard.allow"])
    assert schema.events == ["guard.block", "guard.allow"]


def test_update_schema_max_attempts_only():
    schema = WebhookSubscriptionUpdateSchema(max_attempts=3)
    assert schema.max_attempts == 3


def test_update_schema_metadata_only():
    schema = WebhookSubscriptionUpdateSchema(metadata={"updated": True})
    assert schema.metadata == {"updated": True}


def test_update_schema_rejects_wildcard_in_events():
    with pytest.raises(ValidationError, match=r"\*"):
        WebhookSubscriptionUpdateSchema(events=["*"])


def test_update_schema_rejects_unknown_event_in_update():
    with pytest.raises(ValidationError, match="Unsupported event type"):
        WebhookSubscriptionUpdateSchema(events=["fake.event.type"])


def test_update_schema_rejects_empty_event_list():
    with pytest.raises(ValidationError):
        WebhookSubscriptionUpdateSchema(events=[])


def test_update_schema_rejects_max_attempts_zero():
    with pytest.raises(ValidationError):
        WebhookSubscriptionUpdateSchema(max_attempts=0)


def test_update_schema_rejects_max_attempts_over_limit():
    with pytest.raises(ValidationError):
        WebhookSubscriptionUpdateSchema(max_attempts=11)


def test_update_schema_extra_fields_rejected():
    with pytest.raises(ValidationError):
        WebhookSubscriptionUpdateSchema(secret_hash="nope")


# ---------------------------------------------------------------------------
# WebhookSubscriptionResponseSchema — read response contract
# ---------------------------------------------------------------------------


def test_subscription_response_schema_valid():
    schema = WebhookSubscriptionResponseSchema(**_valid_subscription_response_row())
    assert schema.id == "sub-001"
    assert schema.tenant_id == "tenant-abc"
    assert schema.active is True
    assert schema.secret_hint == "deadbeef..."


def test_subscription_response_schema_tolerates_secret_hash_in_db_row():
    row = _valid_subscription_response_row(secret_hash="cafebabe1234deadbeef")
    schema = WebhookSubscriptionResponseSchema(**row)
    assert schema.id == "sub-001"
    assert "secret_hash" not in schema.model_dump()


def test_subscription_response_schema_does_not_expose_signing_secret():
    row = _valid_subscription_response_row(signing_secret="super_secret_value")
    schema = WebhookSubscriptionResponseSchema(**row)
    serialized = schema.model_dump()
    assert "signing_secret" not in serialized
    assert "secret_hash" not in serialized


def test_subscription_response_schema_events_preserved():
    schema = WebhookSubscriptionResponseSchema(**_valid_subscription_response_row())
    assert schema.events == _VALID_EVENTS


def test_subscription_response_schema_metadata_defaults_empty():
    row = _valid_subscription_response_row()
    row.pop("metadata", None)
    schema = WebhookSubscriptionResponseSchema(**row)
    assert schema.metadata == {}


# ---------------------------------------------------------------------------
# WebhookSubscriptionCreateResponseSchema — one-time secret exposure
# ---------------------------------------------------------------------------


def test_create_response_schema_exposes_signing_secret():
    schema = WebhookSubscriptionCreateResponseSchema(**_valid_create_response())
    assert schema.signing_secret == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


def test_create_response_schema_exposes_secret_hint():
    schema = WebhookSubscriptionCreateResponseSchema(**_valid_create_response())
    assert schema.secret_hint == "deadbeef..."


def test_create_response_schema_signing_secret_in_serialized_output():
    schema = WebhookSubscriptionCreateResponseSchema(**_valid_create_response())
    data = schema.model_dump()
    assert "signing_secret" in data
    assert data["signing_secret"] == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


def test_create_response_schema_secret_hash_not_in_output():
    schema = WebhookSubscriptionCreateResponseSchema(**_valid_create_response(secret_hash="internal_hash"))
    data = schema.model_dump()
    assert "secret_hash" not in data


def test_create_response_schema_missing_signing_secret_rejected():
    payload = _valid_create_response()
    del payload["signing_secret"]
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateResponseSchema(**payload)


def test_create_response_schema_missing_secret_hint_rejected():
    payload = _valid_create_response()
    del payload["secret_hint"]
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateResponseSchema(**payload)


# ---------------------------------------------------------------------------
# WebhookSubscriptionListResponseSchema
# ---------------------------------------------------------------------------


def test_subscription_list_response_empty():
    response = WebhookSubscriptionListResponseSchema(count=0, subscriptions=[])
    assert response.count == 0
    assert response.subscriptions == []


def test_subscription_list_response_with_items():
    subscription = WebhookSubscriptionResponseSchema(**_valid_subscription_response_row())
    response = WebhookSubscriptionListResponseSchema(
        count=1,
        subscriptions=[subscription],
    )
    assert response.count == 1
    assert response.subscriptions[0].id == "sub-001"


def test_subscription_list_response_negative_count_rejected():
    with pytest.raises(ValidationError):
        WebhookSubscriptionListResponseSchema(count=-1, subscriptions=[])


# ---------------------------------------------------------------------------
# WebhookDeliveryLogSchema — DB row deserialization
# ---------------------------------------------------------------------------


def test_delivery_log_schema_valid():
    log = WebhookDeliveryLogSchema(**_valid_delivery_log_row())
    assert log.id == "dlv-001"
    assert log.status == WebhookDeliveryStatus.SUCCESS


def test_delivery_log_schema_tolerates_extra_db_columns():
    row = _valid_delivery_log_row(secret_hash="should_be_ignored", internal_flag=True)
    log = WebhookDeliveryLogSchema(**row)
    assert log.id == "dlv-001"
    data = log.model_dump()
    assert "secret_hash" not in data
    assert "internal_flag" not in data


def test_delivery_log_schema_optional_http_status_defaults_none():
    log = WebhookDeliveryLogSchema(**_valid_delivery_log_row())
    assert log.http_status is None


def test_delivery_log_schema_optional_error_detail_defaults_none():
    log = WebhookDeliveryLogSchema(**_valid_delivery_log_row())
    assert log.error_detail is None


def test_delivery_log_schema_optional_delivered_at_defaults_none():
    log = WebhookDeliveryLogSchema(**_valid_delivery_log_row())
    assert log.delivered_at is None


def test_delivery_log_schema_optional_next_attempt_at_defaults_none():
    log = WebhookDeliveryLogSchema(**_valid_delivery_log_row())
    assert log.next_attempt_at is None


def test_delivery_log_schema_attempts_defaults_zero():
    row = _valid_delivery_log_row()
    row.pop("attempts", None)
    log = WebhookDeliveryLogSchema(**row)
    assert log.attempts == 0


def test_delivery_log_schema_all_delivery_statuses_accepted():
    for status in WebhookDeliveryStatus:
        row = _valid_delivery_log_row(status=status.value)
        log = WebhookDeliveryLogSchema(**row)
        assert log.status == status


def test_delivery_log_schema_invalid_status_rejected():
    with pytest.raises(ValidationError):
        WebhookDeliveryLogSchema(**_valid_delivery_log_row(status="unknown_status"))


def test_delivery_log_schema_error_detail_too_long_rejected():
    with pytest.raises(ValidationError):
        WebhookDeliveryLogSchema(**_valid_delivery_log_row(error_detail="x" * 1025))


def test_delivery_log_schema_http_status_populated():
    log = WebhookDeliveryLogSchema(**_valid_delivery_log_row(http_status=200))
    assert log.http_status == 200


def test_delivery_log_schema_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="Unsupported event type"):
        WebhookDeliveryLogSchema(**_valid_delivery_log_row(event_type="not.a.real.event"))


# ---------------------------------------------------------------------------
# WebhookDeliveryLogListResponseSchema
# ---------------------------------------------------------------------------


def test_delivery_log_list_response_empty():
    response = WebhookDeliveryLogListResponseSchema(count=0, deliveries=[])
    assert response.count == 0
    assert response.deliveries == []


def test_delivery_log_list_response_with_items():
    log = WebhookDeliveryLogSchema(**_valid_delivery_log_row())
    response = WebhookDeliveryLogListResponseSchema(count=1, deliveries=[log])
    assert response.count == 1
    assert response.deliveries[0].id == "dlv-001"


# ---------------------------------------------------------------------------
# WebhookTestRequestSchema — defaults and validation
# ---------------------------------------------------------------------------


def test_test_request_schema_defaults_to_webhook_test_event():
    schema = WebhookTestRequestSchema()
    assert schema.event_type == WebhookEventType.WEBHOOK_TEST


def test_test_request_schema_accepts_valid_event_type():
    schema = WebhookTestRequestSchema(event_type=WebhookEventType.GUARD_BLOCK)
    assert schema.event_type == WebhookEventType.GUARD_BLOCK


def test_test_request_schema_accepts_event_type_string():
    schema = WebhookTestRequestSchema(event_type="guard.allow")
    assert schema.event_type == "guard.allow"


def test_test_request_schema_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="Unsupported event type"):
        WebhookTestRequestSchema(event_type="not.a.type")


def test_test_request_schema_rejects_extra_fields():
    with pytest.raises(ValidationError):
        WebhookTestRequestSchema(subscription_id="should_not_be_here")


def test_test_request_schema_rejects_wildcard_event_type():
    with pytest.raises(ValidationError, match=r"\*"):
        WebhookTestRequestSchema(event_type="*")


# ---------------------------------------------------------------------------
# WebhookTestResponseSchema
# ---------------------------------------------------------------------------


def test_test_response_schema_valid():
    schema = WebhookTestResponseSchema(
        subscription_id="sub-001",
        event_type="webhook.test",
        delivery_status=WebhookDeliveryStatus.SUCCESS,
        tested_at=_NOW,
    )
    assert schema.subscription_id == "sub-001"
    assert schema.delivery_status == WebhookDeliveryStatus.SUCCESS


def test_test_response_schema_optional_fields_default_none():
    schema = WebhookTestResponseSchema(
        subscription_id="sub-001",
        event_type="webhook.test",
        delivery_status="failed",
        tested_at=_NOW,
    )
    assert schema.http_status is None
    assert schema.duration_ms is None
    assert schema.error_message is None


def test_test_response_schema_tolerates_extra_db_columns():
    schema = WebhookTestResponseSchema(
        subscription_id="sub-001",
        event_type="webhook.test",
        delivery_status="success",
        tested_at=_NOW,
        extra_internal_col="ignored",
    )
    assert schema.subscription_id == "sub-001"


def test_test_response_schema_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="Unsupported event type"):
        WebhookTestResponseSchema(
            subscription_id="sub-001",
            event_type="not.a.type",
            delivery_status="success",
            tested_at=_NOW,
        )


def test_test_response_schema_rejects_wildcard_event_type():
    with pytest.raises(ValidationError, match=r"\*"):
        WebhookTestResponseSchema(
            subscription_id="sub-001",
            event_type="*",
            delivery_status="success",
            tested_at=_NOW,
        )


# ---------------------------------------------------------------------------
# WebhookRetryResponseSchema
# ---------------------------------------------------------------------------


def test_retry_response_schema_valid():
    schema = WebhookRetryResponseSchema(
        delivery_id="dlv-001",
        subscription_id="sub-001",
        event_type="guard.block",
        previous_status=WebhookDeliveryStatus.FAILED,
        queued_at=_NOW,
    )
    assert schema.delivery_id == "dlv-001"
    assert schema.previous_status == WebhookDeliveryStatus.FAILED


def test_retry_response_schema_all_delivery_statuses_accepted():
    for status in WebhookDeliveryStatus:
        schema = WebhookRetryResponseSchema(
            delivery_id="dlv-001",
            subscription_id="sub-001",
            event_type="guard.allow",
            previous_status=status,
            queued_at=_NOW,
        )
        assert schema.previous_status == status


def test_retry_response_schema_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="Unsupported event type"):
        WebhookRetryResponseSchema(
            delivery_id="dlv-001",
            subscription_id="sub-001",
            event_type="not.a.real.event",
            previous_status=WebhookDeliveryStatus.FAILED,
            queued_at=_NOW,
        )


# ---------------------------------------------------------------------------
# WebhookEventPayloadSchema — accepts extra fields
# ---------------------------------------------------------------------------


def test_event_payload_schema_valid():
    schema = WebhookEventPayloadSchema(**_valid_event_payload())
    assert schema.ironclaw_delivery_id == "del-abc123"
    assert schema.event_type == "guard.block"


def test_event_payload_schema_accepts_extra_fields():
    schema = WebhookEventPayloadSchema(**_valid_event_payload(custom_field="custom_value", another="x"))
    assert schema.ironclaw_delivery_id == "del-abc123"


def test_event_payload_schema_default_schema_version():
    schema = WebhookEventPayloadSchema(**_valid_event_payload())
    assert schema.schema_version == "1.0"


def test_event_payload_schema_explicit_schema_version():
    schema = WebhookEventPayloadSchema(**_valid_event_payload(schema_version="2.0"))
    assert schema.schema_version == "2.0"


def test_event_payload_schema_data_defaults_empty_dict():
    schema = WebhookEventPayloadSchema(**_valid_event_payload())
    assert schema.data == {}


def test_event_payload_schema_data_populated():
    schema = WebhookEventPayloadSchema(**_valid_event_payload(data={"verdict": "block", "risk_score": 99}))
    assert schema.data["verdict"] == "block"
    assert schema.data["risk_score"] == 99


def test_event_payload_schema_tenant_id_defaults_none():
    schema = WebhookEventPayloadSchema(**_valid_event_payload())
    assert schema.tenant_id is None


def test_event_payload_schema_tenant_id_populated():
    schema = WebhookEventPayloadSchema(**_valid_event_payload(tenant_id="tenant-abc"))
    assert schema.tenant_id == "tenant-abc"


def test_event_payload_schema_missing_delivery_id_rejected():
    payload = _valid_event_payload()
    del payload["ironclaw_delivery_id"]
    with pytest.raises(ValidationError):
        WebhookEventPayloadSchema(**payload)


def test_event_payload_schema_missing_sent_at_rejected():
    payload = _valid_event_payload()
    del payload["sent_at"]
    with pytest.raises(ValidationError):
        WebhookEventPayloadSchema(**payload)


def test_event_payload_schema_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="Unsupported event type"):
        WebhookEventPayloadSchema(**_valid_event_payload(event_type="not.a.real.event"))


# ---------------------------------------------------------------------------
# WebhookEventType enum — coverage of critical event values
# ---------------------------------------------------------------------------


def test_webhook_event_type_guard_events_exist():
    assert WebhookEventType.GUARD_ALLOW == "guard.allow"
    assert WebhookEventType.GUARD_WARN == "guard.warn"
    assert WebhookEventType.GUARD_QUARANTINE == "guard.quarantine"
    assert WebhookEventType.GUARD_BLOCK == "guard.block"


def test_webhook_event_type_wildcard_value():
    assert WebhookEventType.ALL == "*"


def test_webhook_event_type_webhook_test_value():
    assert WebhookEventType.WEBHOOK_TEST == "webhook.test"


def test_webhook_event_type_threat_events_exist():
    assert WebhookEventType.THREAT_DETECTED == "threat.detected"
    assert WebhookEventType.THREAT_BLOCKED == "threat.blocked"


def test_webhook_event_type_review_events_exist():
    assert WebhookEventType.REVIEW_SUBMITTED == "review.submitted"
    assert WebhookEventType.REVIEW_APPROVED == "review.approved"
    assert WebhookEventType.REVIEW_REJECTED == "review.rejected"


# ---------------------------------------------------------------------------
# WebhookDeliveryStatus enum — all states present
# ---------------------------------------------------------------------------


def test_delivery_status_all_values_present():
    values = {status.value for status in WebhookDeliveryStatus}
    assert "pending" in values
    assert "success" in values
    assert "failed" in values
    assert "retrying" in values
    assert "exhausted" in values
