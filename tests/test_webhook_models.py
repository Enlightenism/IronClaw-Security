from __future__ import annotations

from datetime import datetime

from pydantic import SecretStr, ValidationError
import pytest

from app.models.webhook import (
    WEBHOOK_ERROR_MESSAGE_MAX_LENGTH,
    WEBHOOK_EVENT_MAX_ITEMS,
    WEBHOOK_RESPONSE_SNIPPET_MAX_LENGTH,
    WEBHOOK_SCHEMA_VERSION,
    WEBHOOK_SECRET_MAX_LENGTH,
    WEBHOOK_SECRET_MIN_LENGTH,
    WebhookCreateRequest,
    WebhookCreateResponse,
    WebhookDeliveryAttempt,
    WebhookDeliveryLogEntry,
    WebhookDeliveryResponse,
    WebhookDeliveryStatus,
    WebhookEventPayload,
    WebhookEventType,
    WebhookFilterRequest,
    WebhookListResponse,
    WebhookResponse,
    WebhookRotateSecretRequest,
    WebhookRotateSecretResponse,
    WebhookSigningAlgorithm,
    WebhookStatus,
    WebhookStatusUpdateRequest,
    WebhookStatusUpdateResponse,
    WebhookSubscriptionCreate,
    WebhookSubscriptionResponse,
    WebhookSubscriptionUpdateRequest,
    WebhookSummaryResponse,
    WebhookTestRequest,
    WebhookTestResponse,
    WebhookUpdateRequest,
    _WebhookSecretWrite,
)

VALID_SECRET = "a" * WEBHOOK_SECRET_MIN_LENGTH
LONG_VALID_SECRET = "super-secret-value-1234567890"
VALID_URL = "https://hooks.example.com/ironclaw"
VALID_ORG_ID = "org-123"
VALID_WEBHOOK_ID = "wh-123"
VALID_ATTEMPT_ID = "att-123"
VALID_DELIVERY_ID = "dlv-123"
VALID_SUBSCRIPTION_ID = "sub-123"
VALID_TENANT_ID = "tenant-123"


def assert_is_iso8601_z(value: str) -> None:
    assert value.endswith("Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None


def canonical_public_events() -> list[WebhookEventType]:
    return [event for event in WebhookEventType if event is not WebhookEventType.ALL]


class TestWebhookCreateRequest:
    def test_accepts_valid_payload(self) -> None:
        model = WebhookCreateRequest(
            name="Security Alerts",
            target_url=VALID_URL,
            secret=LONG_VALID_SECRET,
            event_types=[
                WebhookEventType.GUARD_BLOCK,
                WebhookEventType.GUARD_WARN,
            ],
            org_id=VALID_ORG_ID,
            signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA512,
            active=False,
            max_retries=5,
            timeout_seconds=20,
            metadata={"source": "test"},
        )

        assert model.name == "Security Alerts"
        assert str(model.target_url) == VALID_URL
        assert model.secret == LONG_VALID_SECRET
        assert model.event_types == [
            WebhookEventType.GUARD_BLOCK,
            WebhookEventType.GUARD_WARN,
        ]
        assert model.org_id == VALID_ORG_ID
        assert model.signing_algorithm == WebhookSigningAlgorithm.HMAC_SHA512
        assert model.active is False
        assert model.max_retries == 5
        assert model.timeout_seconds == 20
        assert model.metadata == {"source": "test"}

    def test_requires_https_target_url(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookCreateRequest(
                name="Bad URL",
                target_url="http://hooks.example.com/insecure",
                secret=VALID_SECRET,
                event_types=[WebhookEventType.GUARD_BLOCK],
            )

        assert "target_url must use HTTPS" in str(exc.value)

    def test_rejects_secret_shorter_than_minimum(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookCreateRequest(
                name="Short Secret",
                target_url=VALID_URL,
                secret="short",
                event_types=[WebhookEventType.GUARD_BLOCK],
            )

        assert "Secret must be at least" in str(exc.value)

    def test_rejects_secret_longer_than_maximum(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookCreateRequest(
                name="Long Secret",
                target_url=VALID_URL,
                secret="x" * (WEBHOOK_SECRET_MAX_LENGTH + 1),
                event_types=[WebhookEventType.GUARD_BLOCK],
            )

        assert "Secret must be at most" in str(exc.value)

    def test_secret_is_trimmed_before_validation(self) -> None:
        model = WebhookCreateRequest(
            name="Trim Secret",
            target_url=VALID_URL,
            secret=f"   {VALID_SECRET}   ",
            event_types=[WebhookEventType.GUARD_BLOCK],
        )

        assert model.secret == VALID_SECRET

    def test_normalizes_org_id_whitespace_to_clean_value(self) -> None:
        model = WebhookCreateRequest(
            name="Org Normalize",
            target_url=VALID_URL,
            secret=VALID_SECRET,
            event_types=[WebhookEventType.GUARD_BLOCK],
            org_id="   org-trimmed   ",
        )

        assert model.org_id == "org-trimmed"

    def test_normalizes_blank_org_id_to_none(self) -> None:
        model = WebhookCreateRequest(
            name="Blank Org",
            target_url=VALID_URL,
            secret=VALID_SECRET,
            event_types=[WebhookEventType.GUARD_BLOCK],
            org_id="   ",
        )

        assert model.org_id is None

    def test_deduplicates_duplicate_event_types_preserving_order(self) -> None:
        model = WebhookCreateRequest(
            name="Dedup Events",
            target_url=VALID_URL,
            secret=VALID_SECRET,
            event_types=[
                "guard.block",
                WebhookEventType.GUARD_BLOCK,
                "guard.warn",
                "guard.block",
            ],
        )

        assert model.event_types == [
            WebhookEventType.GUARD_BLOCK,
            WebhookEventType.GUARD_WARN,
        ]

    def test_rejects_wildcard_event_in_public_create(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookCreateRequest(
                name="Wildcard",
                target_url=VALID_URL,
                secret=VALID_SECRET,
                event_types=[WebhookEventType.ALL],
            )

        assert "wildcard is not accepted" in str(exc.value)

    def test_rejects_unknown_event_type(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookCreateRequest(
                name="Unknown Event",
                target_url=VALID_URL,
                secret=VALID_SECRET,
                event_types=["not.a.real.event"],
            )

        assert "Unsupported event type" in str(exc.value)

    def test_rejects_empty_event_type_list(self) -> None:
        with pytest.raises(ValidationError):
            WebhookCreateRequest(
                name="No Events",
                target_url=VALID_URL,
                secret=VALID_SECRET,
                event_types=[],
            )

    def test_rejects_non_iterable_event_types(self) -> None:
        with pytest.raises(ValidationError):
            WebhookCreateRequest(
                name="Bad Events",
                target_url=VALID_URL,
                secret=VALID_SECRET,
                event_types="guard.block",
            )

    def test_rejects_more_than_max_unique_event_types(self) -> None:
        assert len(canonical_public_events()) <= WEBHOOK_EVENT_MAX_ITEMS

    def test_defaults_are_applied(self) -> None:
        model = WebhookCreateRequest(
            name="Defaults",
            target_url=VALID_URL,
            secret=VALID_SECRET,
            event_types=[WebhookEventType.GUARD_BLOCK],
        )

        assert model.signing_algorithm == WebhookSigningAlgorithm.HMAC_SHA256
        assert model.active is True
        assert model.max_retries == 3
        assert model.timeout_seconds == 10
        assert model.metadata == {}


class TestWebhookUpdateRequest:
    def test_accepts_partial_update(self) -> None:
        model = WebhookUpdateRequest(
            name="Updated Name",
            target_url=VALID_URL,
            secret=LONG_VALID_SECRET,
            event_types=["guard.warn", "guard.warn", "guard.block"],
            org_id="  org-456  ",
            signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA512,
            active=True,
            max_retries=4,
            timeout_seconds=30,
            metadata={"updated": True},
        )

        assert model.name == "Updated Name"
        assert str(model.target_url) == VALID_URL
        assert model.secret == LONG_VALID_SECRET
        assert model.event_types == [
            WebhookEventType.GUARD_WARN,
            WebhookEventType.GUARD_BLOCK,
        ]
        assert model.org_id == "org-456"
        assert model.signing_algorithm == WebhookSigningAlgorithm.HMAC_SHA512
        assert model.active is True
        assert model.max_retries == 4
        assert model.timeout_seconds == 30
        assert model.metadata == {"updated": True}

    def test_allows_empty_partial_update(self) -> None:
        model = WebhookUpdateRequest()
        assert model.model_dump(exclude_none=True) == {}

    def test_rejects_insecure_target_url(self) -> None:
        with pytest.raises(ValidationError):
            WebhookUpdateRequest(target_url="http://hooks.example.com/insecure")

    def test_rejects_short_secret_when_supplied(self) -> None:
        with pytest.raises(ValidationError):
            WebhookUpdateRequest(secret="tiny")

    def test_rejects_wildcard_in_event_types(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookUpdateRequest(event_types=[WebhookEventType.ALL])

        assert "wildcard is not accepted" in str(exc.value)

    def test_blank_org_id_becomes_none(self) -> None:
        model = WebhookUpdateRequest(org_id="   ")
        assert model.org_id is None


class TestWebhookFilterRequest:
    def test_accepts_valid_filter(self) -> None:
        model = WebhookFilterRequest(
            org_id="  org-789  ",
            status=WebhookStatus.ACTIVE,
            event_type="guard.allow",
            active=True,
        )

        assert model.org_id == "org-789"
        assert model.status == WebhookStatus.ACTIVE
        assert model.event_type == WebhookEventType.GUARD_ALLOW
        assert model.active is True

    def test_rejects_wildcard_filter_event(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookFilterRequest(event_type=WebhookEventType.ALL)

        assert "wildcard is not valid as a filter event type" in str(exc.value)

    def test_blank_org_id_becomes_none(self) -> None:
        model = WebhookFilterRequest(org_id="   ")
        assert model.org_id is None


class TestWebhookTestRequest:
    def test_defaults_event_type(self) -> None:
        model = WebhookTestRequest(webhook_id=VALID_WEBHOOK_ID)
        assert model.event_type == WebhookEventType.GUARD_ALLOW

    def test_rejects_wildcard(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookTestRequest(webhook_id=VALID_WEBHOOK_ID, event_type=WebhookEventType.ALL)

        assert "wildcard cannot be used for a test delivery" in str(exc.value)


class TestWebhookRotateSecretRequest:
    def test_accepts_valid_secret(self) -> None:
        model = WebhookRotateSecretRequest(new_secret=LONG_VALID_SECRET)
        assert model.new_secret == LONG_VALID_SECRET

    def test_rejects_short_secret(self) -> None:
        with pytest.raises(ValidationError):
            WebhookRotateSecretRequest(new_secret="short")


class TestWebhookStatusUpdateRequest:
    def test_accepts_boolean_active(self) -> None:
        model = WebhookStatusUpdateRequest(active=True)
        assert model.active is True


class TestWebhookResponse:
    def build_model(self, **overrides) -> WebhookResponse:
        payload = {
            "webhook_id": VALID_WEBHOOK_ID,
            "name": "Webhook A",
            "target_url": VALID_URL,
            "event_types": [WebhookEventType.GUARD_BLOCK, "guard.warn"],
            "org_id": VALID_ORG_ID,
            "signing_algorithm": WebhookSigningAlgorithm.HMAC_SHA256.value,
            "status": WebhookStatus.ACTIVE,
            "active": True,
            "max_retries": 3,
            "timeout_seconds": 10,
            "failure_count": 1,
            "last_triggered_at": "2026-01-01T00:00:00Z",
            "metadata": {"env": "test"},
        }
        payload.update(overrides)
        return WebhookResponse(**payload)

    def test_serializes_event_types_to_strings(self) -> None:
        model = self.build_model()
        assert model.event_types == ["guard.block", "guard.warn"]

    def test_public_read_model_dump_has_no_secret_fields(self) -> None:
        model = self.build_model()
        dumped = model.model_dump()

        assert "secret" not in dumped
        assert "secret_hash" not in dumped
        assert "signing_secret" not in dumped
        assert dumped["event_types"] == ["guard.block", "guard.warn"]

    def test_allows_internal_wildcard_for_read_models(self) -> None:
        model = self.build_model(event_types=[WebhookEventType.ALL])
        assert model.event_types == ["*"]

    def test_sets_default_timestamps(self) -> None:
        model = WebhookResponse(
            webhook_id=VALID_WEBHOOK_ID,
            name="Webhook A",
            target_url=VALID_URL,
            event_types=[WebhookEventType.GUARD_BLOCK],
            signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA256.value,
            status=WebhookStatus.ACTIVE,
            active=True,
            max_retries=3,
            timeout_seconds=10,
        )

        assert_is_iso8601_z(model.created_at)
        assert_is_iso8601_z(model.updated_at)

    def test_rejects_unknown_event_type_in_read_model(self) -> None:
        with pytest.raises(ValidationError):
            self.build_model(event_types=["bad.event"])

    def test_rejects_extra_secret_fields(self) -> None:
        with pytest.raises(ValidationError):
            self.build_model(secret="should-not-serialize", secret_hash="should-not-serialize")


class TestWebhookCreateResponse:
    def build_model(self, **overrides) -> WebhookCreateResponse:
        payload = {
            "webhook_id": VALID_WEBHOOK_ID,
            "name": "Webhook B",
            "target_url": VALID_URL,
            "event_types": [WebhookEventType.GUARD_ALLOW],
            "org_id": VALID_ORG_ID,
            "signing_algorithm": WebhookSigningAlgorithm.HMAC_SHA256.value,
            "status": WebhookStatus.ACTIVE,
            "active": True,
            "max_retries": 3,
            "timeout_seconds": 10,
            "failure_count": 0,
            "last_triggered_at": None,
            "metadata": {"source": "create"},
            "secret_hint": "super-se",
            "signing_secret": "super-secret-created-once",
        }
        payload.update(overrides)
        return WebhookCreateResponse(**payload)

    def test_one_time_create_response_includes_signing_secret(self) -> None:
        model = self.build_model()
        dumped = model.model_dump()

        assert dumped["signing_secret"] == "super-secret-created-once"
        assert dumped["secret_hint"] == "super-se"
        assert "secret" not in dumped
        assert "secret_hash" not in dumped

    def test_accepts_event_types_as_enum_or_string(self) -> None:
        model = self.build_model(event_types=["guard.allow", WebhookEventType.GUARD_BLOCK])
        assert model.event_types == ["guard.allow", "guard.block"]

    def test_backfills_secret_hint_when_missing(self) -> None:
        model = self.build_model(secret_hint="", signing_secret="abcdefgh12345678")
        assert model.secret_hint == "abcdefgh"

    def test_sets_default_timestamps(self) -> None:
        model = WebhookCreateResponse(
            webhook_id=VALID_WEBHOOK_ID,
            name="Webhook B",
            target_url=VALID_URL,
            event_types=[WebhookEventType.GUARD_ALLOW],
            signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA256.value,
            status=WebhookStatus.ACTIVE,
            active=True,
            max_retries=3,
            timeout_seconds=10,
            secret_hint="abcdefgh",
            signing_secret="abcdefgh12345678",
        )

        assert_is_iso8601_z(model.created_at)
        assert_is_iso8601_z(model.updated_at)

    def test_rejects_extra_secret_fields(self) -> None:
        with pytest.raises(ValidationError):
            self.build_model(secret="never-show", secret_hash="never-show")


class TestWebhookRotateSecretResponse:
    def test_never_exposes_secret_fields(self) -> None:
        model = WebhookRotateSecretResponse(
            webhook_id=VALID_WEBHOOK_ID,
            signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA512.value,
        )
        dumped = model.model_dump()

        assert dumped["webhook_id"] == VALID_WEBHOOK_ID
        assert dumped["signing_algorithm"] == WebhookSigningAlgorithm.HMAC_SHA512.value
        assert "signing_secret" not in dumped
        assert "secret" not in dumped
        assert "secret_hash" not in dumped
        assert_is_iso8601_z(dumped["rotated_at"])


class TestWebhookStatusUpdateResponse:
    def test_sets_updated_at(self) -> None:
        model = WebhookStatusUpdateResponse(
            webhook_id=VALID_WEBHOOK_ID,
            active=False,
            status=WebhookStatus.DISABLED,
        )

        assert model.webhook_id == VALID_WEBHOOK_ID
        assert model.active is False
        assert model.status == WebhookStatus.DISABLED
        assert_is_iso8601_z(model.updated_at)


class TestWebhookSummaryAndListResponses:
    def test_summary_response_defaults_created_at(self) -> None:
        model = WebhookSummaryResponse(
            webhook_id=VALID_WEBHOOK_ID,
            name="Webhook C",
            target_url=VALID_URL,
            status=WebhookStatus.ACTIVE,
            active=True,
            event_type_count=2,
        )

        assert model.failure_count == 0
        assert_is_iso8601_z(model.created_at)

    def test_list_response_wraps_items(self) -> None:
        summary = WebhookSummaryResponse(
            webhook_id=VALID_WEBHOOK_ID,
            name="Webhook C",
            target_url=VALID_URL,
            status=WebhookStatus.ACTIVE,
            active=True,
            event_type_count=2,
        )
        model = WebhookListResponse(total=1, items=[summary])

        assert model.total == 1
        assert len(model.items) == 1
        assert model.items[0].webhook_id == VALID_WEBHOOK_ID


class TestWebhookDeliveryAttempt:
    def test_accepts_valid_attempt(self) -> None:
        model = WebhookDeliveryAttempt(
            attempt_id=VALID_ATTEMPT_ID,
            webhook_id=VALID_WEBHOOK_ID,
            event_type=WebhookEventType.GUARD_BLOCK,
            payload_hash="abc123",
            status=WebhookDeliveryStatus.SUCCESS,
            http_status_code=200,
            response_body_snippet="ok",
            attempt_number=1,
            duration_ms=25,
            error_message=None,
        )

        assert model.event_type == "guard.block"
        assert model.status == WebhookDeliveryStatus.SUCCESS
        assert model.http_status_code == 200
        assert model.duration_ms == 25
        assert_is_iso8601_z(model.attempted_at)

    def test_rejects_unknown_event_type(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDeliveryAttempt(
                attempt_id=VALID_ATTEMPT_ID,
                webhook_id=VALID_WEBHOOK_ID,
                event_type="bad.event",
                payload_hash="abc123",
                status=WebhookDeliveryStatus.FAILED,
                attempt_number=1,
            )

    def test_rejects_attempt_number_less_than_one(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDeliveryAttempt(
                attempt_id=VALID_ATTEMPT_ID,
                webhook_id=VALID_WEBHOOK_ID,
                event_type=WebhookEventType.GUARD_BLOCK,
                payload_hash="abc123",
                status=WebhookDeliveryStatus.FAILED,
                attempt_number=0,
            )

    def test_rejects_negative_duration(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDeliveryAttempt(
                attempt_id=VALID_ATTEMPT_ID,
                webhook_id=VALID_WEBHOOK_ID,
                event_type=WebhookEventType.GUARD_BLOCK,
                payload_hash="abc123",
                status=WebhookDeliveryStatus.FAILED,
                attempt_number=1,
                duration_ms=-1,
            )

    def test_rejects_too_long_response_body_snippet(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDeliveryAttempt(
                attempt_id=VALID_ATTEMPT_ID,
                webhook_id=VALID_WEBHOOK_ID,
                event_type=WebhookEventType.GUARD_BLOCK,
                payload_hash="abc123",
                status=WebhookDeliveryStatus.FAILED,
                attempt_number=1,
                response_body_snippet="x" * (WEBHOOK_RESPONSE_SNIPPET_MAX_LENGTH + 1),
            )

    def test_rejects_too_long_error_message(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDeliveryAttempt(
                attempt_id=VALID_ATTEMPT_ID,
                webhook_id=VALID_WEBHOOK_ID,
                event_type=WebhookEventType.GUARD_BLOCK,
                payload_hash="abc123",
                status=WebhookDeliveryStatus.FAILED,
                attempt_number=1,
                error_message="x" * (WEBHOOK_ERROR_MESSAGE_MAX_LENGTH + 1),
            )


class TestWebhookDeliveryResponse:
    def test_wraps_attempts(self) -> None:
        attempt = WebhookDeliveryAttempt(
            attempt_id=VALID_ATTEMPT_ID,
            webhook_id=VALID_WEBHOOK_ID,
            event_type=WebhookEventType.GUARD_BLOCK,
            payload_hash="abc123",
            status=WebhookDeliveryStatus.SUCCESS,
            attempt_number=1,
        )
        model = WebhookDeliveryResponse(
            webhook_id=VALID_WEBHOOK_ID,
            total=1,
            attempts=[attempt],
        )

        assert model.webhook_id == VALID_WEBHOOK_ID
        assert model.total == 1
        assert model.attempts[0].attempt_id == VALID_ATTEMPT_ID


class TestWebhookTestResponse:
    def test_accepts_valid_response(self) -> None:
        model = WebhookTestResponse(
            webhook_id=VALID_WEBHOOK_ID,
            event_type=WebhookEventType.GUARD_WARN,
            delivery_status=WebhookDeliveryStatus.SUCCESS,
            http_status_code=200,
            duration_ms=12,
            error_message=None,
        )

        assert model.event_type == "guard.warn"
        assert model.delivery_status == WebhookDeliveryStatus.SUCCESS
        assert_is_iso8601_z(model.tested_at)

    def test_rejects_wildcard_event(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookTestResponse(
                webhook_id=VALID_WEBHOOK_ID,
                event_type=WebhookEventType.ALL,
                delivery_status=WebhookDeliveryStatus.FAILED,
            )

        assert "wildcard cannot be used for a test response event type" in str(exc.value)


class TestWebhookEventPayload:
    def test_accepts_valid_payload(self) -> None:
        model = WebhookEventPayload(
            ironclaw_delivery_id=VALID_DELIVERY_ID,
            webhook_id=VALID_WEBHOOK_ID,
            event_type=WebhookEventType.GUARD_BLOCK,
            org_id="  org-payload  ",
            data={"score": 90},
            extra_context="allowed-extra-field",
        )

        assert model.ironclaw_delivery_id == VALID_DELIVERY_ID
        assert model.webhook_id == VALID_WEBHOOK_ID
        assert model.event_type == "guard.block"
        assert model.org_id == "org-payload"
        assert model.schema_version == WEBHOOK_SCHEMA_VERSION
        assert model.data == {"score": 90}
        assert model.extra_context == "allowed-extra-field"
        assert_is_iso8601_z(model.sent_at)

    def test_rejects_unknown_event_type(self) -> None:
        with pytest.raises(ValidationError):
            WebhookEventPayload(
                ironclaw_delivery_id=VALID_DELIVERY_ID,
                webhook_id=VALID_WEBHOOK_ID,
                event_type="nope.event",
            )

    def test_blank_org_id_becomes_none(self) -> None:
        model = WebhookEventPayload(
            ironclaw_delivery_id=VALID_DELIVERY_ID,
            webhook_id=VALID_WEBHOOK_ID,
            event_type=WebhookEventType.GUARD_BLOCK,
            org_id="   ",
        )

        assert model.org_id is None


class TestCompatibilityModels:
    def test_subscription_create_accepts_valid_payload(self) -> None:
        model = WebhookSubscriptionCreate(
            target_url=VALID_URL,
            events=["guard.block", "guard.warn", "guard.block"],
            max_attempts=5,
            metadata={"compat": True},
        )

        assert str(model.target_url) == VALID_URL
        assert model.events == [
            WebhookEventType.GUARD_BLOCK,
            WebhookEventType.GUARD_WARN,
        ]
        assert model.max_attempts == 5
        assert model.metadata == {"compat": True}

    def test_subscription_create_rejects_wildcard(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebhookSubscriptionCreate(
                target_url=VALID_URL,
                events=[WebhookEventType.ALL],
            )

        assert "wildcard is not accepted" in str(exc.value)

    def test_subscription_update_accepts_partial_payload(self) -> None:
        model = WebhookSubscriptionUpdateRequest(
            active=False,
            events=["guard.allow", "guard.allow", "guard.warn"],
            max_attempts=3,
            metadata={"patched": True},
        )

        assert model.active is False
        assert model.events == [
            WebhookEventType.GUARD_ALLOW,
            WebhookEventType.GUARD_WARN,
        ]
        assert model.max_attempts == 3
        assert model.metadata == {"patched": True}

    def test_subscription_update_rejects_wildcard(self) -> None:
        with pytest.raises(ValidationError):
            WebhookSubscriptionUpdateRequest(events=[WebhookEventType.ALL])

    def test_subscription_response_serializes_events_and_has_no_secret_fields(self) -> None:
        model = WebhookSubscriptionResponse(
            id=VALID_SUBSCRIPTION_ID,
            tenant_id=VALID_TENANT_ID,
            target_url=VALID_URL,
            events=[WebhookEventType.GUARD_BLOCK, "guard.warn"],
            active=True,
            max_attempts=4,
            metadata={"compat": "read"},
            created_at="2026-01-01T00:00:00Z",
            secret_hint="abcd1234",
        )

        dumped = model.model_dump()
        assert dumped["events"] == ["guard.block", "guard.warn"]
        assert "secret" not in dumped
        assert "secret_hash" not in dumped
        assert "signing_secret" not in dumped

    def test_subscription_response_rejects_extra_secret_fields(self) -> None:
        with pytest.raises(ValidationError):
            WebhookSubscriptionResponse(
                id=VALID_SUBSCRIPTION_ID,
                tenant_id=VALID_TENANT_ID,
                target_url=VALID_URL,
                events=[WebhookEventType.GUARD_BLOCK],
                active=True,
                max_attempts=4,
                metadata={"compat": "read"},
                created_at="2026-01-01T00:00:00Z",
                secret_hint="abcd1234",
                secret="should-not-leak",
                secret_hash="should-not-leak",
            )

    def test_delivery_log_entry_accepts_valid_payload(self) -> None:
        model = WebhookDeliveryLogEntry(
            id=VALID_DELIVERY_ID,
            subscription_id=VALID_SUBSCRIPTION_ID,
            tenant_id=VALID_TENANT_ID,
            event_type=WebhookEventType.GUARD_BLOCK,
            status=WebhookDeliveryStatus.RETRYING,
            attempts=2,
            http_status=503,
            error_detail="temporary failure",
            delivered_at=None,
            next_attempt_at="2026-01-01T00:05:00Z",
        )

        assert model.event_type == "guard.block"
        assert model.status == WebhookDeliveryStatus.RETRYING
        assert model.attempts == 2
        assert model.http_status == 503
        assert_is_iso8601_z(model.created_at)

    def test_delivery_log_entry_rejects_unknown_event(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDeliveryLogEntry(
                id=VALID_DELIVERY_ID,
                subscription_id=VALID_SUBSCRIPTION_ID,
                tenant_id=VALID_TENANT_ID,
                event_type="bad.event",
                status=WebhookDeliveryStatus.FAILED,
            )


class TestInternalSecretWrite:
    def test_secret_is_stored_as_secretstr(self) -> None:
        model = _WebhookSecretWrite(secret=LONG_VALID_SECRET)

        assert isinstance(model.secret, SecretStr)
        assert model.secret.get_secret_value() == LONG_VALID_SECRET

    def test_repr_does_not_expose_secret_value(self) -> None:
        model = _WebhookSecretWrite(secret=LONG_VALID_SECRET)
        rendered = repr(model)

        assert LONG_VALID_SECRET not in rendered
        assert "**********" in rendered or "SecretStr" in rendered


class TestEnumsAndConstants:
    def test_enum_values_are_stable(self) -> None:
        assert WebhookEventType.GUARD_ALLOW.value == "guard.allow"
        assert WebhookEventType.ALL.value == "*"
        assert WebhookStatus.ACTIVE.value == "active"
        assert WebhookDeliveryStatus.EXHAUSTED.value == "exhausted"
        assert WebhookSigningAlgorithm.HMAC_SHA256.value == "hmac-sha256"

    def test_schema_version_constant_is_stable(self) -> None:
        assert WEBHOOK_SCHEMA_VERSION == "1.0"
