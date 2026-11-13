from __future__ import annotations

from collections.abc import Iterator
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import app.api.stripe_webhooks as stripe_webhooks
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.persistencebootstrap import InMemoryPersistenceStore
from app.services import stripe_service as stripe_service_mod

_APP = FastAPI()
_APP.include_router(stripe_webhooks.router)


def _make_service() -> MagicMock:
    service = MagicMock()
    service._get_webhook_secret.return_value = "whsec_test"
    service.resolve_org_from_customer.return_value = "org_123"
    service._issue_paid_install_keys_for_checkout.return_value = {
        program: {
            "key_id": f"ik_{program}_001",
            "owner_key": "ic_org_org_123",
            "program": program,
            "masked_key": f"ic_install_{program}_...abcd",
        }
        for program in InstallKeyFormatRegistry.list_programs()
    }
    return service


def _event_payload(
    *,
    event_type: str,
    event_id: str = "evt_123",
    payment_status: str = "paid",
    org_id: str = "org_123",
    customer_id: str = "cus_123",
    session_id: str = "cs_123",
    metadata: dict[str, object] | None = None,
    **overrides: object,
) -> dict[str, object]:
    base: dict[str, object] = {
        "id": event_id,
        "type": event_type,
        "data": {
            "object": {
                "id": session_id,
                "metadata": {
                    "org_id": org_id,
                    "unit_credits": "50",
                    **(metadata or {}),
                },
                "payment_status": payment_status,
                "mode": "payment",
                "customer": customer_id,
                "amount_total": 2500,
                "currency": "usd",
            }
        },
    }
    base["data"]["object"].update(overrides)
    return base


def _post_event(event_data: dict[str, object], *, signature: str = "t=1,v1=test") -> object:
    client = TestClient(_APP, raise_server_exceptions=False)
    headers = {"stripe-signature": signature, "content-type": "application/json"}
    return client.post("/stripe/webhook", content=json.dumps(event_data).encode("utf-8"), headers=headers)


@pytest.fixture(autouse=True)
def durable_store() -> Iterator[InMemoryPersistenceStore]:
    store = InMemoryPersistenceStore()
    with patch("app.api.stripe_webhooks._durable_store", return_value=store):
        yield store


def test_checkout_completed_paid_event_credits_units_and_issues_install_keys() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    usage_service = MagicMock()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"), patch("app.api.stripe_webhooks.get_usage_metering_service", return_value=usage_service):
        response = _post_event(_event_payload(event_type="checkout.session.completed"))

    assert response.status_code == 200
    payload = response.json()
    assert payload["processed"] is True
    assert payload["event_type"] == "checkout.session.completed"
    service.credit_units.assert_called_once_with(
        org_id="org_123",
        amount=50,
        reason=stripe_service_mod.StripeUnitEventReason.CHECKOUT_COMPLETE,
        reference_id="cs_123",
        package_id=None,
    )
    service._issue_paid_install_keys_for_checkout.assert_called_once()
    usage_service.record_action_event.assert_called()


def test_checkout_session_completed_pending_payment_is_skipped() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = _post_event(
            _event_payload(
                event_type="checkout.session.completed",
                payment_status="pending",
            )
        )

    assert response.status_code == 200
    assert response.json()["processed"] is False
    service._issue_paid_install_keys_for_checkout.assert_not_called()
    service.credit_units.assert_not_called()


def test_checkout_session_completed_skips_when_purchase_already_fulfilled() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    fulfilled_purchase = SimpleNamespace(
        purchase_id="purch_fulfilled_123",
        metadata={
            "payment_status": "paid",
            "fulfillment_status": "fulfilled",
            "checkout_session_id": "cs_123",
        },
    )

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"), patch("app.api.stripe_webhooks._find_matching_purchase_for_checkout", return_value=fulfilled_purchase):
        response = _post_event(_event_payload(event_type="checkout.session.completed"))

    assert response.status_code == 200
    assert response.json()["processed"] is True
    service.credit_units.assert_not_called()
    service._issue_paid_install_keys_for_checkout.assert_not_called()


def test_checkout_completed_writes_purchase_ledger_credit_and_keys(durable_store: InMemoryPersistenceStore) -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"), patch("app.api.stripe_webhooks.get_usage_metering_service", return_value=MagicMock()):
        response = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_store_1"))

    assert response.status_code == 200
    purchase = durable_store.select("billing_purchases", limit=1, filters={"checkout_session_id": "cs_123"})[0]
    assert purchase["purchase_id"] == "cs_123"
    assert purchase["owner_key"] == stripe_webhooks._owner_key_for_org("org_123")
    assert purchase["payment_status"] == "paid"
    assert purchase["granted_units"] == 50
    assert purchase["units_credited"] is True
    assert purchase["install_keys_provisioned"] is True
    assert purchase["fulfillment_status"] == "fulfilled"
    ledger = durable_store.select("event_idempotency_ledger", limit=1, filters={"event_id": "evt_store_1"})[0]
    assert ledger["source"] == "stripe"
    assert ledger["event_type"] == "checkout.session.completed"
    assert ledger["checkout_session_id"] == "cs_123"
    service.credit_units.assert_called_once()
    service._issue_paid_install_keys_for_checkout.assert_called_once()


def test_repeated_checkout_webhook_does_not_double_credit_or_duplicate_keys(durable_store: InMemoryPersistenceStore) -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"), patch("app.api.stripe_webhooks.get_usage_metering_service", return_value=MagicMock()):
        first = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_repeat_1"))
        second = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_repeat_2"))

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["processed"] is True
    service.credit_units.assert_called_once()
    service._issue_paid_install_keys_for_checkout.assert_called_once()
    assert len(durable_store.select("billing_purchases", filters={"checkout_session_id": "cs_123"})) == 1
    assert len(durable_store.select("event_idempotency_ledger", filters={"checkout_session_id": "cs_123"})) == 1


def test_checkout_keys_issue_without_active_subscription(durable_store: InMemoryPersistenceStore) -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    service.get_active_subscription_for_org.return_value = None

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"), patch("app.api.stripe_webhooks.get_usage_metering_service", return_value=MagicMock()):
        response = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_no_sub_1"))

    assert response.status_code == 200
    service._issue_paid_install_keys_for_checkout.assert_called_once()
    purchase = durable_store.select("billing_purchases", limit=1, filters={"checkout_session_id": "cs_123"})[0]
    assert purchase["fulfillment_status"] == "fulfilled"


def test_checkout_key_failure_leaves_purchase_retrying_and_unfulfilled(durable_store: InMemoryPersistenceStore) -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    service._issue_paid_install_keys_for_checkout.side_effect = RuntimeError("program issuance failed")

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_key_fail_1"))

    assert response.status_code == 200
    service.credit_units.assert_called_once()
    purchase = durable_store.select("billing_purchases", limit=1, filters={"checkout_session_id": "cs_123"})[0]
    assert purchase["units_credited"] is True
    assert purchase["install_keys_provisioned"] is False
    assert purchase["fulfillment_status"] == "retrying"


def test_checkout_partial_key_issuance_leaves_purchase_retrying(durable_store: InMemoryPersistenceStore) -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    issued = service._issue_paid_install_keys_for_checkout.return_value
    service._issue_paid_install_keys_for_checkout.return_value = {program: record for program, record in issued.items() if program != "goose"}

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_partial_keys_1"))

    assert response.status_code == 200
    purchase = durable_store.select("billing_purchases", limit=1, filters={"checkout_session_id": "cs_123"})[0]
    assert purchase["install_keys_provisioned"] is False
    assert purchase["fulfillment_status"] == "retrying"


def test_pending_checkout_writes_no_purchase_or_ledger(durable_store: InMemoryPersistenceStore) -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_pending_store", payment_status="pending"))

    assert durable_store.select("billing_purchases") == []
    assert durable_store.select("event_idempotency_ledger") == []


def test_invoice_paid_success_triggers_entitlement_orchestration() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    usage_service = MagicMock()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"), patch("app.api.stripe_webhooks.get_usage_metering_service", return_value=usage_service):
        response = _post_event(
            _event_payload(
                event_type="invoice.paid",
                session_id="inv_123",
                customer_id="cus_123",
                metadata={"unit_credits": "25", "billing_reason": "subscription_cycle"},
                amount_paid=2000,
                billing_reason="subscription_cycle",
            )
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["processed"] is True
    service._issue_paid_install_keys_for_checkout.assert_called_once()
    usage_service.record_action_event.assert_called()


def test_invoice_payment_failed_does_not_issue_install_keys() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = _post_event(
            _event_payload(
                event_type="invoice.payment_failed",
                payment_status="failed",
                session_id="inv_124",
                metadata={"unit_credits": "25"},
            )
        )

    assert response.status_code == 200
    assert response.json()["processed"] is True
    service._issue_paid_install_keys_for_checkout.assert_not_called()


def test_install_key_orchestration_rejects_owner_key_mismatch() -> None:
    service = _make_service()
    service.resolve_org_from_customer.return_value = "org_123"

    result = stripe_webhooks._issue_paid_install_key_orchestration(
        svc=service,
        event_type="checkout.session.completed",
        event_id="evt_owner_mismatch",
        session_id="cs_owner_mismatch",
        org_id="org_123",
        owner_key="user@example.com",
        customer_id="cus_123",
        payment_status="paid",
        unit_credits=50,
        metadata={"unit_credits": 50},
    )

    assert result == {}
    service._issue_paid_install_keys_for_checkout.assert_not_called()


def test_checkout_expired_marks_session_expired() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = _post_event(_event_payload(event_type="checkout.session.expired", payment_status=""))

    assert response.status_code == 200
    assert response.json()["processed"] is True
    service.expire_checkout_session.assert_called_once_with("cs_123")


def test_duplicate_event_is_suppressed() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        first = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_dup_1"))
        second = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_dup_1"))

    assert first.status_code == 200
    assert first.json()["processed"] is True
    assert second.status_code == 200
    assert second.json()["skipped"] is True
    assert second.json()["skip_reason"] == "Duplicate event — already processed."


def test_duplicate_event_state_is_cleared_between_cases() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        first = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_reset_1"))

    assert first.status_code == 200
    assert first.json()["processed"] is True

    stripe_webhooks.reset_processed_events()

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        second = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_reset_1"))

    assert second.status_code == 200
    assert second.json()["processed"] is True


def test_checkout_completed_persistence_failure_is_not_replayed_or_reissued() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    service.credit_units.side_effect = RuntimeError("durable persistence failed")

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = _post_event(_event_payload(event_type="checkout.session.completed", event_id="evt_persist_fail_1"))

    assert response.status_code == 200
    body = response.json()
    assert body["processed"] is False
    assert body["skipped"] is True
    assert "Handler raised an internal error" in body["skip_reason"]
    service.credit_units.assert_called_once()
    service._issue_paid_install_keys_for_checkout.assert_not_called()


def test_charge_refunded_event_routes_to_refund_revocation_and_acks() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    service.handle_webhook_event.return_value = {"action": "processed"}
    event = {
        "id": "evt_refund_001",
        "type": "charge.refunded",
        "data": {
            "object": {
                "id": "ch_123",
                "object": "charge",
                "payment_intent": "pi_123",
                "customer": "cus_123",
                "amount": 2500,
                "amount_refunded": 2500,
                "refunded": True,
                "metadata": {"org_id": "org_123"},
            }
        },
    }

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = _post_event(event)

    assert response.status_code == 200
    payload = response.json()
    assert payload["processed"] is True
    assert payload["event_type"] == "charge.refunded"
    service.handle_webhook_event.assert_called_once_with(event)


def test_invalid_json_returns_400() -> None:
    stripe_webhooks.reset_processed_events()
    service = _make_service()
    client = TestClient(_APP, raise_server_exceptions=False)

    with patch("app.api.stripe_webhooks.get_stripe_service", return_value=service), patch("app.api.stripe_webhooks._verify_stripe_signature"):
        response = client.post(
            "/stripe/webhook",
            content=b"{not json}",
            headers={"stripe-signature": "t=1,v1=test", "content-type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Stripe webhook body is not valid JSON."
