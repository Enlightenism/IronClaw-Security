from __future__ import annotations

from collections.abc import Generator
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import app.api.routes.install_key_events as install_key_events_module
from app.api.routes.install_key_events import router
import app.core.install_keys as install_keys_module
from app.core.install_keys import InstallKeyRecord, InstallKeyRegistry, get_install_key_registry
import app.core.unit_wallet as unit_wallet_module
from app.core.unit_wallet import UnitWalletRegistry, get_unit_wallet_registry
from app.main import app as main_app


@pytest.fixture(autouse=True)
def reset_registries() -> Generator[None, None, None]:
    main_app.dependency_overrides.clear()
    install_keys_module._install_key_registry = InstallKeyRegistry()
    install_keys_module._install_key_registry._loaded = True
    unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()
    yield
    main_app.dependency_overrides.clear()
    install_keys_module._install_key_registry = InstallKeyRegistry()
    install_keys_module._install_key_registry._loaded = True
    unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()


@pytest.fixture()
def app() -> FastAPI:
    application = FastAPI()
    application.include_router(router)
    return application


@pytest.fixture()
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client


def _make_paid_key(
    *,
    owner_key: str = "owner_evt_001",
    program: str = "openclaw",
    subscription_id: str = "sub_evt_001",
) -> InstallKeyRecord:
    registry = get_install_key_registry()
    return registry.generate_for_paid_customer(
        owner_key=owner_key,
        subscription_id=subscription_id,
        program=program,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        purchase_reference="purchase_evt_001",
        checkout_session_id="cs_evt_001",
        label="production",
        metadata={"source": "test"},
    )


def _post_event(
    client: TestClient,
    record: InstallKeyRecord,
    payload: dict[str, object],
) -> Any:
    return client.post(
        "/install-key-events/ingest",
        json=payload,
        headers={"X-Install-Key": record.raw_key},
    )


def test_durable_idempotency_store_checks_shared_event_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {"table": None, "event_id": None}

    class _FakeStore:
        def select(self, table: str, *args: object, **kwargs: object) -> list[dict[str, object]]:
            if table == "ironclaw_event_idempotency":
                seen["table"] = table
                return [{"event_id": "evt_shared_ledger_001"}]
            if table == "event_idempotency_ledger":
                seen["table"] = table
                return []
            return []

        def insert(self, table: str, payload: dict[str, object], **kwargs: object) -> list[dict[str, object]]:
            seen["table"] = table
            seen["event_id"] = payload.get("event_id")
            return [dict(payload)]

    monkeypatch.setattr(install_key_events_module, "_EVENT_IDEMPOTENCY_STORE", install_key_events_module._DurableEventIdempotencyStore())
    monkeypatch.setattr(install_key_events_module, "get_persistence_store", lambda *args, **kwargs: _FakeStore())

    assert install_key_events_module._event_seen("evt_shared_ledger_001") is True
    assert seen["table"] == "ironclaw_event_idempotency"


def test_usage_units_debited_updates_wallet_and_install_key_usage(client: TestClient) -> None:
    owner_key = "owner_evt_001"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 100, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key)

    response = _post_event(
        client,
        record,
        {
            "event_id": "evt_usage_001",
            "event_type": "usage_units_debited",
            "key_id": record.key_id,
            "owner_key": owner_key,
            "program": "openclaw",
            "units": 7,
            "action_type": "prompt",
            "metadata": {"source": "runtime"},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event_type"] == "usage_units_debited"
    assert body["processed"] is True
    assert body["wallet_updated"] is True
    assert body["metadata"]["status"] == "applied"

    wallet = wallet_registry.get_wallet(owner_key)
    assert wallet is not None
    assert wallet.balance_units == 93
    assert wallet.total_consumed_units == 7
    assert wallet.install_key_usage[record.key_id].total_consumed_units == 7
    assert wallet.install_key_usage[record.key_id].owner_key == owner_key
    assert wallet.install_key_usage[record.key_id].metadata["owner_key"] == owner_key
    assert wallet.install_key_usage[record.key_id].metadata["action_type"] == "prompt"


def test_blocked_event_increments_blocked_attack_totals(client: TestClient) -> None:
    owner_key = "owner_evt_002"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 100, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key, program="claude_code")

    response = _post_event(
        client,
        record,
        {
            "event_id": "evt_block_001",
            "event_type": "action_blocked",
            "key_id": record.key_id,
            "owner_key": owner_key,
            "program": "claude_code",
            "blocked_attack_count": 2,
            "action_type": "tool_call",
            "metadata": {"source": "guard"},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event_type"] == "action_blocked"
    assert body["processed"] is True

    wallet = wallet_registry.get_wallet(owner_key)
    assert wallet is not None
    assert wallet.total_blocked_attacks == 2
    assert wallet.install_key_usage[record.key_id].total_blocked_attacks == 2
    assert wallet.install_key_usage[record.key_id].owner_key == owner_key
    assert wallet.install_key_usage[record.key_id].metadata["owner_key"] == owner_key
    assert wallet.install_key_usage[record.key_id].metadata["action_type"] == "tool_call"


def test_event_requires_matching_owner_key_for_usage_event(client: TestClient) -> None:
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units("owner_evt_003", 100, metadata={"seeded": True})
    record = _make_paid_key(owner_key="owner_evt_003")

    response = _post_event(
        client,
        record,
        {
            "event_id": "evt_usage_mismatch_001",
            "event_type": "usage_units_debited",
            "key_id": record.key_id,
            "owner_key": "owner_evt_other",
            "program": "openclaw",
            "units": 3,
            "metadata": {"source": "runtime"},
        },
    )

    assert response.status_code == 403, response.text
    assert "does not match the authenticated install key owner" in response.json()["detail"]


def test_canonical_usage_and_reporting_events_bind_to_install_key_owner(client: TestClient) -> None:
    owner_key = "owner_evt_canonical_001"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 100, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key)

    usage_response = _post_event(
        client,
        record,
        {
            "event_id": "evt_usage_canonical_001",
            "event_type": "install_key_usage_recorded",
            "key_id": record.key_id,
            "owner_key": owner_key,
            "program": "openclaw",
            "units": 4,
            "action_type": "prompt",
            "metadata": {"source": "runtime"},
        },
    )
    assert usage_response.status_code == 200, usage_response.text
    report_response = _post_event(
        client,
        record,
        {
            "event_id": "evt_report_canonical_001",
            "event_type": "install_key_reported",
            "key_id": record.key_id,
            "owner_key": owner_key,
            "program": "openclaw",
            "action_type": "report",
            "metadata": {"source": "dashboard"},
        },
    )
    assert report_response.status_code == 200, report_response.text
    wallet = wallet_registry.get_wallet(owner_key)
    assert wallet is not None
    assert wallet.metadata["dashboard_sync"]["install_key_reported"]["key_id"] == record.key_id
    assert wallet.install_key_usage[record.key_id].metadata["last_event_type"] == "install_key_reported"
    assert wallet.install_key_usage[record.key_id].total_consumed_units == 4

    generic_response = _post_event(
        client,
        record,
        {
            "event_id": "evt_generic_owner_rejected_001",
            "event_type": "install_key_usage_recorded",
            "key_id": record.key_id,
            "owner_key": "system-platform-api-key",
            "program": "openclaw",
            "units": 1,
            "metadata": {"source": "runtime"},
        },
    )
    assert generic_response.status_code == 403, generic_response.text
    assert "does not match the authenticated install key owner" in generic_response.json()["detail"]


def test_missing_body_key_id_uses_authenticated_install_key(client: TestClient) -> None:
    record = _make_paid_key(owner_key="owner_evt_004")
    response = _post_event(
        client,
        record,
        {
            "event_id": "evt_missing_key_001",
            "event_type": "prompt_injection_detected",
            "owner_key": "owner_evt_004",
            "program": "openclaw",
            "metadata": {"source": "guard"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["key_id"] == record.key_id


def test_generation_event_is_rejected_for_telemetry_only_route(client: TestClient) -> None:
    record = _make_paid_key(owner_key="owner_evt_004")
    response = _post_event(
        client,
        record,
        {
            "event_id": "evt_generation_rejected_001",
            "event_type": "install_key_issued",
            "owner_key": "owner_evt_004",
            "program": "openclaw",
            "metadata": {"source": "billing"},
        },
    )

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert isinstance(detail, list)
    assert any("action_blocked" in str(item) for item in detail)


def test_duplicate_event_id_is_idempotent(client: TestClient) -> None:
    owner_key = "owner_evt_005"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 200, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key)

    payload = {
        "event_id": "evt_duplicate_001",
        "event_type": "action_blocked",
        "key_id": record.key_id,
        "owner_key": owner_key,
        "program": "openclaw",
        "blocked_attack_count": 1,
        "action_type": "prompt",
        "metadata": {"source": "guard"},
    }

    first = _post_event(client, record, payload)
    second = _post_event(client, record, payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["wallet_updated"] is False
    assert second.json()["metadata"]["status"] == "duplicate"

    wallet = wallet_registry.get_wallet(owner_key)
    assert wallet is not None
    assert wallet.total_blocked_attacks == 1


def test_install_key_activation_event_syncs_dashboard_state(client: TestClient) -> None:
    owner_key = "owner_evt_006"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 75, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key)

    response = _post_event(
        client,
        record,
        {
            "event_id": "evt_activate_001",
            "event_type": "install_key_activated",
            "key_id": record.key_id,
            "owner_key": owner_key,
            "program": "openclaw",
            "action_type": "activation",
            "metadata": {"source": "runtime"},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event_type"] == "install_key_activated"
    assert body["processed"] is True
    assert body["dashboard_synced"] is True

    wallet = wallet_registry.get_wallet(owner_key)
    assert wallet is not None
    assert wallet.metadata["dashboard_sync"]["install_key_activated"]["key_id"] == record.key_id
    assert wallet.install_key_usage[record.key_id].metadata["last_event_type"] == "install_key_activated"


def test_revoked_event_deactivates_key(client: TestClient) -> None:
    owner_key = "owner_evt_007"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 75, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key)

    response = _post_event(
        client,
        record,
        {
            "event_id": "evt_revoke_001",
            "event_type": "install_key_revoked",
            "key_id": record.key_id,
            "owner_key": owner_key,
            "program": "openclaw",
            "metadata": {"source": "support"},
        },
    )

    assert response.status_code == 200, response.text
    updated_record = get_install_key_registry().get_key_by_id(record.key_id)
    assert updated_record is not None
    assert updated_record.active is False
    assert updated_record.entitlements_status == "revoked"

    wallet = wallet_registry.get_wallet(owner_key)
    assert wallet is not None
    assert wallet.metadata["dashboard_sync"]["install_key_revoked"]["key_id"] == record.key_id


def test_self_status_reports_units_from_live_wallet(client: TestClient) -> None:
    owner_key = "owner_self_001"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 100, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key, subscription_id="sub_self_001")

    usage_response = _post_event(
        client,
        record,
        {
            "event_id": "evt_self_usage_001",
            "event_type": "usage_units_debited",
            "key_id": record.key_id,
            "owner_key": owner_key,
            "program": "openclaw",
            "units": 7,
            "action_type": "prompt",
            "metadata": {"source": "runtime"},
        },
    )
    assert usage_response.status_code == 200, usage_response.text

    response = client.get("/install-key-events/self", headers={"X-Install-Key": record.raw_key})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["owner_key"] == owner_key
    assert body["has_active_entitlement"] is True
    assert len(body["keys"]) == 1
    slot = body["keys"][0]
    assert slot["key_id"] == record.key_id
    assert slot["units_used"] == 7
    assert slot["units_remaining"] == 93
    assert slot["blocked_attacks"] == 0


def test_self_status_rejects_unknown_install_key(client: TestClient) -> None:
    response = client.get("/install-key-events/self", headers={"X-Install-Key": "ic_install_not_a_real_key"})

    assert response.status_code == 401
