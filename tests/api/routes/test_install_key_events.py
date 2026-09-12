from __future__ import annotations

from collections.abc import Generator

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

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
        test_client.headers.update({"X-API-Key": "test-api-key"})
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


def test_usage_units_debited_updates_wallet_and_install_key_usage(client: TestClient) -> None:
    owner_key = "owner_evt_001"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 100, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key)

    response = client.post(
        "/install-key-events/ingest",
        json={
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

    updated_record = get_install_key_registry().get_key_by_id(record.key_id)
    assert updated_record is not None
    assert updated_record.units_consumed == 7

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

    response = client.post(
        "/install-key-events/ingest",
        json={
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

    response = client.post(
        "/install-key-events/ingest",
        json={
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
    assert "does not belong" in response.json()["detail"]


def test_canonical_usage_and_reporting_events_bind_to_install_key_owner(client: TestClient) -> None:
    owner_key = "owner_evt_canonical_001"
    wallet_registry = get_unit_wallet_registry()
    wallet_registry.credit_units(owner_key, 100, metadata={"seeded": True})
    record = _make_paid_key(owner_key=owner_key)

    usage_response = client.post(
        "/install-key-events/ingest",
        json={
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
    updated_record = get_install_key_registry().get_key_by_id(record.key_id)
    assert updated_record is not None
    assert updated_record.units_consumed == 4

    report_response = client.post(
        "/install-key-events/ingest",
        json={
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

    generic_response = client.post(
        "/install-key-events/ingest",
        json={
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
    assert "generic platform auth credential" in generic_response.json()["detail"]


def test_missing_key_id_for_blocked_event_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/install-key-events/ingest",
        json={
            "event_id": "evt_missing_key_001",
            "event_type": "prompt_injection_detected",
            "owner_key": "owner_evt_004",
            "program": "openclaw",
            "metadata": {"source": "guard"},
        },
    )

    assert response.status_code == 422, response.text
    assert "requires key_id" in response.json()["detail"]


def test_generation_event_is_rejected_for_telemetry_only_route(client: TestClient) -> None:
    response = client.post(
        "/install-key-events/ingest",
        json={
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

    first = client.post("/install-key-events/ingest", json=payload)
    second = client.post("/install-key-events/ingest", json=payload)

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

    response = client.post(
        "/install-key-events/ingest",
        json={
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

    response = client.post(
        "/install-key-events/ingest",
        json={
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
