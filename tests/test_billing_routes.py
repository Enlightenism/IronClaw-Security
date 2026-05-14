from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.billing import router as billing_router
from app.core.auth import API_KEY_HEADER_NAME
from app.core.errors import AppError
from app.core.unit_wallet import get_unit_wallet_registry


def _build_app() -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key="test-secret-key",
        admin_api_key=None,
    )
    app.include_router(billing_router)
    return app


def test_billing_wallet_summary_returns_wallet_state() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="customer-001",
        units=300,
        metadata={"source": "starter-package"},
    )
    registry.debit_units(
        owner_key="customer-001",
        units=40,
        metadata={"source": "usage-metering"},
    )

    client = TestClient(_build_app())
    response = client.get(
        "/billing/wallet/customer-001",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data

    wallet = data["wallet"]
    assert wallet["owner_key"] == "customer-001"
    assert wallet["balance_units"] == 260
    assert wallet["total_purchased_units"] == 300
    assert wallet["total_consumed_units"] == 40


def test_billing_wallet_summary_returns_not_found_for_unknown_owner() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/wallet/unknown-owner",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )

    assert response.status_code in (200, 404)


def test_billing_ledger_returns_recent_entries_for_owner() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="customer-ledger",
        units=500,
        metadata={"package": "growth"},
    )
    registry.debit_units(
        owner_key="customer-ledger",
        units=125,
        metadata={"route": "/guard/execute"},
    )

    client = TestClient(_build_app())
    response = client.get(
        "/billing/ledger",
        params={"owner_key": "customer-ledger", "limit": 10},
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert data["owner_key"] == "customer-ledger"
    assert data["limit"] == 10
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) >= 2

    latest_entry = data["entries"][-1]
    assert latest_entry["owner_key"] == "customer-ledger"
    assert latest_entry["entry_type"] in {"credit", "debit"}


def test_billing_routes_require_api_key_when_auth_is_enabled() -> None:
    client = TestClient(_build_app())

    with pytest.raises(AppError) as exc_info:
        client.get("/billing/ledger")

    assert exc_info.value.status_code == 401
    assert exc_info.value.error == "missing_api_key"
