from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app, raise_server_exceptions=False)

_BILLING_BASE = "/api/billing"


def _billing_path(path: str) -> str:
    normalized = path if path.startswith("/") else f"/{path}"
    return f"{_BILLING_BASE}{normalized}"


def test_main_root_returns_ok() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_main_health_returns_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_main_health_liveness_returns_ok() -> None:
    response = client.get("/health/liveness")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_main_health_readiness_returns_ok() -> None:
    response = client.get("/health/readiness")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_endpoint_is_available_or_protected() -> None:
    response = client.get("/openapi.json")
    assert response.status_code in {200, 401, 403, 404, 405}


def test_docs_endpoint_is_available_or_protected() -> None:
    response = client.get("/docs")
    assert response.status_code in {200, 401, 403, 404}


# ---------------------------------------------------------------------------
# Stripe billing router registration smoke tests
# Confirms app.routers.stripe_router is wired into main — routes must exist
# (200/401/403/422) and must NOT return 404 (route missing).
# ---------------------------------------------------------------------------


def test_billing_catalogue_route_is_registered() -> None:
    """GET /api/billing/catalogue — confirms route is registered; auth may be applied at router level."""
    response = client.get(_billing_path("/catalogue"))
    assert response.status_code in {200, 401, 403}


def test_billing_unit_balance_route_is_registered() -> None:
    """GET /api/billing/units/balance is auth-protected — 401/403 confirms route exists."""
    response = client.get(_billing_path("/units/balance"))
    assert response.status_code in {200, 401, 403}


def test_billing_unit_ledger_route_is_registered() -> None:
    """GET /api/billing/units/ledger is auth-protected — 401/403 confirms route exists."""
    response = client.get(_billing_path("/units/ledger"))
    assert response.status_code in {200, 401, 403}


def test_billing_metered_log_route_is_registered() -> None:
    """GET /api/billing/metered/log is auth-protected — 401/403 confirms route exists."""
    response = client.get(_billing_path("/metered/log"))
    assert response.status_code in {200, 401, 403}


def test_billing_payment_methods_route_is_registered() -> None:
    """GET /api/billing/payment-methods is auth-protected — 401/403 confirms route exists."""
    response = client.get(_billing_path("/payment-methods"))
    assert response.status_code in {200, 401, 403}


def test_billing_invoices_route_is_registered() -> None:
    """GET /api/billing/invoices is auth-protected — 401/403 confirms route exists."""
    response = client.get(_billing_path("/invoices"))
    assert response.status_code in {200, 401, 403}
