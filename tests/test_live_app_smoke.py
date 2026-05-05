from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _auth_headers() -> dict[str, str]:
    return {"x-api-key": "test-api-key"}


def test_live_app_health_routes_smoke() -> None:
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"

    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"


def test_live_app_core_protected_routes_smoke() -> None:
    protected_paths = [
        "/integrations",
        "/api/incidents",
        "/api/integrations",
        "/api/review-queue",
        "/ui/runtime/status",
        "/ui/integrations/settings",
    ]

    for path in protected_paths:
        response = client.get(path, headers=_auth_headers())
        assert response.status_code in {200, 401, 403}, path


def test_live_app_ui_pages_return_expected_shapes() -> None:
    runtime_response = client.get("/ui/runtime/status", headers=_auth_headers())
    assert runtime_response.status_code == 200
    runtime_payload = runtime_response.json()
    assert "generatedat" in runtime_payload
    assert "executor" in runtime_payload
    assert "metrics" in runtime_payload

    integration_response = client.get(
        "/ui/integrations/settings",
        headers=_auth_headers(),
    )
    assert integration_response.status_code == 200
    integration_payload = integration_response.json()
    assert "generatedat" in integration_payload
    assert "providers" in integration_payload
    assert isinstance(integration_payload["providers"], list)


def test_live_app_api_inventory_routes_return_expected_shapes() -> None:
    response = client.get("/api/incidents", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        payload = response.json()
        assert isinstance(payload, dict)

    response = client.get("/api/integrations", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        payload = response.json()
        assert isinstance(payload, dict)


def test_live_app_integrations_endpoints_exist() -> None:
    expected_paths = [
        "/api/integrations",
        "/integrations",
        "/integrations/summary",
        "/integrations/{integration_id}",
    ]

    registered_paths = {
        route.path
        for route in app.routes
        if hasattr(route, "path")
    }

    for path in expected_paths:
        assert path in registered_paths, path


def test_live_app_docs_endpoints_are_registered() -> None:
    registered_paths = {
        route.path
        for route in app.routes
        if hasattr(route, "path")
    }

    assert "/docs" in registered_paths
    assert "/openapi.json" in registered_paths