from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.core.apikeys import get_api_key_registry
from app.main import app


def _clear_registry() -> None:
    registry = get_api_key_registry()
    for attr_name in ("clear", "reset"):
        method = getattr(registry, attr_name, None)
        if callable(method):
            method()
            return
    keys_by_id = getattr(registry, "_keys_by_id", None)
    if isinstance(keys_by_id, dict):
        keys_by_id.clear()
    api_keys_to_id = getattr(registry, "_api_keys_to_id", None)
    if isinstance(api_keys_to_id, dict):
        api_keys_to_id.clear()


def _settings_snapshot() -> dict[str, object]:
    settings = app.state.settings
    return {
        "auth_required": getattr(settings, "auth_required", None),
        "internal_platform_api_key": getattr(settings, "internal_platform_api_key", None),
        "platform_api_key": getattr(settings, "platform_api_key", None),
        "admin_api_key": getattr(settings, "admin_api_key", None),
        "api_key": getattr(settings, "api_key", None),
        "effective_platform_api_key": getattr(settings, "effective_platform_api_key", None),
    }


def _restore_settings(snapshot: dict[str, object]) -> None:
    settings = app.state.settings
    for key, value in snapshot.items():
        setattr(settings, key, value)


def test_openapi_includes_api_key_header_security_scheme() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = "integration-secret"
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.get("/openapi.json")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200
    document = response.json()

    assert "components" in document
    assert "securitySchemes" in document["components"]
    assert document["components"]["securitySchemes"]["APIKeyHeader"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
    }


def test_openapi_marks_protected_history_route_with_api_key_security() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = "integration-secret"
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.get("/openapi.json")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200
    document = response.json()

    history_get = document["paths"]["/history"]["get"]
    assert history_get["security"] == [{"APIKeyHeader": []}]


def test_openapi_keeps_health_route_unprotected() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = True
    settings.platform_api_key = "integration-secret"

    try:
        client = TestClient(app)
        response = client.get("/openapi.json")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200
    document = response.json()

    health_get = document["paths"]["/health"]["get"]
    assert "security" not in health_get


def test_swagger_ui_loads_when_auth_is_enabled() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = True
    settings.platform_api_key = "integration-secret"
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.get("/docs")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200
    assert "Swagger UI" in response.text


def test_openapi_json_loads_without_api_key_header() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = True
    settings.platform_api_key = "integration-secret"
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.get("/openapi.json")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200
    assert response.json()["openapi"].startswith("3.")
