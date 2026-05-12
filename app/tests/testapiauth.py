from __future__ import annotations

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


def _register_api_key(*, key_id: str, api_key: str) -> None:
    registry = get_api_key_registry()
    for attr_name in ("register_api_key", "add_api_key", "upsert_api_key"):
        method = getattr(registry, attr_name, None)
        if callable(method):
            try:
                method(key_id=key_id, api_key=api_key)
                return
            except TypeError:
                try:
                    method(id=key_id, api_key=api_key)
                    return
                except TypeError:
                    pass
    raise AssertionError("API key registry does not expose a supported registration method")


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


def test_protected_api_route_rejects_missing_key_when_configured_platform_key_exists() -> None:
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
        response = client.get("/history")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 401
    assert response.json() == {
        "error": "missing_api_key",
        "message": "Missing API key",
        "details": {"header": "X-API-Key"},
    }


def test_protected_api_route_accepts_configured_platform_key() -> None:
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
        response = client.get("/history", headers={"X-API-Key": "integration-secret"})
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200


def test_protected_api_route_rejects_invalid_configured_platform_key() -> None:
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
        response = client.get("/history", headers={"X-API-Key": "wrong-secret"})
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 401
    assert response.json() == {
        "error": "invalid_api_key",
        "message": "Invalid API key",
        "details": {"header": "X-API-Key"},
    }


def test_protected_api_route_accepts_registry_key_without_configured_key() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = None
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None
    _register_api_key(key_id="test-client", api_key="registry-secret")

    try:
        client = TestClient(app)
        response = client.get("/history", headers={"X-API-Key": "registry-secret"})
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200


def test_protected_api_route_rejects_missing_key_when_registry_has_keys() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = None
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None
    _register_api_key(key_id="test-client", api_key="registry-secret")

    try:
        client = TestClient(app)
        response = client.get("/history")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 401
    assert response.json() == {
        "error": "missing_api_key",
        "message": "Missing API key",
        "details": {"header": "X-API-Key"},
    }


def test_protected_api_route_rejects_invalid_registry_key() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = None
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None
    _register_api_key(key_id="test-client", api_key="registry-secret")

    try:
        client = TestClient(app)
        response = client.get("/history", headers={"X-API-Key": "wrong-secret"})
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 401
    assert response.json() == {
        "error": "invalid_api_key",
        "message": "Invalid API key",
        "details": {"header": "X-API-Key"},
    }


def test_explicit_auth_required_false_keeps_route_open_even_with_registry_keys() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = False
    settings.platform_api_key = None
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None
    _register_api_key(key_id="test-client", api_key="registry-secret")

    try:
        client = TestClient(app)
        response = client.get("/history")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200


def test_explicit_auth_required_true_without_any_key_source_returns_service_unavailable() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = True
    settings.platform_api_key = None
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.get("/history", headers={"X-API-Key": "anything"})
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 503
    assert response.json() == {
        "error": "auth_not_configured",
        "message": "API authentication is enabled but no API key is configured",
        "details": None,
    }


def test_open_route_remains_available_without_api_key() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = True
    settings.platform_api_key = "integration-secret"

    try:
        client = TestClient(app)
        response = client.get("/health")
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code == 200
