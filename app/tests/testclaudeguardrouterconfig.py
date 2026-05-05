from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.core.api_keys import get_api_key_registry
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


def _assert_auth_failure_shape(response, *, error: str, message: str) -> None:
    assert response.status_code in {401, 503}
    assert response.json() == {
        "error": error,
        "message": message,
        "details": {"header": "X-API-Key"} if response.status_code == 401 else None,
    }


def test_claude_guard_router_route_requires_api_key_when_platform_key_configured() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = "platform-secret"
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.post("/api/claude-guard-router", json={})
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    _assert_auth_failure_shape(
        response,
        error="missing_api_key",
        message="Missing API key",
    )


def test_claude_guard_router_route_accepts_configured_platform_key() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = "platform-secret"
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.post(
            "/api/claude-guard-router",
            headers={"X-API-Key": "platform-secret"},
            json={},
        )
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code != 401
    assert response.status_code != 503


def test_claude_guard_router_route_accepts_registry_key_without_configured_key() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    _register_api_key(key_id="claude-router", api_key="registry-secret")
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = None
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.post(
            "/api/claude-guard-router",
            headers={"X-API-Key": "registry-secret"},
            json={},
        )
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    assert response.status_code != 401
    assert response.status_code != 503


def test_claude_guard_router_route_rejects_invalid_registry_key() -> None:
    snapshot = _settings_snapshot()
    _clear_registry()
    _register_api_key(key_id="claude-router", api_key="registry-secret")
    settings = app.state.settings
    settings.auth_required = None
    settings.platform_api_key = None
    settings.internal_platform_api_key = None
    settings.admin_api_key = None
    settings.api_key = None
    settings.effective_platform_api_key = None

    try:
        client = TestClient(app)
        response = client.post(
            "/api/claude-guard-router",
            headers={"X-API-Key": "wrong-secret"},
            json={},
        )
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    _assert_auth_failure_shape(
        response,
        error="invalid_api_key",
        message="Invalid API key",
    )


def test_claude_guard_router_route_returns_auth_not_configured_when_forced_without_keys() -> None:
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
        response = client.post(
            "/api/claude-guard-router",
            headers={"X-API-Key": "anything"},
            json={},
        )
    finally:
        _restore_settings(snapshot)
        _clear_registry()

    _assert_auth_failure_shape(
        response,
        error="auth_not_configured",
        message="API authentication is enabled but no API key is configured",
    )


def test_claude_guard_router_route_declares_api_key_security_in_openapi() -> None:
    client = TestClient(app)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    operation = response.json()["paths"]["/api/claude-guard-router"]["post"]
    assert operation["security"] == [{"APIKeyHeader": []}]