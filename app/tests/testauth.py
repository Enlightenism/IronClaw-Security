from __future__ import annotations

from types import SimpleNamespace

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
import pytest

from app.core.apikeys import get_api_key_registry
from app.core.auth import API_KEY_HEADER_NAME, get_api_key, require_api_key
from app.core.errors import AppError
from app.core.handlers import register_exception_handlers


def _build_app(*, settings: object) -> FastAPI:
    app = FastAPI()
    app.state.settings = settings
    register_exception_handlers(app)

    @app.get("/auth/optional")
    def read_optional(api_key: str | None = Depends(get_api_key)):
        return {"api_key": api_key}

    @app.get("/auth/required")
    def read_required(api_key: str | None = Depends(require_api_key)):
        return {"api_key": api_key}

    return app


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


def _register_registry_key(*, key_id: str = "test-key", api_key: str = "registry-secret") -> None:
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
    pytest.skip("API key registry does not expose a supported registration method")


@pytest.fixture(autouse=True)
def _isolated_registry():
    _clear_registry()
    yield
    _clear_registry()


def test_get_api_key_returns_none_when_auth_is_not_required() -> None:
    app = _build_app(settings=SimpleNamespace(auth_required=False))
    client = TestClient(app)

    response = client.get("/auth/optional")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_get_api_key_passthrough_when_auth_is_not_required() -> None:
    app = _build_app(settings=SimpleNamespace(auth_required=False))
    client = TestClient(app)

    response = client.get("/auth/optional", headers={API_KEY_HEADER_NAME: "provided-key"})

    assert response.status_code == 200
    assert response.json() == {"api_key": "provided-key"}


def test_require_api_key_rejects_missing_key_when_auth_required_by_flag() -> None:
    app = _build_app(settings=SimpleNamespace(auth_required=True))
    client = TestClient(app)

    response = client.get("/auth/required")

    assert response.status_code == 503
    payload = response.json()
    assert payload["error"] == "auth_not_configured"


def test_get_api_key_accepts_configured_platform_key() -> None:
    app = _build_app(settings=SimpleNamespace(platform_api_key="platform-secret"))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "platform-secret"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "platform-secret"}


def test_get_api_key_strips_header_before_validation() -> None:
    app = _build_app(settings=SimpleNamespace(platform_api_key="platform-secret"))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "  platform-secret  "},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "platform-secret"}


def test_get_api_key_rejects_blank_header_when_auth_required() -> None:
    app = _build_app(settings=SimpleNamespace(platform_api_key="platform-secret"))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "   "},
    )

    assert response.status_code == 401
    payload = response.json()
    assert payload["error"] == "missing_api_key"
    assert payload["details"]["header"] == API_KEY_HEADER_NAME


def test_get_api_key_rejects_invalid_key_against_configured_value() -> None:
    app = _build_app(settings=SimpleNamespace(platform_api_key="platform-secret"))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "wrong-secret"},
    )

    assert response.status_code == 401
    payload = response.json()
    assert payload["error"] == "invalid_api_key"
    assert payload["details"]["header"] == API_KEY_HEADER_NAME


def test_get_api_key_accepts_registry_key_when_no_configured_key() -> None:
    _register_registry_key(api_key="registry-secret")
    app = _build_app(settings=SimpleNamespace())
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "registry-secret"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "registry-secret"}


def test_get_api_key_rejects_missing_header_when_registry_requires_auth() -> None:
    _register_registry_key(api_key="registry-secret")
    app = _build_app(settings=SimpleNamespace())
    client = TestClient(app)

    response = client.get("/auth/required")

    assert response.status_code == 401
    payload = response.json()
    assert payload["error"] == "missing_api_key"
    assert payload["details"]["header"] == API_KEY_HEADER_NAME


def test_get_api_key_rejects_invalid_registry_key() -> None:
    _register_registry_key(api_key="registry-secret")
    app = _build_app(settings=SimpleNamespace())
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "not-the-key"},
    )

    assert response.status_code == 401
    payload = response.json()
    assert payload["error"] == "invalid_api_key"
    assert payload["details"]["header"] == API_KEY_HEADER_NAME


def test_configured_key_and_registry_key_both_work() -> None:
    _register_registry_key(api_key="registry-secret")
    app = _build_app(settings=SimpleNamespace(platform_api_key="platform-secret"))
    client = TestClient(app)

    configured_response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "platform-secret"},
    )
    registry_response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "registry-secret"},
    )

    assert configured_response.status_code == 200
    assert configured_response.json() == {"api_key": "platform-secret"}
    assert registry_response.status_code == 200
    assert registry_response.json() == {"api_key": "registry-secret"}


def test_explicit_auth_required_false_disables_registry_enforcement() -> None:
    _register_registry_key(api_key="registry-secret")
    app = _build_app(settings=SimpleNamespace(auth_required=False))
    client = TestClient(app)

    response = client.get("/auth/required")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_auth_required_true_without_any_key_source_returns_service_unavailable() -> None:
    app = _build_app(settings=SimpleNamespace(auth_required=True))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "anything"},
    )

    assert response.status_code == 503
    payload = response.json()
    assert payload["error"] == "auth_not_configured"


def test_get_api_key_prefers_effective_platform_api_key_when_present() -> None:
    app = _build_app(settings=SimpleNamespace(effective_platform_api_key="effective-secret"))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "effective-secret"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "effective-secret"}


def test_get_api_key_uses_first_non_empty_supported_setting_field() -> None:
    app = _build_app(
        settings=SimpleNamespace(
            internal_platform_api_key="",
            platform_api_key="",
            admin_api_key="admin-secret",
            api_key="fallback-secret",
        ),
    )
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "admin-secret"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "admin-secret"}


def test_require_api_key_dependency_returns_key_value() -> None:
    app = _build_app(settings=SimpleNamespace(platform_api_key="platform-secret"))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "platform-secret"},
    )

    assert response.status_code == 200
    assert response.json()["api_key"] == "platform-secret"


def test_app_error_shape_for_invalid_key_is_stable() -> None:
    app = _build_app(settings=SimpleNamespace(platform_api_key="platform-secret"))
    client = TestClient(app)

    response = client.get(
        "/auth/required",
        headers={API_KEY_HEADER_NAME: "invalid"},
    )

    assert response.status_code == 401
    payload = response.json()
    assert payload == {
        "error": "invalid_api_key",
        "message": "Invalid API key",
        "details": {"header": API_KEY_HEADER_NAME},
    }


def test_direct_dependency_raises_auth_not_configured_when_enabled_without_keys() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(auth_required=True)
    request = Request(
        {
            "type": "http",
            "app": app,
            "headers": [],
            "method": "GET",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
            "scheme": "http",
            "root_path": "",
            "http_version": "1.1",
        },
    )

    with pytest.raises(AppError) as exc_info:
        get_api_key(request=request, provided_api_key="anything")

    assert exc_info.value.status_code == 503
    assert exc_info.value.error == "auth_not_configured"
