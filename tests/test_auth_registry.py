from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core import auth as auth_module
from app.core.api_keys import create_api_key_registry
from app.core.auth import API_KEY_HEADER_NAME, get_api_key, require_api_key
from app.core.errors import AppError


def _build_app(
    *,
    auth_required: bool = True,
    api_key: str | None = None,
    admin_api_key: str | None = None,
) -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=auth_required,
        api_key=api_key,
        admin_api_key=admin_api_key,
    )
    return app


def test_get_api_key_accepts_registry_key_when_auth_required() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    registry = create_api_key_registry()
    record = registry.create_key("Registry Test Key")

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: registry
    try:
        client = TestClient(app)
        response = client.get("/protected", headers={API_KEY_HEADER_NAME: record.raw_key or ""})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert response.status_code == 200
    assert response.json() == {"api_key": record.raw_key}


def test_require_api_key_accepts_registry_key_when_auth_required() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str = Depends(require_api_key)) -> dict[str, str]:
        return {"api_key": value}

    registry = create_api_key_registry()
    record = registry.create_key("Registry Require Key")

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: registry
    try:
        client = TestClient(app)
        response = client.get("/protected", headers={API_KEY_HEADER_NAME: record.raw_key or ""})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert response.status_code == 200
    assert response.json() == {"api_key": record.raw_key}


def test_get_api_key_raises_auth_not_configured_when_required_without_any_keys() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: create_api_key_registry()
    try:
        client = TestClient(app)
        with pytest.raises(AppError) as exc_info:
            client.get("/protected", headers={API_KEY_HEADER_NAME: "some-key"})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert exc_info.value.status_code == 503
    assert exc_info.value.error == "auth_not_configured"


def test_get_api_key_prefers_configured_key_over_invalid_registry_lookup() -> None:
    app = _build_app(auth_required=True, api_key="configured-secret")

    @app.get("/protected")
    def protected_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: create_api_key_registry()
    try:
        client = TestClient(app)
        response = client.get("/protected", headers={API_KEY_HEADER_NAME: "configured-secret"})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert response.status_code == 200
    assert response.json() == {"api_key": "configured-secret"}


def test_require_api_key_rejects_invalid_registry_key() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str = Depends(require_api_key)) -> dict[str, str]:
        return {"api_key": value}

    registry = create_api_key_registry()
    registry.create_key("Valid Registry Key")

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: registry
    try:
        client = TestClient(app)
        with pytest.raises(AppError) as exc_info:
            client.get("/protected", headers={API_KEY_HEADER_NAME: "invalid-registry-key"})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert exc_info.value.status_code == 401
    assert exc_info.value.error == "invalid_api_key"