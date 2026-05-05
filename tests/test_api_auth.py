from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME, get_api_key, require_api_key
from app.core.errors import AppError


def test_get_api_key_allows_when_auth_not_required() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        auth_required=False,
    )

    @app.get("/open")
    def open_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/open")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_get_api_key_returns_supplied_key_when_auth_not_required() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        auth_required=False,
    )

    @app.get("/open")
    def open_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get(
        "/open",
        headers={API_KEY_HEADER_NAME: "provided-key"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "provided-key"}


def test_require_api_key_allows_valid_key_when_required() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        auth_required=True,
    )

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get(
        "/protected",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "test-secret-key"}


def test_require_api_key_rejects_missing_key_when_required() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        auth_required=True,
    )

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)

    with pytest.raises(AppError) as exc_info:
        client.get("/protected")

    assert exc_info.value.status_code == 401
    assert exc_info.value.error == "missing_api_key"


def test_require_api_key_rejects_invalid_key_when_required() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        auth_required=True,
    )

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)

    with pytest.raises(AppError) as exc_info:
        client.get(
            "/protected",
            headers={API_KEY_HEADER_NAME: "wrong-key"},
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.error == "invalid_api_key"


def test_require_api_key_allows_when_auth_disabled_even_without_key() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        auth_required=False,
    )

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/protected")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}