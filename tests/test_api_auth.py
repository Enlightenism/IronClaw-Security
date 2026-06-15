from __future__ import annotations

from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME, get_api_key, require_api_key
from app.core.errors import register_exception_handlers

# ---------------------------------------------------------------------------
# App factory — registers exception handlers so 401 surfaces as HTTP response
# ---------------------------------------------------------------------------


def _make_app(*, auth_required: bool, api_key: str = "test-secret-key") -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.state.settings = SimpleNamespace(
        api_key=api_key,
        auth_required=auth_required,
    )
    return app


# ---------------------------------------------------------------------------
# get_api_key — open routes
# ---------------------------------------------------------------------------


def test_get_api_key_allows_when_auth_not_required() -> None:
    app = _make_app(auth_required=False)

    @app.get("/open")
    def open_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/open")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_get_api_key_returns_supplied_key_when_auth_not_required() -> None:
    app = _make_app(auth_required=False)

    @app.get("/open")
    def open_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get(
        "/open",
        headers={API_KEY_HEADER_NAME: "provided-key"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "provided-key"}


# ---------------------------------------------------------------------------
# require_api_key — protected routes
# ---------------------------------------------------------------------------


def test_require_api_key_allows_valid_key_when_required() -> None:
    app = _make_app(auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get(
        "/protected",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": "test-secret-key"}


def test_require_api_key_rejects_missing_key_when_required() -> None:
    app = _make_app(auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected")

    assert response.status_code == 401
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], str)
    assert "missing" in body["detail"].lower() or "api key" in body["detail"].lower()


def test_require_api_key_rejects_invalid_key_when_required() -> None:
    app = _make_app(auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get(
        "/protected",
        headers={API_KEY_HEADER_NAME: "wrong-key"},
    )

    assert response.status_code == 401
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], str)
    assert "invalid" in body["detail"].lower() or "api key" in body["detail"].lower()


def test_require_api_key_allows_when_auth_disabled_even_without_key() -> None:
    app = _make_app(auth_required=False)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


# ---------------------------------------------------------------------------
# 401 body contract assertions
# ---------------------------------------------------------------------------


def test_missing_key_401_body_does_not_have_error_key() -> None:
    """HTTPException 401 must produce {"detail": str}, never {"error": ...}."""
    app = _make_app(auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected")

    assert response.status_code == 401
    body = response.json()
    assert "error" not in body
    assert "detail" in body


def test_invalid_key_401_body_does_not_have_error_key() -> None:
    """HTTPException 401 for invalid key must produce {"detail": str}."""
    app = _make_app(auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected", headers={API_KEY_HEADER_NAME: "wrong-key"})

    assert response.status_code == 401
    body = response.json()
    assert "error" not in body
    assert "detail" in body
    assert "invalid" in body["detail"].lower() or "api key" in body["detail"].lower()


def test_503_auth_not_configured_body_has_detail() -> None:
    """When auth_required=True but no key is configured and registry is empty, 503 uses {"detail": str}."""
    app = FastAPI()
    register_exception_handlers(app)
    # No api_key attribute on settings — simulates unconfigured auth
    app.state.settings = SimpleNamespace(auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected")

    # Either 401 (missing key) or 503 (no keys configured) — both use {"detail": str}
    assert response.status_code in (401, 503)
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], str)
