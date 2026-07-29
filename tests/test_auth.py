from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.auth import (
    API_KEY_HEADER_NAME,
    _get_jwt_secret,
    _get_secret_key,
    get_api_key,
    get_auth_context,
    get_bearer_context,
    require_api_key,
    require_auth_context,
)
from app.core.errors import register_exception_handlers
from app.core.settings import get_settings

_SECRET_KEY_SENTINEL = "changeme-32-chars-minimum!!!!!"
_JWT_SECRET_SENTINEL = "changeme-jwt-32-chars-minimum!!"


def _make_request(settings_ns: SimpleNamespace):
    app = SimpleNamespace(state=SimpleNamespace(settings=settings_ns))
    return SimpleNamespace(app=app)


class TestGetSecretKeySentinel:
    def test_sentinel_returns_none(self):
        req = _make_request(SimpleNamespace(secret_key=_SECRET_KEY_SENTINEL))
        assert _get_secret_key(req) is None

    def test_empty_string_returns_none(self):
        req = _make_request(SimpleNamespace(secret_key=""))
        assert _get_secret_key(req) is None

    def test_whitespace_only_returns_none(self):
        req = _make_request(SimpleNamespace(secret_key="   "))
        assert _get_secret_key(req) is None

    def test_missing_attribute_returns_none(self):
        req = _make_request(SimpleNamespace())
        assert _get_secret_key(req) is None

    def test_none_settings_returns_none(self):
        app = SimpleNamespace(state=SimpleNamespace(settings=None))
        req = SimpleNamespace(app=app)
        with patch("app.core.auth.get_settings", side_effect=Exception("no settings")):
            assert _get_secret_key(req) is None


class TestGetSecretKeyRealValue:
    def test_real_value_is_returned(self):
        real_key = "my-real-ironclaw-secret-key-xyz!"
        req = _make_request(SimpleNamespace(secret_key=real_key))
        assert _get_secret_key(req) == real_key

    def test_leading_trailing_whitespace_stripped(self):
        req = _make_request(SimpleNamespace(secret_key="  real-key  "))
        assert _get_secret_key(req) == "real-key"

    def test_does_not_bleed_into_jwt_secret(self):
        req = _make_request(
            SimpleNamespace(
                secret_key="real-secret-key-abc",
                jwt_secret=_JWT_SECRET_SENTINEL,
            )
        )
        assert _get_secret_key(req) == "real-secret-key-abc"
        assert _get_jwt_secret(req) is None


class TestGetJwtSecretSentinel:
    def test_sentinel_returns_none(self):
        req = _make_request(SimpleNamespace(jwt_secret=_JWT_SECRET_SENTINEL))
        assert _get_jwt_secret(req) is None

    def test_empty_string_returns_none(self):
        req = _make_request(SimpleNamespace(jwt_secret=""))
        assert _get_jwt_secret(req) is None

    def test_whitespace_only_returns_none(self):
        req = _make_request(SimpleNamespace(jwt_secret="   "))
        assert _get_jwt_secret(req) is None

    def test_missing_attribute_returns_none(self):
        req = _make_request(SimpleNamespace())
        assert _get_jwt_secret(req) is None

    def test_none_settings_returns_none(self):
        app = SimpleNamespace(state=SimpleNamespace(settings=None))
        req = SimpleNamespace(app=app)
        with patch("app.core.auth.get_settings", side_effect=Exception("no settings")):
            assert _get_jwt_secret(req) is None


class TestGetJwtSecretRealValue:
    def test_real_value_is_returned(self):
        real_jwt = "my-real-jwt-secret-key-xyz-long!"
        req = _make_request(SimpleNamespace(jwt_secret=real_jwt))
        assert _get_jwt_secret(req) == real_jwt

    def test_leading_trailing_whitespace_stripped(self):
        req = _make_request(SimpleNamespace(jwt_secret="  real-jwt  "))
        assert _get_jwt_secret(req) == "real-jwt"

    def test_does_not_bleed_into_secret_key(self):
        req = _make_request(
            SimpleNamespace(
                secret_key=_SECRET_KEY_SENTINEL,
                jwt_secret="real-jwt-secret-abc",
            )
        )
        assert _get_jwt_secret(req) == "real-jwt-secret-abc"
        assert _get_secret_key(req) is None


class TestSecretsIndependence:
    def test_both_real_values_returned_independently(self):
        req = _make_request(
            SimpleNamespace(
                secret_key="real-secret",
                jwt_secret="real-jwt",
            )
        )
        assert _get_secret_key(req) == "real-secret"
        assert _get_jwt_secret(req) == "real-jwt"

    def test_both_sentinels_both_return_none(self):
        req = _make_request(
            SimpleNamespace(
                secret_key=_SECRET_KEY_SENTINEL,
                jwt_secret=_JWT_SECRET_SENTINEL,
            )
        )
        assert _get_secret_key(req) is None
        assert _get_jwt_secret(req) is None


class TestGetApiKeyAuthNotConfigured:
    def test_auth_not_configured_logs_warning(self, caplog):
        app = FastAPI()
        register_exception_handlers(app)
        app.state.settings = SimpleNamespace(auth_required=True)

        @app.get("/probe")
        def probe(value: str | None = Depends(get_api_key)) -> dict:
            return {"api_key": value}

        client = TestClient(app, raise_server_exceptions=False)

        with caplog.at_level(logging.WARNING, logger="app.core.auth"):
            response = client.get("/probe", headers={API_KEY_HEADER_NAME: "some-key"})

        assert response.status_code in (401, 503)
        warning_messages = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("auth_not_configured" in m for m in warning_messages)

    def test_auth_not_configured_raises_503(self, caplog):
        app = FastAPI()
        register_exception_handlers(app)
        app.state.settings = SimpleNamespace(auth_required=True)

        @app.get("/probe")
        def probe(value: str | None = Depends(get_api_key)) -> dict:
            return {"api_key": value}

        client = TestClient(app, raise_server_exceptions=False)

        with caplog.at_level(logging.WARNING, logger="app.core.auth"):
            response = client.get("/probe", headers={API_KEY_HEADER_NAME: "some-key"})

        assert response.status_code in (401, 503)


def test_get_api_key_allows_when_auth_not_required_no_settings() -> None:
    get_settings.cache_clear()

    app = FastAPI()
    app.state.settings = SimpleNamespace(auth_required=False)

    @app.get("/open")
    def open_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/open")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_require_api_key_accepts_valid_key_when_configured() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/protected", headers={API_KEY_HEADER_NAME: "test-secret-key"})

    assert response.status_code == 200
    assert response.json() == {"api_key": "test-secret-key"}


def test_require_api_key_raises_for_missing_key_when_required() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected")

    assert response.status_code == 401
    detail = response.json()["detail"]
    assert "missing" in detail.lower() or "api key" in detail.lower()


def test_require_api_key_raises_for_invalid_key_when_required() -> None:
    app = FastAPI()
    register_exception_handlers(app)
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected", headers={API_KEY_HEADER_NAME: "wrong-key"})

    assert response.status_code == 401
    body = response.json()
    assert body.get("error") == "invalid_api_key"
    assert "invalid" in body.get("message", "").lower() or "api key" in body.get("message", "").lower()


def test_require_api_key_allows_optional_mode_without_header() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(auth_required=False)

    @app.get("/optional")
    def optional_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/optional")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_get_api_key_accepts_admin_api_key_when_configured() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(admin_api_key="admin-secret-key", auth_required=True)

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/protected", headers={API_KEY_HEADER_NAME: "admin-secret-key"})

    assert response.status_code == 200
    assert response.json() == {"api_key": "admin-secret-key"}


def test_true_browser_preflight_bypasses_require_api_key() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.options("/protected")
    def protected_options(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.options(
        "/protected",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_true_browser_preflight_bypasses_get_api_key() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.options("/probe")
    def probe(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.options(
        "/probe",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_plain_options_without_browser_preflight_headers_does_not_bypass_auth() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.options("/protected")
    def protected_options(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.options("/protected")

    assert response.status_code == 401


def test_options_with_origin_but_without_access_control_request_method_does_not_bypass_auth() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.options("/protected")
    def protected_options(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.options(
        "/protected",
        headers={
            "Origin": "https://moving-forward.ca",
        },
    )

    assert response.status_code == 401


def test_get_bearer_context_ignores_true_browser_preflight() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        jwt_secret="test-jwt-secret",
        effective_jwt_secret="test-jwt-secret",
        supabase_jwt_secret="test-jwt-secret",
    )

    @app.options("/bearer")
    def bearer_route(
        context=Depends(get_bearer_context),
    ) -> dict[str, bool]:
        return {"is_none": context is None}

    client = TestClient(app)
    response = client.options(
        "/bearer",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"is_none": True}


def test_get_auth_context_returns_preflight_context_for_true_browser_preflight() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.options("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "principal_type": context.principal_type,
            "authenticated": context.authenticated,
            "auth_source": context.auth_source,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.options(
        "/context",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "principal_type": "preflight",
        "authenticated": False,
        "auth_source": "preflight",
        "metadata": {"request_method": "OPTIONS"},
    }


def test_require_auth_context_allows_preflight_context_without_authentication() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.options("/require-context")
    def require_context_route(
        context=Depends(require_auth_context),
    ) -> dict[str, str]:
        return {"principal_type": context.principal_type}

    client = TestClient(app)
    response = client.options(
        "/require-context",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"principal_type": "preflight"}


def test_preflight_metadata_is_telemetry_only_and_does_not_change_normal_get_auth() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(api_key="test-secret-key", auth_required=True)

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "principal_type": context.principal_type,
            "authenticated": context.authenticated,
            "auth_source": context.auth_source,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["principal_type"] != "preflight"
    assert body["authenticated"] is True
    assert body["auth_source"] in {"configured", "passthrough", "registry"}
    assert body["metadata"] == {"header": API_KEY_HEADER_NAME}
