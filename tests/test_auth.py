from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import jwt

from app.core.auth import (
    API_KEY_HEADER_NAME,
    AUTHORIZATION_HEADER_NAME,
    ORG_ID_HEADER_NAME,
    ORGANIZATION_ID_HEADER_NAME,
    TENANT_ID_HEADER_NAME,
    _get_jwt_secret,
    _get_secret_key,
    get_api_key,
    get_auth_context,
    get_bearer_context,
    get_supabase_jwt_secret,
    require_api_key,
    require_auth_context,
)
from app.core.errors import register_exception_handlers
from app.core.settings import get_settings

_TEST_EC_PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILQtrVqsgUBlx+2WU/ONqBI+Gb/9CWO5Iu/yhlPzJVxmoAoGCCqGSM49
AwEHoUQDQgAERpwUk5Yi5ZO5ri/HP7iaajbhPQ8snugWesnbfp0af61Fq+U2NNmQ
DPmuzaOjuR1oe5rKSQo5GSFypwv7QeIhBw==
-----END EC PRIVATE KEY-----"""

_TEST_EC_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERpwUk5Yi5ZO5ri/HP7iaajbhPQ8s
nugWesnbfp0af61Fq+U2NNmQDPmuzaOjuR1oe5rKSQo5GSFypwv7QeIhBw==
-----END PUBLIC KEY-----"""

_HS256_SUPABASE_SECRET = "supabase-secret-key-for-tests-32-bytes-min!!"
_HS256_WRONG_SECRET = "wrong-secret-key-for-tests-32-bytes-min!!!!!"
_HS512_JWT_SECRET = "jwt-secret-key-for-tests-hs512-64-bytes-minimum-length-value!!!!"


def _make_request(settings_ns: SimpleNamespace):
    app = SimpleNamespace(state=SimpleNamespace(settings=settings_ns))
    return SimpleNamespace(app=app)


class TestGetSecretKeySentinel:
    def test_sentinel_returns_none(self):
        req = _make_request(SimpleNamespace(secret_key=""))
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

    def test_effective_secret_key_takes_precedence(self):
        req = _make_request(
            SimpleNamespace(
                effective_secret_key="effective-secret",
                secret_key="raw-secret",
            )
        )
        assert _get_secret_key(req) == "effective-secret"


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
                jwt_secret="",
            )
        )
        assert _get_secret_key(req) == "real-secret-key-abc"
        assert _get_jwt_secret(req) is None


class TestGetJwtSecretSentinel:
    def test_sentinel_returns_none(self):
        req = _make_request(SimpleNamespace(jwt_secret=""))
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

    def test_effective_jwt_secret_takes_precedence(self):
        req = _make_request(
            SimpleNamespace(
                effective_jwt_secret="effective-jwt",
                jwt_secret="raw-jwt",
            )
        )
        assert _get_jwt_secret(req) == "effective-jwt"


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
                secret_key="",
                jwt_secret="real-jwt-secret-abc",
            )
        )
        assert _get_jwt_secret(req) == "real-jwt-secret-abc"
        assert _get_secret_key(req) is None


class TestGetSupabaseJwtSecret:
    def test_effective_supabase_jwt_secret_takes_precedence(self):
        req = _make_request(
            SimpleNamespace(
                effective_supabase_jwt_secret="effective-supabase-jwt",
                supabase_jwt_secret="raw-supabase-jwt",
                effective_jwt_secret="effective-jwt",
            )
        )
        assert get_supabase_jwt_secret(req) == "effective-supabase-jwt"

    def test_supabase_jwt_secret_falls_back_to_direct_supabase_value(self):
        req = _make_request(
            SimpleNamespace(
                supabase_jwt_secret="raw-supabase-jwt",
                effective_jwt_secret="effective-jwt",
            )
        )
        assert get_supabase_jwt_secret(req) == "raw-supabase-jwt"

    def test_supabase_jwt_secret_falls_back_to_jwt_secret(self):
        req = _make_request(
            SimpleNamespace(
                effective_jwt_secret="effective-jwt",
            )
        )
        assert get_supabase_jwt_secret(req) == "effective-jwt"


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

    def test_both_empty_both_return_none(self):
        req = _make_request(
            SimpleNamespace(
                secret_key="",
                jwt_secret="",
            )
        )
        assert _get_secret_key(req) is None
        assert _get_jwt_secret(req) is None


class TestGetApiKeyAuthNotConfigured:
    def test_auth_not_configured_logs_warning(self, caplog):
        app = FastAPI()
        register_exception_handlers(app)
        app.state.settings = SimpleNamespace(effective_auth_required=True)

        @app.get("/probe")
        def probe(value: str | None = Depends(get_api_key)) -> dict:
            return {"api_key": value}

        client = TestClient(app, raise_server_exceptions=False)

        with caplog.at_level(logging.WARNING, logger="app.core.auth"):
            response = client.get("/probe", headers={API_KEY_HEADER_NAME: "some-key"})

        assert response.status_code == 503
        warning_messages = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("auth_not_configured" in m for m in warning_messages)

    def test_auth_not_configured_raises_503(self, caplog):
        app = FastAPI()
        register_exception_handlers(app)
        app.state.settings = SimpleNamespace(effective_auth_required=True)

        @app.get("/probe")
        def probe(value: str | None = Depends(get_api_key)) -> dict:
            return {"api_key": value}

        client = TestClient(app, raise_server_exceptions=False)

        with caplog.at_level(logging.WARNING, logger="app.core.auth"):
            response = client.get("/probe", headers={API_KEY_HEADER_NAME: "some-key"})

        assert response.status_code == 503


def test_get_api_key_allows_when_auth_not_required_no_settings() -> None:
    get_settings.cache_clear()

    app = FastAPI()
    app.state.settings = SimpleNamespace(effective_auth_required=False)

    @app.get("/open")
    def open_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/open")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_require_api_key_accepts_valid_key_when_configured() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    assert (
        "invalid" in body.get("message", "").lower()
        or "api key"
        in body.get(
            "message",
            "",
        ).lower()
    )


def test_require_api_key_allows_optional_mode_without_header() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(effective_auth_required=False)

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
    app.state.settings = SimpleNamespace(
        admin_api_key="admin-secret-key",
        effective_auth_required=True,
    )

    @app.get("/protected")
    def protected_route(
        value: str | None = Depends(get_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/protected", headers={API_KEY_HEADER_NAME: "admin-secret-key"})

    assert response.status_code == 200
    assert response.json() == {"api_key": "admin-secret-key"}


def test_effective_auth_required_false_overrides_raw_auth_required_true() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        effective_auth_required=False,
    )

    @app.get("/optional")
    def optional_route(
        value: str | None = Depends(require_api_key),
    ) -> dict[str, str | None]:
        return {"api_key": value}

    client = TestClient(app)
    response = client.get("/optional")

    assert response.status_code == 200
    assert response.json() == {"api_key": None}


def test_true_browser_preflight_bypasses_require_api_key() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
        effective_auth_required=True,
        effective_jwt_secret=_TEST_EC_PRIVATE_KEY_PEM,
        effective_supabase_jwt_secret=_TEST_EC_PRIVATE_KEY_PEM,
        effective_jwt_algorithm="ES256",
        jwt_public_key=_TEST_EC_PUBLIC_KEY_PEM,
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


def test_get_bearer_context_uses_effective_supabase_jwt_secret() -> None:
    token = jwt.encode({"sub": "user-123"}, _TEST_EC_PRIVATE_KEY_PEM, algorithm="ES256")

    app = FastAPI()
    app.state.settings = SimpleNamespace(
        effective_auth_required=True,
        effective_supabase_jwt_secret=_TEST_EC_PRIVATE_KEY_PEM,
        effective_jwt_secret=_HS256_WRONG_SECRET,
        effective_jwt_algorithm="ES256",
        jwt_public_key=_TEST_EC_PUBLIC_KEY_PEM,
    )

    @app.get("/bearer")
    def bearer_route(
        context=Depends(get_bearer_context),
    ) -> dict[str, str | None]:
        return {"principal_id": None if context is None else context.principal_id}

    client = TestClient(app)
    response = client.get(
        "/bearer",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"principal_id": "user-123"}


def test_get_bearer_context_uses_settings_jwt_algorithm() -> None:
    token = jwt.encode({"sub": "user-456"}, _TEST_EC_PRIVATE_KEY_PEM, algorithm="ES256")

    app = FastAPI()
    app.state.settings = SimpleNamespace(
        effective_auth_required=True,
        effective_supabase_jwt_secret=_TEST_EC_PRIVATE_KEY_PEM,
        effective_jwt_algorithm="ES256",
        jwt_public_key=_TEST_EC_PUBLIC_KEY_PEM,
    )

    @app.get("/bearer")
    def bearer_route(
        context=Depends(get_bearer_context),
    ) -> dict[str, str | None]:
        return {"principal_id": None if context is None else context.principal_id}

    client = TestClient(app)
    response = client.get(
        "/bearer",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"principal_id": "user-456"}


def test_get_bearer_context_returns_503_when_effective_auth_required_and_secret_missing() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        effective_auth_required=True,
        effective_supabase_jwt_secret=None,
        effective_jwt_secret=None,
    )

    @app.get("/bearer")
    def bearer_route(
        context=Depends(get_bearer_context),
    ) -> dict[str, bool]:
        return {"is_none": context is None}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get(
        "/bearer",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"].lower()


def test_get_bearer_context_ignores_invalid_token_when_auth_not_effectively_required() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        effective_auth_required=False,
        effective_supabase_jwt_secret=_TEST_EC_PRIVATE_KEY_PEM,
        effective_jwt_algorithm="ES256",
        jwt_public_key=_TEST_EC_PUBLIC_KEY_PEM,
    )

    @app.get("/bearer")
    def bearer_route(
        context=Depends(get_bearer_context),
    ) -> dict[str, bool]:
        return {"is_none": context is None}

    client = TestClient(app)
    response = client.get(
        "/bearer",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"is_none": True}


def test_get_auth_context_returns_preflight_context_for_true_browser_preflight() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

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
    assert body["metadata"] == {
        "header": API_KEY_HEADER_NAME,
        "org_source": "none",
    }


def test_get_auth_context_uses_x_org_id_header() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "org_id": context.org_id,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={
            API_KEY_HEADER_NAME: "test-secret-key",
            ORG_ID_HEADER_NAME: "org-123",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "org_id": "org-123",
        "metadata": {
            "header": API_KEY_HEADER_NAME,
            "org_source": ORG_ID_HEADER_NAME,
        },
    }


def test_get_auth_context_uses_x_organization_id_header_alias() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "org_id": context.org_id,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={
            API_KEY_HEADER_NAME: "test-secret-key",
            ORGANIZATION_ID_HEADER_NAME: "org-xyz",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "org_id": "org-xyz",
        "metadata": {
            "header": API_KEY_HEADER_NAME,
            "org_source": ORGANIZATION_ID_HEADER_NAME,
        },
    }


def test_get_auth_context_uses_x_tenant_id_header_alias() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "org_id": context.org_id,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={
            API_KEY_HEADER_NAME: "test-secret-key",
            TENANT_ID_HEADER_NAME: "tenant-123",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "org_id": "tenant-123",
        "metadata": {
            "header": API_KEY_HEADER_NAME,
            "org_source": TENANT_ID_HEADER_NAME,
        },
    }


def test_get_auth_context_rejects_conflicting_org_headers() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "org_id": context.org_id,
        }

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get(
        "/context",
        headers={
            API_KEY_HEADER_NAME: "test-secret-key",
            ORG_ID_HEADER_NAME: "org-123",
            ORGANIZATION_ID_HEADER_NAME: "org-456",
        },
    )

    assert response.status_code == 400
    assert "conflicting organization scope headers" in response.json()["detail"].lower()


def test_get_auth_context_allows_duplicate_org_headers_when_values_match() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        api_key="test-secret-key",
        effective_auth_required=True,
    )

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "org_id": context.org_id,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={
            API_KEY_HEADER_NAME: "test-secret-key",
            ORG_ID_HEADER_NAME: "org-123",
            ORGANIZATION_ID_HEADER_NAME: "org-123",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "org_id": "org-123",
        "metadata": {
            "header": API_KEY_HEADER_NAME,
            "org_source": ORG_ID_HEADER_NAME,
        },
    }


def test_get_auth_context_bearer_claim_org_takes_precedence_over_header_aliases() -> None:
    token = jwt.encode(
        {
            "sub": "user-123",
            "org_id": "claim-org-123",
            "email": "user@example.com",
        },
        _TEST_EC_PRIVATE_KEY_PEM,
        algorithm="ES256",
    )

    app = FastAPI()
    app.state.settings = SimpleNamespace(
        effective_auth_required=True,
        effective_supabase_jwt_secret=_TEST_EC_PRIVATE_KEY_PEM,
        effective_jwt_algorithm="ES256",
        jwt_public_key=_TEST_EC_PUBLIC_KEY_PEM,
    )

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "principal_id": context.principal_id,
            "org_id": context.org_id,
            "auth_source": context.auth_source,
            "auth_method": context.auth_method,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={
            AUTHORIZATION_HEADER_NAME: f"Bearer {token}",
            ORGANIZATION_ID_HEADER_NAME: "header-org-999",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "principal_id": "user-123",
        "org_id": "claim-org-123",
        "auth_source": "supabase_jwt",
        "auth_method": "bearer_jwt",
        "metadata": {
            "header": AUTHORIZATION_HEADER_NAME,
            "email": "user@example.com",
            "org_source": "claim:org_id",
        },
    }


def test_get_auth_context_bearer_falls_back_to_header_alias_when_claim_missing() -> None:
    token = jwt.encode(
        {"sub": "user-456"},
        _TEST_EC_PRIVATE_KEY_PEM,
        algorithm="ES256",
    )

    app = FastAPI()
    app.state.settings = SimpleNamespace(
        effective_auth_required=True,
        effective_supabase_jwt_secret=_TEST_EC_PRIVATE_KEY_PEM,
        effective_jwt_algorithm="ES256",
        jwt_public_key=_TEST_EC_PUBLIC_KEY_PEM,
    )

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "principal_id": context.principal_id,
            "org_id": context.org_id,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={
            AUTHORIZATION_HEADER_NAME: f"Bearer {token}",
            ORGANIZATION_ID_HEADER_NAME: "header-org-456",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "principal_id": "user-456",
        "org_id": "header-org-456",
        "metadata": {
            "header": AUTHORIZATION_HEADER_NAME,
            "org_source": ORGANIZATION_ID_HEADER_NAME,
        },
    }


def test_get_auth_context_returns_anonymous_context_with_header_org_when_auth_disabled() -> None:
    app = FastAPI()
    app.state.settings = SimpleNamespace(effective_auth_required=False)

    @app.get("/context")
    def context_route(
        context=Depends(get_auth_context),
    ) -> dict[str, object]:
        return {
            "principal_type": context.principal_type,
            "authenticated": context.authenticated,
            "org_id": context.org_id,
            "auth_source": context.auth_source,
            "metadata": context.metadata,
        }

    client = TestClient(app)
    response = client.get(
        "/context",
        headers={ORGANIZATION_ID_HEADER_NAME: "org-open-123"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "principal_type": "anonymous",
        "authenticated": False,
        "org_id": "org-open-123",
        "auth_source": "disabled",
        "metadata": {"org_source": ORGANIZATION_ID_HEADER_NAME},
    }
