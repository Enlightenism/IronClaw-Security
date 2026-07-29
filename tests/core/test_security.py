from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.auth import require_api_key
from app.core.security import (
    _DEFAULT_ALLOWED_HEADERS,
    _DEFAULT_ALLOWED_METHODS,
    _DEFAULT_CSP,
    _DEFAULT_EXPOSE_HEADERS,
    _coerce_list,
    _csv_to_list,
    _normalize_unique,
    get_allowed_headers,
    get_allowed_hosts,
    get_allowed_methods,
    get_allowed_origins,
    get_exposed_headers,
    install_security_middleware,
    should_allow_credentials,
)
from app.core.settings import Settings


def _build_app(settings: Settings) -> FastAPI:
    app = FastAPI()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/dashboard/overview")
    def dashboard_overview(
        _: str | None = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/integrations/token")
    def integrations_token(
        _: str | None = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/ui/billing/payment-methods")
    def payment_methods(
        _: str | None = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/billing/checkout/sessions")
    def checkout_sessions(
        _: str | None = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/events/simulate")
    def events_simulate(
        _: str | None = Depends(require_api_key),
    ) -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/protected")
    def protected(_: str | None = Depends(require_api_key)) -> dict[str, str]:
        return {"status": "ok"}

    install_security_middleware(app, settings)
    app.state.settings = settings
    return app


def _build_production_like_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "ALLOWED_ORIGINS": "https://moving-forward.ca,https://www.moving-forward.ca",
        "TRUSTED_HOSTS": "testserver,moving-forward.ca,[www.moving-forward.ca](https://www.moving-forward.ca),ironclaw-security-production.up.railway.app",
        "AUTH_REQUIRED": True,
        "API_KEY": "test-api-key",
        "CORS_ALLOWED_METHODS": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "CORS_ALLOWED_HEADERS": "Authorization,Content-Type,X-API-Key,X-Request-ID",
        "CORS_EXPOSE_HEADERS": "X-Request-ID,X-Trace-ID",
    }
    values.update(overrides)
    return Settings(**values)


def _assert_preflight_ok(
    client: TestClient,
    path: str,
    *,
    method: str,
    request_headers: str,
) -> None:
    response = client.options(
        path,
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": request_headers,
        },
    )

    assert response.status_code == 200, f"expected HTTP 200 preflight for {path}, got {response.status_code}: {response.text}"
    assert response.headers["access-control-allow-origin"] == "https://moving-forward.ca"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert "access-control-allow-methods" in response.headers
    assert "access-control-allow-headers" in response.headers
    assert method in response.headers["access-control-allow-methods"]


def test_csv_to_list_returns_default_for_none() -> None:
    assert _csv_to_list(None, default=["a", "b"]) == ["a", "b"]


def test_csv_to_list_parses_csv_and_drops_empty_items() -> None:
    assert _csv_to_list("https://a.com, ,https://b.com", default=["fallback"]) == [
        "https://a.com",
        "https://b.com",
    ]


def test_csv_to_list_returns_default_for_blank_string() -> None:
    assert _csv_to_list("   ", default=["fallback"]) == ["fallback"]


def test_coerce_list_returns_default_for_none() -> None:
    assert _coerce_list(None, default=["fallback"]) == ["fallback"]


def test_coerce_list_parses_string_values() -> None:
    assert _coerce_list("GET, POST", default=["fallback"]) == ["GET", "POST"]


def test_coerce_list_parses_iterables() -> None:
    assert _coerce_list([" GET ", "", "POST", "POST"], default=["fallback"]) == [
        "GET",
        "POST",
        "POST",
    ]


def test_coerce_list_returns_default_for_non_iterable() -> None:
    assert _coerce_list(123, default=["fallback"]) == ["fallback"]


def test_normalize_unique_deduplicates_case_insensitively() -> None:
    assert _normalize_unique(["GET", "get", " POST ", "", "post", "PATCH"]) == [
        "GET",
        "POST",
        "PATCH",
    ]


def test_get_allowed_origins_prefers_primary_allowed_origins_over_legacy_when_primary_present() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca, https://www.moving-forward.ca",
        CORS_ORIGINS="https://preview.pages.dev",
    )

    allowed_origins = get_allowed_origins(settings)

    assert "https://moving-forward.ca" in allowed_origins
    assert "https://www.moving-forward.ca" in allowed_origins
    assert "https://preview.pages.dev" not in allowed_origins


def test_get_allowed_origins_uses_legacy_cors_origins_when_primary_is_empty() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="",
        CORS_ORIGINS="https://moving-forward.ca, https://preview.pages.dev",
    )

    allowed_origins = get_allowed_origins(settings)

    assert "https://moving-forward.ca" in allowed_origins
    assert "https://preview.pages.dev" in allowed_origins


def test_get_allowed_origins_ignores_base_urls_when_not_supported_by_settings_contract() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="",
        CORS_ORIGINS="",
        APP_BASE_URL="https://api.moving-forward.ca",
        ENGINE_BASE_URL="https://engine.moving-forward.ca",
    )

    allowed_origins = get_allowed_origins(settings)

    assert "https://api.moving-forward.ca" not in allowed_origins
    assert "https://engine.moving-forward.ca" not in allowed_origins
    assert "http://localhost" in allowed_origins


def test_get_allowed_origins_falls_back_to_localhost_when_empty() -> None:
    settings = Settings(ALLOWED_ORIGINS="", CORS_ORIGINS="", ENVIRONMENT="development")

    allowed_origins = get_allowed_origins(settings)

    assert "http://localhost" in allowed_origins


def test_get_allowed_origins_does_not_append_localhost_in_production() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        CORS_ORIGINS="",
        ENVIRONMENT="production",
    )

    allowed_origins = get_allowed_origins(settings)

    assert allowed_origins == ["https://moving-forward.ca"]


def test_get_allowed_methods_uses_defaults() -> None:
    settings = Settings()
    assert get_allowed_methods(settings) == _DEFAULT_ALLOWED_METHODS


def test_get_allowed_methods_uses_configured_values() -> None:
    settings = Settings(CORS_ALLOWED_METHODS="GET,POST,OPTIONS,post")
    assert get_allowed_methods(settings) == ["GET", "POST", "OPTIONS"]


def test_get_allowed_methods_appends_options_when_missing() -> None:
    settings = Settings(CORS_ALLOWED_METHODS="GET,POST")
    assert get_allowed_methods(settings) == ["GET", "POST", "OPTIONS"]


def test_get_allowed_headers_uses_defaults() -> None:
    settings = Settings()
    assert get_allowed_headers(settings) == _DEFAULT_ALLOWED_HEADERS


def test_get_allowed_headers_uses_configured_values_and_keeps_required_defaults() -> None:
    settings = Settings(
        CORS_ALLOWED_HEADERS="Authorization, Content-Type, X-API-Key, authorization",
    )
    assert get_allowed_headers(settings) == [
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-Request-ID",
    ]


def test_get_allowed_headers_preserves_explicit_request_id_header() -> None:
    settings = Settings(
        CORS_ALLOWED_HEADERS="Authorization, Content-Type, X-API-Key, X-Request-ID",
    )
    assert get_allowed_headers(settings) == [
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-Request-ID",
    ]


def test_get_exposed_headers_uses_defaults() -> None:
    settings = Settings()
    assert get_exposed_headers(settings) == _DEFAULT_EXPOSE_HEADERS


def test_get_exposed_headers_uses_configured_values() -> None:
    settings = Settings(CORS_EXPOSE_HEADERS="X-Request-ID, X-Trace-ID, x-request-id")
    assert get_exposed_headers(settings) == ["X-Request-ID", "X-Trace-ID"]


def test_get_allowed_hosts_uses_effective_trusted_hosts() -> None:
    settings = Settings(
        TRUSTED_HOSTS="moving-forward.ca,[www.moving-forward.ca](https://www.moving-forward.ca),moving-forward.ca",
    )
    assert get_allowed_hosts(settings) == [
        "moving-forward.ca",
        "www.moving-forward.ca",
    ]


def test_get_allowed_hosts_derives_from_allowed_origins_and_base_urls() -> None:
    settings = Settings(
        TRUSTED_HOSTS="",
        ALLOWED_ORIGINS="https://moving-forward.ca,https://www.moving-forward.ca",
        APP_BASE_URL="https://api.moving-forward.ca",
        ENGINE_BASE_URL="https://engine.moving-forward.ca",
    )
    assert get_allowed_hosts(settings) == [
        "moving-forward.ca",
        "www.moving-forward.ca",
        "api.moving-forward.ca",
        "engine.moving-forward.ca",
    ]


def test_should_allow_credentials_rejects_explicit_true_for_wildcard_origin() -> None:
    settings = Settings(CORS_ALLOW_CREDENTIALS=True)
    assert should_allow_credentials(settings, ["*"]) is False


def test_should_allow_credentials_returns_explicit_setting_false() -> None:
    settings = Settings(CORS_ALLOW_CREDENTIALS=False)
    assert should_allow_credentials(settings, ["https://moving-forward.ca"]) is False


def test_should_allow_credentials_defaults_false_for_wildcard_origin() -> None:
    settings = Settings()
    assert should_allow_credentials(settings, ["*"]) is False


def test_should_allow_credentials_defaults_true_for_specific_origins() -> None:
    settings = Settings()
    assert should_allow_credentials(settings, ["https://moving-forward.ca"]) is True


def test_install_security_middleware_applies_security_headers() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
    )
    client = TestClient(_build_app(settings))

    response = client.get("/health", headers={"Origin": "https://moving-forward.ca"})

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Permissions-Policy"] == "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    assert response.headers["Content-Security-Policy"] == _DEFAULT_CSP
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"


def test_install_security_middleware_omits_cross_origin_isolation_headers_on_options_preflight() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        CORS_ALLOWED_METHODS="GET,POST,OPTIONS",
        CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-API-Key",
    )
    client = TestClient(_build_app(settings))

    response = client.options(
        "/protected",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key,Content-Type",
        },
    )

    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers
    assert "Cross-Origin-Opener-Policy" not in response.headers
    assert "Cross-Origin-Resource-Policy" not in response.headers
    assert "Cross-Origin-Embedder-Policy" not in response.headers


def test_install_security_middleware_applies_hsts_for_https_requests() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        ENABLE_HSTS=True,
    )
    client = TestClient(_build_app(settings), base_url="https://testserver")

    response = client.get("/health", headers={"Origin": "https://moving-forward.ca"})

    assert response.status_code == 200
    assert response.headers["Strict-Transport-Security"] == "max-age=63072000; includeSubDomains"


def test_install_security_middleware_omits_hsts_for_http_requests() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        ENABLE_HSTS=True,
    )
    client = TestClient(_build_app(settings), base_url="http://testserver")

    response = client.get("/health", headers={"Origin": "https://moving-forward.ca"})

    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers


def test_install_security_middleware_omits_hsts_when_disabled() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        ENABLE_HSTS=False,
    )
    client = TestClient(_build_app(settings), base_url="https://testserver")

    response = client.get("/health", headers={"Origin": "https://moving-forward.ca"})

    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers


def test_install_security_middleware_uses_custom_csp_when_configured() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        CONTENT_SECURITY_POLICY="default-src 'self'; connect-src 'self' https://moving-forward.ca",
    )
    client = TestClient(_build_app(settings))

    response = client.get("/health", headers={"Origin": "https://moving-forward.ca"})

    assert response.status_code == 200
    assert response.headers["Content-Security-Policy"] == "default-src 'self'; connect-src 'self' https://moving-forward.ca"


def test_install_security_middleware_uses_default_csp_for_blank_custom_value() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        CONTENT_SECURITY_POLICY="   ",
    )
    client = TestClient(_build_app(settings))

    response = client.get("/health", headers={"Origin": "https://moving-forward.ca"})

    assert response.status_code == 200
    assert response.headers["Content-Security-Policy"] == _DEFAULT_CSP


def test_install_security_middleware_sets_cors_headers_for_allowed_origin() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca,https://www.moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        CORS_ALLOWED_METHODS="GET,POST,OPTIONS",
        CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-API-Key",
        CORS_EXPOSE_HEADERS="X-Request-ID,X-Trace-ID",
    )
    client = TestClient(_build_app(settings))

    response = client.options(
        "/health",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type,X-API-Key",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://moving-forward.ca"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["access-control-allow-methods"] == "GET, POST, OPTIONS"
    assert response.headers["access-control-allow-headers"] == "Accept, Accept-Language, Authorization, Content-Language, Content-Type, X-API-Key, X-Request-ID"

    get_response = client.get(
        "/health",
        headers={"Origin": "https://moving-forward.ca"},
    )
    assert get_response.headers["access-control-allow-origin"] == "https://moving-forward.ca"
    assert get_response.headers["access-control-expose-headers"] == "X-Request-ID, X-Trace-ID"


def test_install_security_middleware_respects_explicit_credentials_false() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        CORS_ALLOW_CREDENTIALS=False,
    )
    client = TestClient(_build_app(settings))

    response = client.options(
        "/health",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert "access-control-allow-credentials" not in response.headers


def test_install_security_middleware_rejects_browser_invalid_wildcard_credentials_config() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="*",
        TRUSTED_HOSTS="testserver",
        CORS_ALLOW_CREDENTIALS=True,
    )
    client = TestClient(_build_app(settings))

    response = client.options(
        "/health",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 400 or "access-control-allow-credentials" not in response.headers


def test_preflight_to_protected_route_returns_200_without_api_key() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        AUTH_REQUIRED=True,
        API_KEY="test-api-key",
        CORS_ALLOWED_METHODS="GET,POST,OPTIONS",
        CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-API-Key",
    )
    client = TestClient(_build_app(settings))

    response = client.options(
        "/protected",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key,Content-Type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://moving-forward.ca"
    assert response.headers["access-control-allow-methods"] == "GET, POST, OPTIONS"
    assert "access-control-allow-headers" in response.headers


def test_post_to_protected_route_requires_api_key_after_successful_preflight() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        AUTH_REQUIRED=True,
        API_KEY="test-api-key",
        CORS_ALLOWED_METHODS="GET,POST,OPTIONS",
        CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-API-Key",
    )
    client = TestClient(_build_app(settings))

    preflight = client.options(
        "/protected",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key,Content-Type",
        },
    )
    assert preflight.status_code == 200

    response = client.post(
        "/protected",
        headers={"Origin": "https://moving-forward.ca"},
    )

    assert response.status_code == 401


def test_preflight_to_protected_route_is_not_blocked_by_auth_dependency_when_bearer_requested() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        AUTH_REQUIRED=True,
        JWT_SECRET="test-jwt-secret",
        CORS_ALLOWED_METHODS="GET,POST,OPTIONS",
        CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-API-Key",
    )
    client = TestClient(_build_app(settings))

    response = client.options(
        "/protected",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://moving-forward.ca"
    assert "access-control-allow-headers" in response.headers


def test_preflight_disallowed_origin_is_rejected_for_protected_route() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        AUTH_REQUIRED=True,
        API_KEY="test-api-key",
        CORS_ALLOWED_METHODS="GET,POST,OPTIONS",
        CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-API-Key",
    )
    client = TestClient(_build_app(settings))

    response = client.options(
        "/protected",
        headers={
            "Origin": "https://untrusted.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key,Content-Type",
        },
    )

    assert response.status_code == 400


def test_install_security_middleware_blocks_untrusted_host() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="moving-forward.ca",
    )
    client = TestClient(_build_app(settings), base_url="https://moving-forward.ca")

    response = client.get(
        "/health",
        headers={"host": "untrusted.example.com"},
    )

    assert response.status_code == 400


def test_preflight_to_affected_api_endpoints_returns_http_ok_for_moving_forward_origin() -> None:
    settings = _build_production_like_settings()
    client = TestClient(_build_app(settings))

    affected_requests = [
        ("/api/integrations/token", "POST", "X-API-Key,Content-Type"),
        ("/api/dashboard/overview", "GET", "X-API-Key,Content-Type"),
        ("/api/ui/billing/payment-methods?organizationid=org-001", "GET", "X-API-Key,Content-Type"),
        ("/api/billing/checkout/sessions", "POST", "X-API-Key,Content-Type"),
        ("/api/events/simulate", "POST", "X-API-Key,Content-Type"),
    ]

    for path, method, request_headers in affected_requests:
        _assert_preflight_ok(
            client,
            path,
            method=method,
            request_headers=request_headers,
        )


def test_preflight_to_checkout_payment_route_allows_request_id_header() -> None:
    settings = _build_production_like_settings()
    client = TestClient(_build_app(settings))

    response = client.options(
        "/api/billing/checkout/sessions",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type,X-API-Key,X-Request-ID",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://moving-forward.ca"
    assert "X-Request-ID" in response.headers["access-control-allow-headers"]


def test_preflight_to_affected_api_endpoints_does_not_include_isolation_headers() -> None:
    settings = _build_production_like_settings()
    client = TestClient(_build_app(settings))

    affected_requests = [
        ("/api/integrations/token", "POST"),
        ("/api/dashboard/overview", "GET"),
        ("/api/ui/billing/payment-methods?organizationid=org-001", "GET"),
        ("/api/billing/checkout/sessions", "POST"),
        ("/api/events/simulate", "POST"),
    ]

    for path, method in affected_requests:
        response = client.options(
            path,
            headers={
                "Origin": "https://moving-forward.ca",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "X-API-Key,Content-Type",
            },
        )
        assert response.status_code == 200
        assert "Content-Security-Policy" not in response.headers
        assert "Cross-Origin-Opener-Policy" not in response.headers
        assert "Cross-Origin-Resource-Policy" not in response.headers
        assert "Cross-Origin-Embedder-Policy" not in response.headers


def test_requests_to_affected_api_endpoints_still_require_auth_after_successful_preflight() -> None:
    settings = _build_production_like_settings()
    client = TestClient(_build_app(settings))

    preflight_paths = [
        ("/api/integrations/token", "POST"),
        ("/api/dashboard/overview", "GET"),
        ("/api/ui/billing/payment-methods?organizationid=org-001", "GET"),
        ("/api/billing/checkout/sessions", "POST"),
        ("/api/events/simulate", "POST"),
    ]

    for path, method in preflight_paths:
        _assert_preflight_ok(
            client,
            path,
            method=method,
            request_headers="X-API-Key,Content-Type",
        )

    response = client.post(
        "/api/integrations/token",
        headers={"Origin": "https://moving-forward.ca"},
    )
    assert response.status_code == 401

    response = client.get(
        "/api/dashboard/overview",
        headers={"Origin": "https://moving-forward.ca"},
    )
    assert response.status_code == 401

    response = client.get(
        "/api/ui/billing/payment-methods?organizationid=org-001",
        headers={"Origin": "https://moving-forward.ca"},
    )
    assert response.status_code == 401

    response = client.post(
        "/api/billing/checkout/sessions",
        headers={"Origin": "https://moving-forward.ca"},
    )
    assert response.status_code == 401

    response = client.post(
        "/api/events/simulate",
        headers={"Origin": "https://moving-forward.ca"},
    )
    assert response.status_code == 401


def test_preflight_to_affected_api_endpoints_is_rejected_for_untrusted_origin() -> None:
    settings = _build_production_like_settings()
    client = TestClient(_build_app(settings))

    affected_paths = [
        ("/api/integrations/token", "POST"),
        ("/api/dashboard/overview", "GET"),
        ("/api/ui/billing/payment-methods?organizationid=org-001", "GET"),
        ("/api/billing/checkout/sessions", "POST"),
        ("/api/events/simulate", "POST"),
    ]

    for path, method in affected_paths:
        response = client.options(
            path,
            headers={
                "Origin": "https://untrusted.example.com",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "X-API-Key,Content-Type",
            },
        )
        assert response.status_code == 400
