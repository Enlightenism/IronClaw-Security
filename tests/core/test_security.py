from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

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

    install_security_middleware(app, settings)
    return app


def test_csv_to_list_returns_default_for_none() -> None:
    assert _csv_to_list(None, default=["a", "b"]) == ["a", "b"]


def test_csv_to_list_parses_csv_and_drops_empty_items() -> None:
    assert _csv_to_list("  https://a.com, ,https://b.com  ", default=["fallback"]) == [
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


def test_get_allowed_origins_uses_effective_allowed_origins() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca, https://www.moving-forward.ca",
        CORS_ORIGINS="https://moving-forward.ca, https://preview.pages.dev",
    )

    assert get_allowed_origins(settings) == [
        "https://moving-forward.ca",
        "https://www.moving-forward.ca",
        "https://preview.pages.dev",
    ]


def test_get_allowed_origins_falls_back_to_localhost_when_empty() -> None:
    settings = Settings(ALLOWED_ORIGINS="", CORS_ORIGINS="")
    assert get_allowed_origins(settings) == ["http://localhost"]


def test_get_allowed_methods_uses_defaults() -> None:
    settings = Settings()
    assert get_allowed_methods(settings) == _DEFAULT_ALLOWED_METHODS


def test_get_allowed_methods_uses_configured_values() -> None:
    settings = Settings(CORS_ALLOWED_METHODS="GET,POST,OPTIONS,post")
    assert get_allowed_methods(settings) == ["GET", "POST", "OPTIONS"]


def test_get_allowed_headers_uses_defaults() -> None:
    settings = Settings()
    assert get_allowed_headers(settings) == _DEFAULT_ALLOWED_HEADERS


def test_get_allowed_headers_uses_configured_values() -> None:
    settings = Settings(
        CORS_ALLOWED_HEADERS="Authorization, Content-Type, X-API-Key, authorization",
    )
    assert get_allowed_headers(settings) == [
        "Authorization",
        "Content-Type",
        "X-API-Key",
    ]


def test_get_exposed_headers_uses_defaults() -> None:
    settings = Settings()
    assert get_exposed_headers(settings) == _DEFAULT_EXPOSE_HEADERS


def test_get_exposed_headers_uses_configured_values() -> None:
    settings = Settings(CORS_EXPOSE_HEADERS="X-Request-ID, X-Trace-ID, x-request-id")
    assert get_exposed_headers(settings) == ["X-Request-ID", "X-Trace-ID"]


def test_get_allowed_hosts_uses_effective_trusted_hosts() -> None:
    settings = Settings(
        TRUSTED_HOSTS="moving-forward.ca,www.moving-forward.ca,moving-forward.ca",
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


def test_should_allow_credentials_returns_explicit_setting_true() -> None:
    settings = Settings(CORS_ALLOW_CREDENTIALS=True)
    assert should_allow_credentials(settings, ["*"]) is True


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
    assert response.headers["Permissions-Policy"] == ("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
    assert response.headers["Content-Security-Policy"] == _DEFAULT_CSP
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"


def test_install_security_middleware_applies_hsts_for_https_requests() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="testserver",
        ENABLE_HSTS=True,
    )
    client = TestClient(_build_app(settings), base_url="https://testserver")

    response = client.get("/health", headers={"Origin": "https://moving-forward.ca"})

    assert response.status_code == 200
    assert response.headers["Strict-Transport-Security"] == ("max-age=63072000; includeSubDomains")


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
    assert response.headers["Content-Security-Policy"] == ("default-src 'self'; connect-src 'self' https://moving-forward.ca")


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
    assert response.headers["access-control-allow-headers"] == ("Accept, Accept-Language, Authorization, Content-Language, Content-Type, X-API-Key")

    get_response = client.get(
        "/health",
        headers={"Origin": "https://moving-forward.ca"},
    )
    assert get_response.headers["access-control-allow-origin"] == "https://moving-forward.ca"
    assert get_response.headers["access-control-expose-headers"] == ("X-Request-ID, X-Trace-ID")


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


def test_install_security_middleware_blocks_untrusted_host() -> None:
    settings = Settings(
        ALLOWED_ORIGINS="https://moving-forward.ca",
        TRUSTED_HOSTS="moving-forward.ca",
    )
    client = TestClient(_build_app(settings), base_url="https://moving-forward.ca")

    response = client.get(
        "/health",
        headers={"host": "evil.example.com"},
    )

    assert response.status_code == 400
