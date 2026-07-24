from __future__ import annotations

from collections.abc import Iterable, Sequence
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.settings import Settings

_DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; script-src 'self'; object-src 'none'"
_DEFAULT_ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_DEFAULT_ALLOWED_HEADERS = [
    "Authorization",
    "Content-Type",
    "X-API-Key",
    "X-Request-ID",
]
_DEFAULT_EXPOSE_HEADERS = ["X-Request-ID"]
_DEFAULT_LOCAL_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]


class SecurityHeadersMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        include_hsts: bool = True,
        csp: str | None = None,
    ) -> None:
        self.app = app
        self.include_hsts = include_hsts
        self.csp = (csp or _DEFAULT_CSP).strip()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "")).upper()
        scheme = str(scope.get("scheme", "")).lower()

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message["headers"])
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault(
                    "Permissions-Policy",
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
                )

                if method != "OPTIONS":
                    headers.setdefault("Content-Security-Policy", self.csp)
                    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
                    headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
                    headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")

                if self.include_hsts and scheme == "https":
                    headers.setdefault(
                        "Strict-Transport-Security",
                        "max-age=63072000; includeSubDomains",
                    )

            await send(message)

        await self.app(scope, receive, send_with_security_headers)


def _strip_wrappers(value: str) -> str:
    cleaned = value.strip().strip("\"'").strip()

    if cleaned.startswith("[") and "](" in cleaned and cleaned.endswith(")"):
        cleaned = cleaned[cleaned.index("](") + 2 : -1].strip()

    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()

    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1].strip()

    return cleaned.strip().strip("\"'").strip()


def _clean_token(value: str) -> str:
    return _strip_wrappers(value)


def _clean_origin_token(value: str) -> str:
    cleaned = _strip_wrappers(value)
    if cleaned == "*":
        return "*"

    parsed = urlparse(cleaned)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    return cleaned


def _clean_host_token(value: str) -> str:
    cleaned = _strip_wrappers(value)
    parsed = urlparse(cleaned)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return parsed.netloc.strip().lower()
    return cleaned.strip().lower()


def _csv_to_list(value: str | None, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    parsed = [_clean_origin_token(item) for item in value.split(",")]
    normalized = [item for item in parsed if item]
    return normalized or list(default)


def _coerce_list(value: object, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        return _csv_to_list(value, default=default)
    if isinstance(value, Iterable):
        parsed: list[str] = []
        for item in value:
            text = _clean_token(str(item))
            if text:
                parsed.append(text)
        return parsed or list(default)
    return list(default)


def _coerce_host_list(value: object, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        parsed = [_clean_host_token(item) for item in value.split(",")]
        normalized = [item for item in parsed if item]
        return normalized or list(default)
    if isinstance(value, Iterable):
        parsed: list[str] = []
        for item in value:
            text = _clean_host_token(str(item))
            if text:
                parsed.append(text)
        return parsed or list(default)
    return list(default)


def _normalize_unique(values: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = value.strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    return normalized


def _normalize_methods(values: Sequence[str]) -> list[str]:
    return _normalize_unique([value.upper() for value in values])


def _normalize_headers(values: Sequence[str]) -> list[str]:
    return _normalize_unique(values)


def _is_valid_origin(value: str) -> bool:
    if value == "*":
        return True
    parsed = urlparse(value)
    return bool(parsed.scheme in {"http", "https"} and parsed.netloc)


def _origin_to_host(origin: str) -> str:
    parsed = urlparse(origin)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return parsed.netloc.strip().lower()
    return ""


def _append_local_origins(origins: Sequence[str], settings: Settings) -> list[str]:
    environment = str(getattr(settings, "environment", "") or "").strip().lower()
    if environment == "production":
        return list(origins)
    return _normalize_unique([*origins, *_DEFAULT_LOCAL_ORIGINS])


def _is_local_origin(origin: str) -> bool:
    return origin in _DEFAULT_LOCAL_ORIGINS


def _is_local_host(host: str) -> bool:
    return host in {
        "localhost",
        "localhost:3000",
        "localhost:5173",
        "127.0.0.1",
        "127.0.0.1:3000",
        "127.0.0.1:5173",
        "testserver",
    }


def get_allowed_origins(settings: Settings) -> list[str]:
    primary = getattr(settings, "ALLOWED_ORIGINS", None)
    if primary is None:
        primary = getattr(settings, "allowed_origins", None)
    if primary is None:
        primary = getattr(settings, "effective_allowed_origins", None)

    legacy = getattr(settings, "CORS_ORIGINS", None)
    if legacy is None:
        legacy = getattr(settings, "cors_origins", None)

    raw_primary = _coerce_list(primary, default=[])
    raw_legacy = _coerce_list(legacy, default=[])

    primary_origins = _normalize_unique([origin for origin in raw_primary if _is_valid_origin(origin)])
    legacy_origins = _normalize_unique([origin for origin in raw_legacy if _is_valid_origin(origin)])

    selected = primary_origins if primary_origins else legacy_origins
    if not selected:
        selected = ["http://localhost"]

    return _append_local_origins(selected, settings) or ["http://localhost"]


def get_allowed_methods(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_allowed_methods", None)
    if raw is None:
        raw = getattr(settings, "CORS_ALLOWED_METHODS", None)
    methods = _coerce_list(raw, default=_DEFAULT_ALLOWED_METHODS)
    return _normalize_methods(methods)


def get_allowed_headers(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_allowed_headers", None)
    if raw is None:
        raw = getattr(settings, "CORS_ALLOWED_HEADERS", None)
    headers = _coerce_list(raw, default=_DEFAULT_ALLOWED_HEADERS)
    normalized = _normalize_headers(headers)
    if "*" in normalized:
        return ["*"]
    return normalized


def get_exposed_headers(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_expose_headers", None)
    if raw is None:
        raw = getattr(settings, "CORS_EXPOSE_HEADERS", None)
    headers = _coerce_list(raw, default=_DEFAULT_EXPOSE_HEADERS)
    return _normalize_headers(headers)


def get_allowed_hosts(settings: Settings) -> list[str]:
    raw = getattr(settings, "TRUSTED_HOSTS", None)
    if raw is None:
        raw = getattr(settings, "trusted_hosts", None)
    if raw is None:
        raw = getattr(settings, "effective_trusted_hosts", None)

    hosts = _coerce_host_list(raw, default=[])
    normalized_hosts = _normalize_unique(hosts)
    if normalized_hosts and normalized_hosts != ["*"]:
        return normalized_hosts

    derived_hosts: list[str] = []

    for origin in get_allowed_origins(settings):
        host = _origin_to_host(origin)
        if host and not _is_local_host(host):
            derived_hosts.append(host)

    for attr in (
        "APP_BASE_URL",
        "app_base_url",
        "ENGINE_BASE_URL",
        "engine_base_url",
    ):
        value = getattr(settings, attr, None)
        if isinstance(value, str) and value.strip():
            host = _origin_to_host(value.strip())
            if host and not _is_local_host(host):
                derived_hosts.append(host)

    return _normalize_unique(derived_hosts) or ["*"]


def should_allow_credentials(settings: Settings, origins: Sequence[str]) -> bool:
    raw = getattr(settings, "cors_allow_credentials", None)
    if raw is None:
        raw = getattr(settings, "CORS_ALLOW_CREDENTIALS", None)
    if isinstance(raw, bool):
        return raw
    return "*" not in origins


def install_security_middleware(app: FastAPI, settings: Settings) -> None:
    origins = get_allowed_origins(settings)
    methods = get_allowed_methods(settings)
    headers = get_allowed_headers(settings)
    exposed_headers = get_exposed_headers(settings)
    hosts = get_allowed_hosts(settings)
    allow_credentials = should_allow_credentials(settings, origins)

    if allow_credentials:
        methods = [method for method in methods if method != "*"] or list(_DEFAULT_ALLOWED_METHODS)
        headers = [header for header in headers if header != "*"] or list(_DEFAULT_ALLOWED_HEADERS)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=methods,
        allow_headers=headers,
        expose_headers=exposed_headers,
        max_age=3600,
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=hosts,
    )

    include_hsts = bool(getattr(settings, "enable_hsts", getattr(settings, "ENABLE_HSTS", True)))
    csp = getattr(settings, "content_security_policy", None)
    if csp is None:
        csp = getattr(settings, "CONTENT_SECURITY_POLICY", None)
    normalized_csp = csp.strip() if isinstance(csp, str) and csp.strip() else None

    app.add_middleware(
        SecurityHeadersMiddleware,
        include_hsts=include_hsts,
        csp=normalized_csp,
    )
