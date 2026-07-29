from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.settings import Settings

_DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; script-src 'self'; object-src 'none'; manifest-src 'self'"
_DEFAULT_ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_DEFAULT_ALLOWED_HEADERS = [
    "Authorization",
    "Content-Type",
    "X-API-Key",
    "X-Org-Id",
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
_SECURITY_MIDDLEWARE_INSTALLED_FLAG = "_ironclaw_security_middleware_installed"
_PRODUCTION_REQUIRED_ORIGINS = [
    "https://moving-forward.ca",
    "https://www.moving-forward.ca",
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

        header_names = {key.decode("latin-1").lower() for key, _ in scope.get("headers", []) if isinstance(key, (bytes, bytearray))}
        is_preflight = method == "OPTIONS" and "origin" in header_names and "access-control-request-method" in header_names

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

                if not is_preflight:
                    headers.setdefault("Content-Security-Policy", self.csp)

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
    if not cleaned:
        return ""
    if cleaned == "*":
        return "*"

    parsed = urlparse(cleaned)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    return ""


def _clean_host_token(value: str) -> str:
    cleaned = _strip_wrappers(value)
    if not cleaned:
        return ""
    if cleaned == "*":
        return "*"

    parsed = urlparse(cleaned)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        cleaned = parsed.netloc

    cleaned = cleaned.strip().strip("/").lower()

    if cleaned.startswith("*."):
        return cleaned

    if ":" in cleaned and not cleaned.startswith("["):
        host, _, port = cleaned.partition(":")
        if port.isdigit():
            return host

    return cleaned


def _coerce_csv_list(
    value: str | None,
    *,
    default: Sequence[str],
    cleaner: Callable[[str], str],
) -> list[str]:
    if value is None:
        return list(default)
    parsed = [cleaner(item) for item in value.split(",")]
    normalized = [item for item in parsed if item]
    return normalized or list(default)


def _csv_to_list(value: str | None, *, default: Sequence[str]) -> list[str]:
    return _coerce_csv_list(value, default=default, cleaner=_clean_origin_token)


def _coerce_list(value: object, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        return _coerce_csv_list(value, default=default, cleaner=_clean_token)
    if isinstance(value, Iterable):
        parsed: list[str] = []
        for item in value:
            text = _clean_token(str(item))
            if text:
                parsed.append(text)
        return parsed or list(default)
    return list(default)


def _coerce_origin_list(value: object, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        return _coerce_csv_list(value, default=default, cleaner=_clean_origin_token)
    if isinstance(value, Iterable):
        parsed: list[str] = []
        for item in value:
            text = _clean_origin_token(str(item))
            if text:
                parsed.append(text)
        return parsed or list(default)
    return list(default)


def _coerce_host_list(value: object, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        return _coerce_csv_list(value, default=default, cleaner=_clean_host_token)
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


def _origin_to_host(origin: str) -> str:
    parsed = urlparse(origin)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return _clean_host_token(parsed.netloc)
    return ""


def _environment_name(settings: Settings) -> str:
    return (
        str(
            getattr(settings, "environment", getattr(settings, "ENVIRONMENT", "")) or "",
        )
        .strip()
        .lower()
    )


def _append_local_origins(origins: Sequence[str], settings: Settings) -> list[str]:
    base = _normalize_unique(origins)
    if _environment_name(settings) == "production":
        return base
    return _normalize_unique([*base, *_DEFAULT_LOCAL_ORIGINS])


def _append_required_production_origins(origins: Sequence[str], settings: Settings) -> list[str]:
    normalized = _normalize_unique(origins)
    if _environment_name(settings) != "production":
        return normalized
    return _normalize_unique([*normalized, *_PRODUCTION_REQUIRED_ORIGINS])


def _is_local_host(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "0.0.0.0", "testserver"}


def _parse_bool(value: object, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _is_effectively_empty(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return _strip_wrappers(value) == ""
    return False


def _first_non_empty(*values: object) -> object:
    for value in values:
        if not _is_effectively_empty(value):
            return value
    return None


def _derived_base_origins(settings: Settings) -> list[str]:
    derived: list[str] = []

    for attr in (
        "APP_BASE_URL",
        "app_base_url",
        "ENGINE_BASE_URL",
        "engine_base_url",
        "IRONCLAW_BASE_URL",
        "ironclaw_base_url",
    ):
        value = getattr(settings, attr, None)
        if value is None:
            continue
        origin = _clean_origin_token(str(value))
        if origin:
            derived.append(origin)

    return _normalize_unique(derived)


def get_allowed_origins(settings: Settings) -> list[str]:
    effective = getattr(settings, "effective_allowed_origins", None)
    if isinstance(effective, list):
        normalized_effective = _normalize_unique(
            [item for item in (_clean_origin_token(str(value)) for value in effective) if item],
        )
        normalized_effective = _append_required_production_origins(normalized_effective, settings)
        if normalized_effective:
            return _append_local_origins(normalized_effective, settings)
        if _environment_name(settings) == "production":
            return list(_PRODUCTION_REQUIRED_ORIGINS)
        return list(_DEFAULT_LOCAL_ORIGINS)

    primary_raw = _first_non_empty(
        getattr(settings, "allowed_origins", None),
        getattr(settings, "ALLOWED_ORIGINS", None),
    )
    legacy_raw = _first_non_empty(
        getattr(settings, "cors_origins", None),
        getattr(settings, "CORS_ORIGINS", None),
    )

    primary_origins = _normalize_unique(_coerce_origin_list(primary_raw, default=[]))
    legacy_origins = _normalize_unique(_coerce_origin_list(legacy_raw, default=[]))
    configured_origins = _normalize_unique([*primary_origins, *legacy_origins])
    configured_origins = _append_required_production_origins(configured_origins, settings)

    if configured_origins:
        return _append_local_origins(configured_origins, settings)

    derived_origins = _append_required_production_origins(_derived_base_origins(settings), settings)
    if derived_origins:
        return _append_local_origins(derived_origins, settings)

    if _environment_name(settings) == "production":
        return list(_PRODUCTION_REQUIRED_ORIGINS)
    return list(_DEFAULT_LOCAL_ORIGINS)


def get_allowed_methods(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_allowed_methods", None)
    if raw is None:
        raw = getattr(settings, "CORS_ALLOWED_METHODS", None)
    methods = _coerce_list(raw, default=_DEFAULT_ALLOWED_METHODS)
    normalized = _normalize_methods(methods)
    if "*" in normalized:
        return ["*"]
    if "OPTIONS" not in normalized:
        normalized.append("OPTIONS")
    return _normalize_methods(normalized) or list(_DEFAULT_ALLOWED_METHODS)


def get_allowed_headers(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_allowed_headers", None)
    if raw is None:
        raw = getattr(settings, "CORS_ALLOWED_HEADERS", None)
    headers = _coerce_list(raw, default=_DEFAULT_ALLOWED_HEADERS)
    normalized = _normalize_headers(headers)
    if "*" in normalized:
        return ["*"]

    required_headers = _normalize_headers(_DEFAULT_ALLOWED_HEADERS)
    return _normalize_headers([*normalized, *required_headers]) or list(_DEFAULT_ALLOWED_HEADERS)


def get_exposed_headers(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_expose_headers", None)
    if raw is None:
        raw = getattr(settings, "CORS_EXPOSE_HEADERS", None)
    headers = _coerce_list(raw, default=_DEFAULT_EXPOSE_HEADERS)
    normalized = _normalize_headers(headers)
    return normalized or list(_DEFAULT_EXPOSE_HEADERS)


def get_allowed_hosts(settings: Settings) -> list[str]:
    raw = _first_non_empty(
        getattr(settings, "TRUSTED_HOSTS", None),
        getattr(settings, "trusted_hosts", None),
        getattr(settings, "effective_trusted_hosts", None),
    )

    hosts = _coerce_host_list(raw, default=[])
    normalized_hosts = _normalize_unique(hosts)
    if normalized_hosts:
        if "*" in normalized_hosts:
            return ["*"]
        return normalized_hosts

    derived_hosts: list[str] = []

    for origin in get_allowed_origins(settings):
        host = _origin_to_host(origin)
        if host:
            derived_hosts.append(host)

    for attr in (
        "APP_BASE_URL",
        "app_base_url",
        "ENGINE_BASE_URL",
        "engine_base_url",
        "IRONCLAW_BASE_URL",
        "ironclaw_base_url",
    ):
        value = getattr(settings, attr, None)
        if isinstance(value, str) and value.strip():
            host = _origin_to_host(value.strip())
            if host:
                derived_hosts.append(host)

    normalized_derived_hosts = _normalize_unique(derived_hosts)
    if normalized_derived_hosts:
        return normalized_derived_hosts

    return ["*"]


def should_allow_credentials(settings: Settings, origins: Sequence[str]) -> bool:
    raw = getattr(settings, "cors_allow_credentials", None)
    if raw is None:
        raw = getattr(settings, "CORS_ALLOW_CREDENTIALS", None)
    if raw is not None:
        explicit = _parse_bool(raw, default="*" not in origins)
        if explicit and "*" in origins:
            return False
        return explicit
    return "*" not in origins


def install_security_middleware(app: FastAPI, settings: Settings) -> None:
    if getattr(app.state, _SECURITY_MIDDLEWARE_INSTALLED_FLAG, False):
        return

    origins = get_allowed_origins(settings)
    methods = get_allowed_methods(settings)
    headers = get_allowed_headers(settings)
    exposed_headers = get_exposed_headers(settings)
    hosts = get_allowed_hosts(settings)
    allow_credentials = should_allow_credentials(settings, origins)

    if allow_credentials:
        origins = [origin for origin in origins if origin != "*"]
        methods = [method for method in methods if method != "*"] or list(_DEFAULT_ALLOWED_METHODS)
        headers = [header for header in headers if header != "*"] or list(_DEFAULT_ALLOWED_HEADERS)

    include_hsts = _parse_bool(
        getattr(settings, "enable_hsts", getattr(settings, "ENABLE_HSTS", True)),
        default=True,
    )

    csp = _first_non_empty(
        getattr(settings, "content_security_policy", None),
        getattr(settings, "CONTENT_SECURITY_POLICY", None),
    )
    normalized_csp = csp.strip() if isinstance(csp, str) and csp.strip() else None

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
    app.add_middleware(
        SecurityHeadersMiddleware,
        include_hsts=include_hsts,
        csp=normalized_csp,
    )

    setattr(app.state, _SECURITY_MIDDLEWARE_INSTALLED_FLAG, True)
