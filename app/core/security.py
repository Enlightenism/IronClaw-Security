from __future__ import annotations

from collections.abc import Iterable, Sequence

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        include_hsts: bool = True,
        csp: str | None = None,
    ) -> None:
        super().__init__(app)
        self.include_hsts = include_hsts
        self.csp = (csp or _DEFAULT_CSP).strip()

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        )
        if request.method.upper() != "OPTIONS":
            response.headers.setdefault("Content-Security-Policy", self.csp)
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")

        if self.include_hsts and request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            )

        return response


def _csv_to_list(value: str | None, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    parsed = [item.strip() for item in value.split(",") if item.strip()]
    return parsed or list(default)


def _coerce_list(value: object, *, default: Sequence[str]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        return _csv_to_list(value, default=default)
    if isinstance(value, Iterable):
        parsed: list[str] = []
        for item in value:
            text = str(item).strip()
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


def get_allowed_origins(settings: Settings) -> list[str]:
    raw = getattr(settings, "effective_allowed_origins", None)
    origins = _coerce_list(raw, default=["http://localhost"])
    return _normalize_unique(origins)


def get_allowed_methods(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_allowed_methods", None)
    methods = _coerce_list(raw, default=_DEFAULT_ALLOWED_METHODS)
    return _normalize_unique(methods)


def get_allowed_headers(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_allowed_headers", None)
    headers = _coerce_list(raw, default=_DEFAULT_ALLOWED_HEADERS)
    return _normalize_unique(headers)


def get_exposed_headers(settings: Settings) -> list[str]:
    raw = getattr(settings, "cors_expose_headers", None)
    headers = _coerce_list(raw, default=_DEFAULT_EXPOSE_HEADERS)
    return _normalize_unique(headers)


def get_allowed_hosts(settings: Settings) -> list[str]:
    raw = getattr(settings, "effective_trusted_hosts", None)
    hosts = _coerce_list(raw, default=["*"])
    return _normalize_unique(hosts)


def should_allow_credentials(settings: Settings, origins: Sequence[str]) -> bool:
    raw = getattr(settings, "cors_allow_credentials", None)
    if isinstance(raw, bool):
        return raw
    return "*" not in origins


def install_security_middleware(app: FastAPI, settings: Settings) -> None:
    origins = get_allowed_origins(settings)
    methods = get_allowed_methods(settings)
    headers = get_allowed_headers(settings)
    exposed_headers = get_exposed_headers(settings)
    hosts = get_allowed_hosts(settings)

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=hosts,
    )

    include_hsts = bool(getattr(settings, "enable_hsts", True))
    csp = getattr(settings, "content_security_policy", None)
    normalized_csp = csp.strip() if isinstance(csp, str) and csp.strip() else None

    app.add_middleware(
        SecurityHeadersMiddleware,
        include_hsts=include_hsts,
        csp=normalized_csp,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=should_allow_credentials(settings, origins),
        allow_methods=methods,
        allow_headers=headers,
        expose_headers=exposed_headers,
    )
