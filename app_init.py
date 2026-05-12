from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.core.errors import register_exception_handlers
from app.core.logging import RequestContextMiddleware, configure_logging
from app.core.ratelimit import install_rate_limit_middleware
from app.core.security import install_security_middleware
from app.core.settings import Settings, get_settings


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str


class ReadinessComponent(BaseModel):
    name: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class ReadinessResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    checks: list[ReadinessComponent]


def _safe_attr(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def _build_readiness_checks(settings: Settings, app: FastAPI) -> list[ReadinessComponent]:
    checks: list[ReadinessComponent] = []

    checks.append(
        ReadinessComponent(
            name="settings",
            status="ok",
            details={
                "api_prefix": settings.api_prefix,
                "guard_actions_enabled": settings.enable_guard_actions,
                "guard_policy_enabled": settings.enable_guard_action_policy,
                "guard_decision_enabled": settings.enable_guard_action_decision,
                "structured_logging_enabled": settings.structured_logging_enabled,
            },
        )
    )

    scanner_service: Any | None = getattr(app.state, "scanner_service", None)
    checks.append(
        ReadinessComponent(
            name="scanner_service",
            status="ok" if scanner_service is not None else "not_configured",
            details={
                "present": scanner_service is not None,
            },
        )
    )

    history_service: Any | None = getattr(app.state, "history_service", None)
    checks.append(
        ReadinessComponent(
            name="history_service",
            status="ok" if history_service is not None else "not_configured",
            details={
                "present": history_service is not None,
            },
        )
    )

    groq_ready = (not settings.groq_enabled) or bool(settings.groq_api_key)
    checks.append(
        ReadinessComponent(
            name="groq",
            status="ok" if groq_ready else "misconfigured",
            details={
                "enabled": settings.groq_enabled,
                "model": settings.groq_model,
                "api_key_present": bool(settings.groq_api_key),
                "timeout_seconds": settings.groq_timeout_seconds,
            },
        )
    )

    return checks


def _overall_readiness_status(checks: list[ReadinessComponent]) -> str:
    failing_statuses = {"error", "failed", "misconfigured"}
    if any(check.status in failing_statuses for check in checks):
        return "degraded"
    return "ok"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings)
    app.state.settings = settings
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        lifespan=lifespan,
    )

    register_exception_handlers(app)
    install_security_middleware(app, settings)
    install_rate_limit_middleware(app)
    app.add_middleware(RequestContextMiddleware)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health(config: Settings = Depends(get_settings)) -> HealthResponse:
        return HealthResponse(
            status="ok",
            service=config.app_name,
            version=config.app_version,
            environment=config.environment.value,
        )

    @app.get("/ready", response_model=ReadinessResponse, tags=["system"])
    def readiness(config: Settings = Depends(get_settings)) -> ReadinessResponse:
        checks = _build_readiness_checks(config, app)
        return ReadinessResponse(
            status=_overall_readiness_status(checks),
            service=config.app_name,
            version=config.app_version,
            environment=config.environment.value,
            checks=checks,
        )

    return app


app = create_app()