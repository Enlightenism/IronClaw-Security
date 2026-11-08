from __future__ import annotations

from collections.abc import Callable
from contextlib import asynccontextmanager
from importlib import import_module
from inspect import isawaitable
import logging
from typing import Any, cast

from fastapi import Depends, FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute

from app.core.security import get_allowed_origins, install_security_middleware
from app.core.settings import get_settings

ProtectedDependencyFactory = Callable[[], Any]


_log = logging.getLogger(__name__)


def _optional_module(module_path: str) -> Any | None:
    try:
        return import_module(module_path)
    except ModuleNotFoundError as exc:
        missing_name = getattr(exc, "name", "") or ""
        if missing_name == module_path:
            _log.debug("main: optional module not found: %s", module_path)
            return None
        _log.exception(
            "main: optional module import failed for %s due to missing nested dependency %s",
            module_path,
            missing_name,
        )
        raise
    except Exception:
        _log.exception("main: optional module import failed for %s", module_path)
        raise


def _optional_router(module_path: str) -> Any | None:
    module = _optional_module(module_path)
    if module is None:
        return None
    router = getattr(module, "router", None)
    if router is None:
        _log.debug("main: module %s has no router attribute", module_path)
    return router


def _optional_attr(module_path: str, attr_name: str) -> Any | None:
    module = _optional_module(module_path)
    if module is None:
        return None
    return getattr(module, attr_name, None)


def _route_signature(route: APIRoute) -> tuple[str, tuple[str, ...]]:
    return (
        route.path,
        tuple(sorted((method or "").upper() for method in route.methods or set())),
    )


def _include_router_once(
    app: FastAPI,
    router: Any,
    **kwargs: Any,
) -> None:
    if router is None:
        return

    existing = {_route_signature(route) for route in app.routes if isinstance(route, APIRoute)}

    app.include_router(router, **kwargs)

    new_routes = [route for route in app.routes if isinstance(route, APIRoute) and _route_signature(route) not in existing]

    if not new_routes:
        _log.warning(
            "main: router include produced no new routes (possible duplicate): %s",
            getattr(router, "prefix", "<no-prefix>"),
        )


def _include_router_group(
    app: FastAPI,
    routers: list[tuple[Any, dict[str, Any]]],
) -> None:
    for router, kwargs in routers:
        if router is None:
            continue
        _include_router_once(app, router, **kwargs)


def _include_optional_router(
    app: FastAPI,
    module_path: str,
    *,
    prefix: str | None = None,
    dependencies: list[Any] | None = None,
) -> None:
    router = _optional_router(module_path)
    if router is None:
        return

    kwargs: dict[str, Any] = {}
    if prefix is not None:
        kwargs["prefix"] = prefix
    if dependencies is not None:
        kwargs["dependencies"] = dependencies

    _include_router_once(app, router, **kwargs)
    _log.info(
        "main: included router from %s%s",
        module_path,
        f" with prefix {prefix}" if prefix is not None else "",
    )


def _normalize_dependency_metadata(app: FastAPI) -> None:
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue

        for dependant in route.dependant.dependencies:
            if getattr(dependant, "dependency", None) is None:
                call = getattr(dependant, "call", None)
                if call is not None:
                    dependant.dependency = call


def _build_openapi(app: FastAPI) -> dict[str, Any]:
    if app.openapi_schema is not None:
        return cast("dict[str, Any]", app.openapi_schema)

    app.openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    return cast("dict[str, Any]", app.openapi_schema)


def _install_openapi_factory(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        return _build_openapi(app)

    app.openapi = custom_openapi


def _coerce_optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return None


def _is_auth_required() -> bool:
    try:
        settings = get_settings()
    except Exception:
        return True

    effective = _coerce_optional_bool(getattr(settings, "effective_auth_required", None))
    if effective is not None:
        return effective

    explicit = _coerce_optional_bool(getattr(settings, "auth_required", None))
    if explicit is not None:
        return explicit

    explicit = _coerce_optional_bool(getattr(settings, "AUTH_REQUIRED", None))
    if explicit is not None:
        return explicit

    return True


def _protected_dependencies() -> list[Any]:
    require_api_key = _optional_attr("app.core.auth", "require_api_key")
    if require_api_key is None:
        return []
    return [Depends(require_api_key)]


def _agent_rate_limit_dep(agent_id_param: str = "agent_id") -> Any | None:
    agent_rate_limit_dependency = _optional_attr(
        "app.core.rate_limiter",
        "agent_rate_limit_dependency",
    )
    if not callable(agent_rate_limit_dependency):
        return None
    return Depends(agent_rate_limit_dependency(agent_id_param))


def _agent_protected_dependencies(agent_id_param: str = "agent_id") -> list[Any]:
    deps = _protected_dependencies()
    agent_rl = _agent_rate_limit_dep(agent_id_param)
    if agent_rl is not None:
        deps = deps + [agent_rl]
    return deps


def _public_router_configs() -> list[tuple[Any, dict[str, Any]]]:
    scan_router = _optional_router("app.api.scan")
    stripe_webhook_router = _optional_attr("app.routers.stripe_router", "webhook_router")
    billing_webhook_router = _optional_attr("app.api.routes.billing", "webhook_router")
    return [
        (_optional_router("app.api.skill_package"), {}),
        (_optional_router("app.api.favicon"), {}),
        (_optional_router("app.api.system"), {}),
        (_optional_router("app.api.ui_status"), {}),
        (_optional_router("app.api.ui_pages"), {}),
        (_optional_router("app.api.telemetry_access"), {}),
        (scan_router, {"prefix": "/scan"}),
        (scan_router, {"prefix": "/api/scan"}),
        (_optional_router("app.api.router"), {}),
        (_optional_router("app.api.actionusage"), {}),
        (_optional_router("app.api.region_status"), {}),
        (billing_webhook_router, {}),
        (billing_webhook_router, {"prefix": "/api"}),
        (stripe_webhook_router, {}),
        (stripe_webhook_router, {"prefix": "/api"}),
    ]


def _stripe_router_configs() -> list[tuple[Any, dict[str, Any]]]:
    stripe_router = _optional_router("app.routers.stripe_router")
    if stripe_router is None:
        return []

    auth_required = _is_auth_required()
    _log.info(
        "main: including stripe router with route-level auth control; effective_auth_required=%s",
        auth_required,
    )

    return [
        (stripe_router, {}),
        (stripe_router, {"prefix": "/api"}),
    ]


def _protected_router_configs() -> list[tuple[Any, dict[str, Any]]]:
    dependencies = _protected_dependencies()
    agent_dependencies = _agent_protected_dependencies("agent_id")
    action_execute_router = _optional_router("app.api.action_execute")
    event_simulation_router = _optional_router("app.api.event_simulation")
    return [
        (_optional_router("app.api.requestcontext"), {"dependencies": dependencies}),
        (_optional_router("app.api.history"), {"prefix": "/history", "dependencies": dependencies}),
        (_optional_router("app.api.action_guard"), {"prefix": "/guard", "dependencies": agent_dependencies}),
        (_optional_router("app.api.guard"), {"dependencies": agent_dependencies}),
        (_optional_router("app.api.guard_action"), {"dependencies": agent_dependencies}),
        (action_execute_router, {"prefix": "/guard", "dependencies": agent_dependencies}),
        (action_execute_router, {"prefix": "/execute", "dependencies": agent_dependencies}),
        (_optional_router("app.api.execute"), {"dependencies": agent_dependencies}),
        (_optional_router("app.api.review_queue"), {"prefix": "/guard", "dependencies": dependencies}),
        (_optional_router("app.api.audit_log"), {"prefix": "/guard", "dependencies": dependencies}),
        (_optional_router("app.api.auditlog"), {"dependencies": dependencies}),
        (_optional_router("app.api.audit"), {"prefix": "/api", "dependencies": dependencies}),
        (_optional_router("app.api.behavioral_baseline"), {"dependencies": dependencies}),
        (_optional_router("app.api.policy"), {"prefix": "/policy", "dependencies": dependencies}),
        (_optional_router("app.api.return_gate"), {"prefix": "/return-gate"}),
        (_optional_router("app.api.install_gate"), {"prefix": "/install-gate"}),
        (_optional_router("app.api.actionpolicy"), {"dependencies": dependencies}),
        (_optional_router("app.api.actiondecision"), {"dependencies": dependencies}),
        (_optional_router("app.api.actionguard"), {"dependencies": agent_dependencies}),
        (_optional_router("app.api.actionexecute"), {}),
        (_optional_router("app.api.release_policy_routes"), {"dependencies": dependencies}),
        (_optional_router("app.api.customer_keys"), {"dependencies": dependencies}),
        (_optional_router("app.api.usage_reports"), {"dependencies": dependencies}),
        (_optional_router("app.api.auth"), {"dependencies": dependencies}),
        (_optional_router("app.api.operator_auth"), {"dependencies": dependencies}),
        (_optional_router("app.api.customer_auth"), {"dependencies": dependencies}),
        (_optional_router("app.api.session_security"), {"dependencies": dependencies}),
        (_optional_router("app.api.access_control"), {"dependencies": dependencies}),
        (_optional_router("app.api.org_context"), {"dependencies": dependencies}),
        (_optional_router("app.api.ui_admin_operators"), {}),
        (_optional_router("app.api.ui_data_retention"), {"dependencies": dependencies}),
        (_optional_router("app.api.ui_system_diagnostics"), {}),
        (_optional_router("app.api.webhooks"), {"dependencies": dependencies}),
        (_optional_router("app.api.onboarding"), {"dependencies": dependencies}),
        (_optional_router("app.api.backup"), {"dependencies": dependencies}),
        (_optional_router("app.api.restore"), {"dependencies": dependencies}),
        (_optional_router("app.api.incidents"), {"dependencies": dependencies}),
        (_optional_router("app.api.notifications"), {"dependencies": dependencies}),
        (_optional_router("app.api.diagnostics"), {"dependencies": dependencies}),
        (_optional_router("app.api.review"), {"dependencies": dependencies}),
        (_optional_router("app.api.reviews"), {"dependencies": dependencies}),
        (_optional_router("app.api.health"), {"dependencies": dependencies}),
        (_optional_router("app.api.prompt_guard"), {"dependencies": dependencies}),
        (_optional_router("app.api.claude_bootstrap"), {"dependencies": dependencies}),
        (_optional_router("app.api.claude_guard_router"), {"dependencies": dependencies}),
        (_optional_router("app.api.claude_stream_guard"), {"dependencies": dependencies}),
        (_optional_router("app.api.claude_router_proxy"), {"dependencies": dependencies}),
        (_optional_router("app.routers.threat_detection"), {"dependencies": dependencies}),
        (_optional_router("app.api.threat_detection"), {"dependencies": dependencies}),
        (_optional_router("app.api.threat_hunt"), {"dependencies": dependencies}),
        (_optional_router("app.api.ioc_management"), {"dependencies": dependencies}),
        (event_simulation_router, {"prefix": "/events", "dependencies": dependencies}),
        (event_simulation_router, {"prefix": "/api/events", "dependencies": dependencies}),
        (_optional_router("app.worker.remediation_worker"), {"dependencies": dependencies}),
    ]


def _include_optional_protected_routers(app: FastAPI) -> None:
    dependencies = _protected_dependencies()

    legacy_modules = [
        "app.api.routes.quarantine",
        "app.api.routes.llamafirewall",
        "app.api.routes.reviewqueue",
        "app.api.routes.unitledger",
        "app.api.routes.unitwallet",
        "app.api.routes.organizations",
    ]
    for module_path in legacy_modules:
        _include_optional_router(app, module_path, dependencies=dependencies)

    integration_modules = [
        "app.routes.integrations.agent_skills",
        "app.routes.integrations.claude_code",
        "app.routes.integrations.compatibility",
        "app.routes.integrations.copilot",
        "app.routes.integrations.cursor",
        "app.routes.integrations.gemini_cli",
        "app.routes.integrations.goose",
        "app.routes.integrations.hermes",
        "app.routes.integrations.installer",
        "app.routes.integrations.lifecycle",
        "app.routes.integrations.observability",
        "app.routes.integrations.openclaw",
        "app.routes.integrations.readiness",
        "app.routes.integrations.rollouts",
        "app.routes.integrations.secrets",
        "app.routes.integrations.telemetry",
        "app.routes.integrations.verifier",
    ]
    for module_path in integration_modules:
        _include_optional_router(app, module_path, dependencies=dependencies)

    _include_optional_router(app, "app.api.routes.billing")
    _include_optional_router(app, "app.api.routes.install_key_events")
    _include_optional_router(app, "app.api.routes.dashboard")
    _include_optional_router(app, "app.api.integrations")


def _install_core_middleware(app: FastAPI) -> None:
    if getattr(app.state, "_core_middleware_installed", False):
        return

    request_id_middleware = _optional_attr("app.core.request_id", "RequestIDMiddleware")
    request_context_middleware = _optional_attr("app.core.logging", "RequestContextMiddleware")
    usage_metering_middleware = _optional_attr("app.core.middleware", "UsageMeteringMiddleware")

    for middleware_cls in (
        request_id_middleware,
        request_context_middleware,
        usage_metering_middleware,
    ):
        if middleware_cls is not None:
            app.add_middleware(middleware_cls)

    app.state._core_middleware_installed = True


def _safe_call(call: Callable[[], Any] | None, default: Any) -> Any:
    if not callable(call):
        return default
    try:
        return call()
    except Exception:
        return default


def _install_core_routes(app: FastAPI) -> None:
    if getattr(app.state, "_core_routes_installed", False):
        return

    settings = get_settings()

    get_system_status = _optional_attr("app.api.system", "get_system_status")
    get_ui_manifest = _optional_attr("app.api.ui_pages", "get_ui_manifest")
    get_runtime_status = _optional_attr("app.ui.runtimestatus", "get_runtime_status_page")
    if get_runtime_status is None:
        get_runtime_status = _optional_attr("app.ui.runtimestatus", "getruntimestatuspage")

    @app.get("/")
    def root() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/liveness", tags=["system"])
    def health_liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/readiness", tags=["system"])
    def health_readiness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/system/status", tags=["system"])
    def system_status() -> Any:
        return _safe_call(
            get_system_status,
            {
                "status": "ok",
                "service": settings.app_name,
            },
        )

    @app.get("/ui/manifest", tags=["ui"])
    def ui_manifest() -> Any:
        return _safe_call(
            get_ui_manifest,
            {
                "status": "ok",
                "service": settings.app_name,
                "pages": [],
            },
        )

    @app.get("/runtime/status", tags=["ui"])
    def ui_runtime_status() -> Any:
        return _safe_call(
            get_runtime_status,
            {
                "status": "ok",
                "runtimeavailable": True,
                "boundaryactive": True,
                "reviewqueueenabled": True,
            },
        )

    app.state._core_routes_installed = True


def _install_all_routers(app: FastAPI) -> None:
    if getattr(app.state, "_routers_installed", False):
        return

    _include_router_group(app, _public_router_configs())
    _include_router_group(app, _protected_router_configs())
    _include_router_group(app, _stripe_router_configs())
    _include_optional_protected_routers(app)

    include_ui_routers = _optional_attr("app.ui.router", "include_ui_routers")
    if callable(include_ui_routers):
        include_ui_routers(app)

    app.state._routers_installed = True


def _initialize_scan_history_repository() -> None:
    set_scan_history_repository = _optional_attr(
        "app.services.history",
        "set_scan_history_repository",
    )
    build_scan_history_repository = _optional_attr(
        "app.repositories.scan_history_repository",
        "build_scan_history_repository",
    )

    if callable(set_scan_history_repository) and callable(build_scan_history_repository):
        try:
            repository = build_scan_history_repository()
            set_scan_history_repository(repository)
        except Exception as exc:
            _log.warning("main: scan_history_repository init failed: %s", exc)


async def _initialize_policy_rules() -> None:
    load_builtin_policy_rules_from_db = _optional_attr(
        "app.services.rules",
        "load_builtin_policy_rules_from_db",
    )
    if not callable(load_builtin_policy_rules_from_db):
        _log.debug("main.lifespan: load_builtin_policy_rules_from_db not available, skipping")
        return
    try:
        result = load_builtin_policy_rules_from_db()
        if isawaitable(result):
            await result
        _log.info("main.lifespan: policy rules hydrated from db")
    except Exception as exc:
        _log.error("main.lifespan: policy rules hydration failed: %s", exc)


async def _initialize_scanner_rule_index() -> None:
    load_builtin_patterns_from_db = _optional_attr(
        "app.services.scanner",
        "load_builtin_patterns_from_db",
    )
    if not callable(load_builtin_patterns_from_db):
        _log.debug("main.lifespan: load_builtin_patterns_from_db not available, skipping")
        return
    try:
        result = load_builtin_patterns_from_db()
        if isawaitable(result):
            await result
        _log.info("main.lifespan: scanner RULE_INDEX hydrated from db")
    except Exception as exc:
        _log.error("main.lifespan: scanner RULE_INDEX hydration failed: %s", exc)


def _initialize_pattern_registry() -> None:
    load = _optional_attr("app.core.pattern_registry", "load")
    if not callable(load):
        _log.debug("main.lifespan: pattern_registry.load not available, skipping")
        return
    try:
        load(force=True)
        _log.info("main.lifespan: pattern_registry loaded from db")
    except Exception as exc:
        _log.error("main.lifespan: pattern_registry.load failed: %s", exc)


def _shutdown_pattern_registry() -> None:
    invalidate = _optional_attr("app.core.pattern_registry", "invalidate")
    if callable(invalidate):
        try:
            invalidate()
            _log.info("main.lifespan: pattern_registry cache invalidated on shutdown")
        except Exception as exc:
            _log.error("main.lifespan: pattern_registry.invalidate failed: %s", exc)


def _shutdown_trust_engine_cache() -> None:
    invalidate_all_cache = _optional_attr("app.core.trust_engine", "invalidate_all_cache")
    if callable(invalidate_all_cache):
        try:
            invalidate_all_cache()
            _log.info("main.lifespan: trust_engine cache invalidated on shutdown")
        except Exception as exc:
            _log.error("main.lifespan: trust_engine.invalidate_all_cache failed: %s", exc)
    else:
        try:
            trust_engine_mod = _optional_module("app.core.trust_engine")
            if trust_engine_mod is not None:
                cache: dict | None = getattr(trust_engine_mod, "_profile_cache", None)
                lock = getattr(trust_engine_mod, "_lock", None)
                if isinstance(cache, dict) and lock is not None:
                    with lock:
                        cache.clear()
                    _log.info("main.lifespan: trust_engine._profile_cache cleared on shutdown")
        except Exception as exc:
            _log.error("main.lifespan: trust_engine cache clear failed: %s", exc)


def _initialize_notification_engine() -> None:
    get_notification_engine = _optional_attr(
        "app.services.notification_engine",
        "get_notification_engine",
    )
    if not callable(get_notification_engine):
        _log.debug("main.lifespan: get_notification_engine not available, skipping")
        return
    try:
        get_notification_engine()
        _log.info("main.lifespan: notification_engine singleton pre-warmed")
    except Exception as exc:
        _log.error("main.lifespan: notification_engine pre-warm failed: %s", exc)


def _start_threat_feed_scheduler() -> None:
    try:
        from app.services.threat_feed_scheduler import start_scheduler  # noqa: PLC0415

        start_scheduler()
        _log.info("main.lifespan: threat_feed_scheduler started")
    except Exception as exc:
        _log.error("main.lifespan: threat_feed_scheduler failed to start: %s", exc)


def _stop_threat_feed_scheduler() -> None:
    try:
        from app.services.threat_feed_scheduler import stop_scheduler  # noqa: PLC0415

        stop_scheduler()
        _log.info("main.lifespan: threat_feed_scheduler stopped")
    except Exception as exc:
        _log.error("main.lifespan: threat_feed_scheduler failed to stop: %s", exc)


def _start_remediation_scheduler() -> None:
    try:
        from app.worker.remediation_worker import start_remediation_scheduler  # noqa: PLC0415

        start_remediation_scheduler()
        _log.info("main.lifespan: remediation_scheduler started")
    except Exception as exc:
        _log.error("main.lifespan: remediation_scheduler failed to start: %s", exc)


def _stop_remediation_scheduler() -> None:
    try:
        from app.worker.remediation_worker import stop_remediation_scheduler  # noqa: PLC0415

        stop_remediation_scheduler()
        _log.info("main.lifespan: remediation_scheduler stopped")
    except Exception as exc:
        _log.error("main.lifespan: remediation_scheduler failed to stop: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    pipeline = None
    initialize_secure_runtime_pipeline = _optional_attr(
        "app.orchestrator.secure_runtime_pipeline",
        "initialize_secure_runtime_pipeline",
    )
    set_action_execute_pipeline = _optional_attr(
        "app.dependencies.action_execute",
        "set_action_execute_pipeline",
    )
    reset_action_execute_pipeline = _optional_attr(
        "app.dependencies.action_execute",
        "reset_action_execute_pipeline",
    )
    reset_scan_history_repository = _optional_attr(
        "app.services.history",
        "reset_scan_history_repository",
    )

    _log.info("main.lifespan: startup begin")

    _initialize_scan_history_repository()
    await _initialize_policy_rules()
    await _initialize_scanner_rule_index()

    try:
        _initialize_pattern_registry()
    except Exception as exc:
        _log.error("main.lifespan: _initialize_pattern_registry raised unexpectedly: %s", exc)

    try:
        _initialize_notification_engine()
    except Exception as exc:
        _log.error("main.lifespan: _initialize_notification_engine raised unexpectedly: %s", exc)

    if callable(initialize_secure_runtime_pipeline):
        try:
            result = initialize_secure_runtime_pipeline()
            if isawaitable(result):
                pipeline = await result
            else:
                pipeline = result
            _log.info("main.lifespan: secure_runtime_pipeline initialized")
        except Exception as exc:
            _log.error("main.lifespan: secure_runtime_pipeline init failed: %s", exc)

    app.state.action_execute_pipeline = pipeline
    if pipeline is not None and callable(set_action_execute_pipeline):
        set_action_execute_pipeline(pipeline)

    try:
        _start_threat_feed_scheduler()
    except Exception as exc:
        _log.error("main.lifespan: _start_threat_feed_scheduler raised unexpectedly: %s", exc)

    try:
        _start_remediation_scheduler()
    except Exception as exc:
        _log.error("main.lifespan: _start_remediation_scheduler raised unexpectedly: %s", exc)

    try:
        settings = get_settings()
        resolved_origins = get_allowed_origins(settings)
        _log.info("main.lifespan: CORS allowed origins resolved: %s", resolved_origins)
        _log.info("main.lifespan: effective_auth_required resolved: %s", _is_auth_required())
    except Exception as exc:
        _log.warning("main.lifespan: could not resolve startup security settings for log: %s", exc)

    _log.info("main.lifespan: startup complete")

    try:
        yield
    finally:
        _log.info("main.lifespan: shutdown begin")

        try:
            _stop_remediation_scheduler()
        except Exception as exc:
            _log.error("main.lifespan: _stop_remediation_scheduler raised unexpectedly: %s", exc)

        try:
            _stop_threat_feed_scheduler()
        except Exception as exc:
            _log.error("main.lifespan: _stop_threat_feed_scheduler raised unexpectedly: %s", exc)

        try:
            close = getattr(pipeline, "close", None)
            if callable(close):
                result = close()
                if isawaitable(result):
                    await result
        except Exception as exc:
            _log.error("main.lifespan: pipeline close failed: %s", exc)

        try:
            _shutdown_trust_engine_cache()
        except Exception as exc:
            _log.error("main.lifespan: _shutdown_trust_engine_cache raised unexpectedly: %s", exc)

        try:
            _shutdown_pattern_registry()
        except Exception as exc:
            _log.error("main.lifespan: _shutdown_pattern_registry raised unexpectedly: %s", exc)

        app.state.action_execute_pipeline = None

        if callable(reset_action_execute_pipeline):
            try:
                reset_action_execute_pipeline()
            except Exception as exc:
                _log.error("main.lifespan: reset_action_execute_pipeline failed: %s", exc)

        if callable(reset_scan_history_repository):
            try:
                reset_scan_history_repository()
            except Exception as exc:
                _log.error("main.lifespan: reset_scan_history_repository failed: %s", exc)

        _log.info("main.lifespan: shutdown complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Local-first AI security API for prompt inspection, guarded execution, and protected runtime controls.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    app.state.settings = settings

    _install_core_middleware(app)
    install_security_middleware(app, settings)

    _install_openapi_factory(app)

    bootstrap_app = _optional_attr("app.bootstrap", "bootstrap_app")
    if callable(bootstrap_app):
        bootstrap_app(app)

    register_exception_handlers = _optional_attr("app.core.errors", "register_exception_handlers")
    if callable(register_exception_handlers):
        register_exception_handlers(app)

    _install_core_routes(app)
    _install_all_routers(app)

    install_protected_docs = _optional_attr("app.core.docs", "install_protected_docs")
    if callable(install_protected_docs):
        install_protected_docs(app)

    _normalize_dependency_metadata(app)

    return app


app = create_app()
