from __future__ import annotations

from collections.abc import Callable
from contextlib import asynccontextmanager
from importlib import import_module
from inspect import isawaitable
from typing import Any, cast

from fastapi import Depends, FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute

ProtectedDependencyFactory = Callable[[], Any]


def _optional_module(module_path: str) -> Any | None:
    try:
        return import_module(module_path)
    except ModuleNotFoundError as exc:
        if exc.name != module_path:
            raise
        return None


def _optional_router(module_path: str) -> Any | None:
    module = _optional_module(module_path)
    if module is None:
        return None
    return getattr(module, "router", None)


def _optional_attr(module_path: str, attr_name: str) -> Any | None:
    module = _optional_module(module_path)
    if module is None:
        return None
    return getattr(module, attr_name, None)


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

    app.include_router(router, **kwargs)


def _include_router_group(
    app: FastAPI,
    routers: list[tuple[Any, dict[str, Any]]],
) -> None:
    for router, kwargs in routers:
        if router is None:
            continue
        app.include_router(router, **kwargs)


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


def _protected_dependencies() -> list[Any]:
    require_api_key = _optional_attr("app.core.auth", "require_api_key")
    if require_api_key is None:
        return []
    return [Depends(require_api_key)]


def _public_router_configs() -> list[tuple[Any, dict[str, Any]]]:
    scan_router = _optional_router("app.api.scan")
    return [
        (_optional_router("app.api.system"), {}),
        (_optional_router("app.api.ui_status"), {}),
        (_optional_router("app.api.ui_pages"), {}),
        (_optional_router("app.api.telemetry_access"), {}),
        (scan_router, {"prefix": "/scan"}),
        (scan_router, {"prefix": "/api/scan"}),
        (_optional_router("app.api.router"), {}),
        (_optional_router("app.api.actionusage"), {}),
    ]


def _protected_router_configs() -> list[tuple[Any, dict[str, Any]]]:
    dependencies = _protected_dependencies()
    return [
        (_optional_router("app.api.requestcontext"), {"dependencies": dependencies}),
        (_optional_router("app.api.history"), {"prefix": "/history", "dependencies": dependencies}),
        (
            _optional_router("app.api.history"),
            {"prefix": "/api/history", "dependencies": dependencies},
        ),
        (
            _optional_router("app.api.action_guard"),
            {"prefix": "/guard", "dependencies": dependencies},
        ),
        (
            _optional_router("app.api.action_execute"),
            {"prefix": "/guard", "dependencies": dependencies},
        ),
        (
            _optional_router("app.api.review_queue"),
            {"prefix": "/guard", "dependencies": dependencies},
        ),
        (_optional_router("app.api.audit_log"), {"prefix": "/guard", "dependencies": dependencies}),
        (_optional_router("app.api.policy"), {"prefix": "/policy", "dependencies": dependencies}),
        (_optional_router("app.api.release_policy_routes"), {"dependencies": dependencies}),
        (_optional_router("app.api.integrations"), {"dependencies": dependencies}),
        (_optional_router("app.api.customer_keys"), {}),
        (_optional_router("app.api.usage_reports"), {"dependencies": dependencies}),
        (_optional_router("app.api.auth"), {"dependencies": dependencies}),
        (_optional_router("app.api.operator_auth"), {"dependencies": dependencies}),
        (_optional_router("app.api.customer_auth"), {"dependencies": dependencies}),
        (_optional_router("app.api.session_security"), {"dependencies": dependencies}),
        (_optional_router("app.api.access_control"), {"dependencies": dependencies}),
        (_optional_router("app.api.org_context"), {"dependencies": dependencies}),
        (_optional_router("app.api.ui_admin_operators"), {}),
    ]


def _include_optional_protected_routers(app: FastAPI) -> None:
    dependencies = _protected_dependencies()
    optional_modules = [
        "app.api.routes.quarantine",
        "app.api.routes.reviewqueue",
        "app.api.routes.unitledger",
        "app.api.routes.unitwallet",
        "app.api.routes.dashboard",
        "app.api.routes.organizations",
    ]
    for module_path in optional_modules:
        _include_optional_router(
            app,
            module_path,
            dependencies=dependencies,
        )


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

    get_system_status = _optional_attr("app.api.system", "get_system_status")
    get_ui_manifest = _optional_attr("app.api.ui_pages", "get_ui_manifest")
    get_ui_status = _optional_attr("app.api.ui_status", "get_ui_status")
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
                "service": "IronClaw-Security",
            },
        )

    @app.get("/ui/manifest", tags=["ui"])
    def ui_manifest() -> Any:
        return _safe_call(
            get_ui_manifest,
            {
                "status": "ok",
                "service": "IronClaw-Security",
                "pages": [],
            },
        )

    @app.get("/ui/status", tags=["ui"])
    def ui_status() -> Any:
        return _safe_call(
            get_ui_status,
            {
                "status": "ok",
                "service": "IronClaw-Security",
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
        except Exception:
            pass


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

    _initialize_scan_history_repository()

    if callable(initialize_secure_runtime_pipeline):
        pipeline = initialize_secure_runtime_pipeline()

    app.state.action_execute_pipeline = pipeline
    if pipeline is not None and callable(set_action_execute_pipeline):
        set_action_execute_pipeline(pipeline)

    try:
        yield
    finally:
        try:
            close = getattr(pipeline, "close", None)
            if callable(close):
                result = close()
                if isawaitable(result):
                    await result
        finally:
            app.state.action_execute_pipeline = None
            if callable(reset_action_execute_pipeline):
                reset_action_execute_pipeline()
            if callable(reset_scan_history_repository):
                reset_scan_history_repository()


def create_app() -> FastAPI:
    app = FastAPI(
        title="IronClaw-Security",
        version="1.0.0",
        description=("Local-first AI security API for prompt inspection, guarded execution, " "and protected runtime controls."),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    _install_openapi_factory(app)
    _install_core_middleware(app)

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
