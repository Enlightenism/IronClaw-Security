from __future__ import annotations

import importlib
import sys
import threading
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_app() -> FastAPI:
    """Re-import app.main after clearing module cache so lifespan runs fresh."""
    for key in list(sys.modules.keys()):
        if key == "app.main" or key.startswith("app.main."):
            del sys.modules[key]
    mod = importlib.import_module("app.main")
    return mod.create_app()


def _dep_callables(app: FastAPI, path_prefix: str) -> list[Any]:
    """Return the raw callables from all Depends on routes whose path starts with prefix."""
    from fastapi import params as fastapi_params
    from fastapi.routing import APIRoute

    callables: list[Any] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not route.path.startswith(path_prefix):
            continue
        for dep in route.dependencies:
            if isinstance(dep, fastapi_params.Depends):
                callables.append(dep.dependency)
            else:
                dep_obj = getattr(dep, "dependency", None) or getattr(dep, "call", None)
                if dep_obj is not None:
                    callables.append(dep_obj)
    return callables


# ---------------------------------------------------------------------------
# 1. pattern_registry.load(force=True) is called during startup
# ---------------------------------------------------------------------------


class TestPatternRegistryStartup:
    def test_load_called_with_force_true_on_startup(self) -> None:
        load_mock = MagicMock()

        with patch.dict(sys.modules, {}):
            fake_registry = ModuleType("app.core.pattern_registry")
            fake_registry.load = load_mock  # type: ignore[attr-defined]
            sys.modules["app.core.pattern_registry"] = fake_registry

            for key in list(sys.modules.keys()):
                if key == "app.main":
                    del sys.modules[key]

            from app import main as main_mod  # noqa: PLC0415

            with TestClient(main_mod.create_app(), raise_server_exceptions=True):
                pass

        load_mock.assert_called_once_with(force=True)

    def test_load_failure_does_not_crash_startup(self) -> None:
        exploding_load = MagicMock(side_effect=RuntimeError("db unavailable"))

        with patch.dict(sys.modules, {}):
            fake_registry = ModuleType("app.core.pattern_registry")
            fake_registry.load = exploding_load  # type: ignore[attr-defined]
            sys.modules["app.core.pattern_registry"] = fake_registry

            for key in list(sys.modules.keys()):
                if key == "app.main":
                    del sys.modules[key]

            from app import main as main_mod  # noqa: PLC0415

            with TestClient(main_mod.create_app(), raise_server_exceptions=True) as client:
                resp = client.get("/health")
            assert resp.status_code == 200

    def test_load_absent_does_not_crash_startup(self) -> None:
        with patch.dict(sys.modules, {}):
            fake_registry = ModuleType("app.core.pattern_registry")
            sys.modules["app.core.pattern_registry"] = fake_registry

            for key in list(sys.modules.keys()):
                if key == "app.main":
                    del sys.modules[key]

            from app import main as main_mod  # noqa: PLC0415

            with TestClient(main_mod.create_app(), raise_server_exceptions=True) as client:
                resp = client.get("/health")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. trust_engine._profile_cache is empty after shutdown
# ---------------------------------------------------------------------------


class TestTrustEngineCacheShutdown:
    def test_profile_cache_cleared_on_shutdown(self) -> None:
        import app.core.trust_engine as trust_engine_mod  # noqa: PLC0415

        lock: threading.Lock = trust_engine_mod._lock
        cache: dict = trust_engine_mod._profile_cache

        with lock:
            cache["agent-test-1"] = {"trust_level": "high", "data": "sensitive"}
            cache["agent-test-2"] = {"trust_level": "low", "data": "other"}

        assert len(cache) == 2

        from app.main import create_app  # noqa: PLC0415

        app_instance = create_app()
        with TestClient(app_instance, raise_server_exceptions=True):
            pass

        with lock:
            assert len(cache) == 0, f"trust_engine._profile_cache was not cleared on shutdown; remaining keys: {list(cache.keys())}"

    def test_invalidate_all_cache_preferred_over_direct_clear(self) -> None:
        invalidate_mock = MagicMock()

        with patch.dict(sys.modules, {}):
            fake_trust = ModuleType("app.core.trust_engine")
            fake_trust.invalidate_all_cache = invalidate_mock  # type: ignore[attr-defined]
            sys.modules["app.core.trust_engine"] = fake_trust

            for key in list(sys.modules.keys()):
                if key == "app.main":
                    del sys.modules[key]

            from app import main as main_mod  # noqa: PLC0415

            with TestClient(main_mod.create_app(), raise_server_exceptions=True):
                pass

        invalidate_mock.assert_called_once()

    def test_shutdown_survives_invalidate_all_cache_raising(self) -> None:
        exploding_invalidate = MagicMock(side_effect=RuntimeError("shutdown error"))

        with patch.dict(sys.modules, {}):
            fake_trust = ModuleType("app.core.trust_engine")
            fake_trust.invalidate_all_cache = exploding_invalidate  # type: ignore[attr-defined]
            sys.modules["app.core.trust_engine"] = fake_trust

            for key in list(sys.modules.keys()):
                if key == "app.main":
                    del sys.modules[key]

            from app import main as main_mod  # noqa: PLC0415

            with TestClient(main_mod.create_app(), raise_server_exceptions=True) as client:
                resp = client.get("/health")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 3. /guard and /execute routers carry auth + agent_rate_limit_dependency
# ---------------------------------------------------------------------------


class TestAgentRouterDependencies:
    """
    Verify that routes mounted under /guard and /execute carry both:
    - require_api_key  (auth enforcement)
    - a dependency factory produced by agent_rate_limit_dependency (per-agent rate limit)
    """

    def _get_app(self) -> FastAPI:
        from app.main import create_app  # noqa: PLC0415

        return create_app()

    def _route_dependencies(self, app: FastAPI, prefix: str) -> list[Any]:
        from fastapi import params as fp  # noqa: PLC0415
        from fastapi.routing import APIRoute  # noqa: PLC0415

        deps: list[Any] = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            if not route.path.startswith(prefix):
                continue
            for d in route.dependencies:
                if isinstance(d, fp.Depends):
                    deps.append(d.dependency)
        return deps

    def test_guard_routes_carry_auth_dependency(self) -> None:
        from app.core.auth import require_api_key  # noqa: PLC0415

        app = self._get_app()
        guard_deps = self._route_dependencies(app, "/guard")

        if not guard_deps:
            pytest.skip("/guard routes not present in this build")

        assert require_api_key in guard_deps, "require_api_key not found in /guard route dependencies"

    def test_execute_routes_carry_auth_dependency(self) -> None:
        from app.core.auth import require_api_key  # noqa: PLC0415

        app = self._get_app()
        execute_deps = self._route_dependencies(app, "/execute")

        if not execute_deps:
            pytest.skip("/execute routes not present in this build")

        assert require_api_key in execute_deps, "require_api_key not found in /execute route dependencies"

    def test_guard_routes_carry_agent_rate_limit_dependency(self) -> None:
        app = self._get_app()
        guard_deps = self._route_dependencies(app, "/guard")

        if not guard_deps:
            pytest.skip("/guard routes not present in this build")

        dep_qualnames = [getattr(d, "__qualname__", "") for d in guard_deps]
        assert any("agent_rate_limit_dependency" in qn for qn in dep_qualnames), f"No agent_rate_limit_dependency closure found in /guard deps. Found qualnames: {dep_qualnames}"

    def test_execute_routes_carry_agent_rate_limit_dependency(self) -> None:
        app = self._get_app()
        execute_deps = self._route_dependencies(app, "/execute")

        if not execute_deps:
            pytest.skip("/execute routes not present in this build")

        dep_qualnames = [getattr(d, "__qualname__", "") for d in execute_deps]
        assert any("agent_rate_limit_dependency" in qn for qn in dep_qualnames), f"No agent_rate_limit_dependency closure found in /execute deps. Found qualnames: {dep_qualnames}"

    def test_guard_routes_have_both_auth_and_rate_limit(self) -> None:
        """Single consolidated assertion that both deps are present together."""
        from app.core.auth import require_api_key  # noqa: PLC0415

        app = self._get_app()
        guard_deps = self._route_dependencies(app, "/guard")

        if not guard_deps:
            pytest.skip("/guard routes not present in this build")

        has_auth = require_api_key in guard_deps
        has_agent_rl = any("agent_rate_limit_dependency" in getattr(d, "__qualname__", "") for d in guard_deps)
        assert has_auth and has_agent_rl, f"Expected both require_api_key and agent_rate_limit_dependency on /guard. has_auth={has_auth}, has_agent_rl={has_agent_rl}"


# ---------------------------------------------------------------------------
# 4. Lifespan survives when all optional modules are absent (graceful no-op)
# ---------------------------------------------------------------------------


class TestLifespanGracefulNoop:
    """
    Verify the lifespan startup + shutdown completes without error when every
    optional module that main.py tries to import is unavailable (ModuleNotFoundError).
    The only modules that must remain are the core ones required for FastAPI to boot.
    """

    _OPTIONAL_MODULES = [
        "app.core.pattern_registry",
        "app.core.trust_engine",
        "app.core.auth",
        "app.core.rate_limiter",
        "app.services.history",
        "app.services.rules",
        "app.services.scanner",
        "app.services.notification_engine",
        "app.repositories.scan_history_repository",
        "app.orchestrator.secure_runtime_pipeline",
        "app.dependencies.action_execute",
        "app.services.threat_feed_scheduler",
        "app.worker.remediation_worker",
        "app.bootstrap",
        "app.core.errors",
        "app.core.docs",
        "app.core.middleware",
        "app.core.request_id",
        "app.core.logging",
        "app.ui.router",
    ]

    def test_startup_succeeds_with_all_optionals_missing(self) -> None:
        saved: dict[str, Any] = {}
        for mod in self._OPTIONAL_MODULES:
            if mod in sys.modules:
                saved[mod] = sys.modules[mod]
            sys.modules[mod] = None  # type: ignore[assignment]

        main_saved = sys.modules.pop("app.main", None)

        try:
            from app import main as main_mod  # noqa: PLC0415

            app_instance = main_mod.create_app()
            with TestClient(app_instance, raise_server_exceptions=True) as client:
                resp = client.get("/health")
            assert resp.status_code == 200
        finally:
            if main_saved is not None:
                sys.modules["app.main"] = main_saved
            else:
                sys.modules.pop("app.main", None)

            for mod in self._OPTIONAL_MODULES:
                if mod in saved:
                    sys.modules[mod] = saved[mod]
                else:
                    sys.modules.pop(mod, None)

    def test_health_endpoint_returns_ok_after_degraded_startup(self) -> None:
        from app.main import create_app  # noqa: PLC0415

        with patch("app.main._initialize_pattern_registry", side_effect=Exception("registry down")):
            with patch("app.main._initialize_notification_engine", side_effect=Exception("notify down")):
                with patch("app.main._start_threat_feed_scheduler", side_effect=Exception("sched down")):
                    app_instance = create_app()
                    with TestClient(app_instance, raise_server_exceptions=True) as client:
                        resp = client.get("/health")
        assert resp.status_code == 200

    def test_shutdown_completes_when_optional_shutdown_hooks_raise(self) -> None:
        from app.main import create_app  # noqa: PLC0415

        with patch("app.main._shutdown_trust_engine_cache", side_effect=Exception("trust down")):
            with patch("app.main._shutdown_pattern_registry", side_effect=Exception("registry down")):
                with patch("app.main._stop_threat_feed_scheduler", side_effect=Exception("sched down")):
                    app_instance = create_app()
                    with TestClient(app_instance, raise_server_exceptions=True) as client:
                        resp = client.get("/health")
        assert resp.status_code == 200

    def test_liveness_endpoint_available(self) -> None:
        from app.main import create_app  # noqa: PLC0415

        app_instance = create_app()
        with TestClient(app_instance, raise_server_exceptions=True) as client:
            resp = client.get("/health/liveness")
        assert resp.status_code == 200

    def test_readiness_endpoint_available(self) -> None:
        from app.main import create_app  # noqa: PLC0415

        app_instance = create_app()
        with TestClient(app_instance, raise_server_exceptions=True) as client:
            resp = client.get("/health/readiness")
        assert resp.status_code == 200
