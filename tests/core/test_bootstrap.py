from __future__ import annotations

import logging
from unittest.mock import patch

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
import pytest

from app.bootstrap import (
    DefaultActionDecisionService,
    DefaultActionPolicyService,
    DefaultGuardService,
    DefaultScannerService,
    InMemoryHistoryService,
    _run_deferred_startup,
    add_request_tracing_middleware,
    add_security_middleware,
    assert_schema_completeness,
    bootstrap_app,
    configure_app_state,
)
from app.persistencebootstrap import (
    InMemoryPersistenceStore,
    get_registered_tables,
)

_EXPECTED_TABLE_COUNT = 19
_BOOTSTRAP_PATCH = "app.bootstrap.get_registered_tables"
_STORE_PATCH = "app.bootstrap.get_persistence_store"


# ===========================================================================
# Helpers
# ===========================================================================


def _fresh_app() -> FastAPI:
    return FastAPI()


def _real_table_set() -> frozenset[str]:
    return get_registered_tables()


# ===========================================================================
# assert_schema_completeness
# ===========================================================================


class TestAssertSchemaCompleteness:
    def test_passes_and_returns_frozenset(self):
        result = assert_schema_completeness()
        assert isinstance(result, frozenset)

    def test_returns_all_19_tables(self):
        result = assert_schema_completeness()
        assert len(result) == _EXPECTED_TABLE_COUNT

    def test_return_value_matches_registry(self):
        result = assert_schema_completeness()
        assert result == _real_table_set()

    def test_all_table_names_are_strings(self):
        result = assert_schema_completeness()
        assert all(isinstance(t, str) for t in result)

    def test_all_table_names_are_nonempty(self):
        result = assert_schema_completeness()
        assert all(len(t) > 0 for t in result)

    def test_raises_runtime_error_on_wrong_count_too_few(self):
        fake = frozenset({"table_a", "table_b"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError, match="schema completeness check failed"):
                assert_schema_completeness()

    def test_raises_runtime_error_on_empty_registry(self):
        with patch(_BOOTSTRAP_PATCH, return_value=frozenset()):
            with pytest.raises(RuntimeError, match="expected 19 tables"):
                assert_schema_completeness()

    def test_raises_runtime_error_on_wrong_count_too_many(self):
        fake = frozenset({f"table_{i}" for i in range(25)})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError, match="schema completeness check failed"):
                assert_schema_completeness()

    def test_error_message_contains_table_count(self):
        fake = frozenset({"only_one"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError) as exc_info:
                assert_schema_completeness()
        assert "19" in str(exc_info.value)

    def test_error_message_contains_actual_count(self):
        fake = frozenset({"only_one"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError) as exc_info:
                assert_schema_completeness()
        assert "1" in str(exc_info.value)


# ===========================================================================
# _run_deferred_startup  (replaces TestBootstrapAppSchemaGate)
#
# bootstrap_app() no longer calls assert_schema_completeness() synchronously.
# The schema gate now lives in _run_deferred_startup(), which is registered as
# a startup event handler. It must log a critical error on failure — NOT raise —
# so a schema mismatch never kills the import path or test collection.
# ===========================================================================


class TestRunDeferredStartup:
    def test_succeeds_silently_on_valid_schema(self, caplog):
        app = _fresh_app()
        with caplog.at_level(logging.INFO, logger="app.bootstrap"):
            _run_deferred_startup(app)
        # No critical log on success
        assert not any(r.levelno >= logging.CRITICAL for r in caplog.records)

    def test_logs_critical_on_wrong_table_count(self, caplog):
        app = _fresh_app()
        fake = frozenset({"table_a", "table_b"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with caplog.at_level(logging.CRITICAL, logger="app.bootstrap"):
                _run_deferred_startup(app)
        assert any(r.levelno >= logging.CRITICAL for r in caplog.records)

    def test_does_not_raise_on_wrong_table_count(self):
        app = _fresh_app()
        fake = frozenset({"table_a"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            # Must not raise — deferred startup is fail-open for server continuity
            _run_deferred_startup(app)

    def test_does_not_raise_on_empty_registry(self):
        app = _fresh_app()
        with patch(_BOOTSTRAP_PATCH, return_value=frozenset()):
            _run_deferred_startup(app)

    def test_critical_log_contains_schema_context(self, caplog):
        app = _fresh_app()
        fake = frozenset({"only_one"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with caplog.at_level(logging.CRITICAL, logger="app.bootstrap"):
                _run_deferred_startup(app)
        critical_messages = [r.message for r in caplog.records if r.levelno >= logging.CRITICAL]
        assert any("schema" in m.lower() for m in critical_messages)

    def test_succeeds_with_correct_table_count(self, caplog):
        app = _fresh_app()
        with caplog.at_level(logging.INFO, logger="app.bootstrap"):
            _run_deferred_startup(app)
        # INFO pass log from assert_schema_completeness should be present
        assert any(r.levelno == logging.INFO for r in caplog.records)


# ===========================================================================
# bootstrap_app — startup event registration
# ===========================================================================


class TestBootstrapAppStartupEvent:
    def test_startup_event_is_registered(self):
        app = _fresh_app()
        bootstrap_app(app)
        # FastAPI stores on_event("startup") handlers in router.on_startup
        assert len(app.router.on_startup) >= 1

    def test_startup_flag_set_after_bootstrap(self):
        app = _fresh_app()
        bootstrap_app(app)
        assert getattr(app.state, "_bootstrap_startup_registered", False) is True

    def test_startup_event_not_duplicated_on_second_call(self):
        app = _fresh_app()
        bootstrap_app(app)
        count_after_first = len(app.router.on_startup)
        bootstrap_app(app)
        assert len(app.router.on_startup) == count_after_first

    @pytest.mark.anyio
    async def test_startup_event_runs_without_raising(self):
        app = _fresh_app()
        bootstrap_app(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Startup fires here; must not raise
            response = await client.get("/nonexistent")
        assert response.status_code in {404, 200}

    @pytest.mark.anyio
    async def test_startup_event_logs_schema_pass(self, caplog):
        app = _fresh_app()
        bootstrap_app(app)
        with caplog.at_level(logging.INFO, logger="app.bootstrap"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                await client.get("/nonexistent")
        assert any("schema" in r.message.lower() for r in caplog.records)


# ===========================================================================
# bootstrap_app — idempotency
# ===========================================================================


class TestBootstrapAppIdempotency:
    def test_bootstrap_installs_flag(self):
        app = _fresh_app()
        bootstrap_app(app)
        assert app.state._bootstrap_installed is True

    def test_bootstrap_is_idempotent(self):
        app = _fresh_app()
        bootstrap_app(app)
        bootstrap_app(app)
        assert app.state._bootstrap_installed is True

    def test_bootstrap_returns_same_app(self):
        app = _fresh_app()
        result = bootstrap_app(app)
        assert result is app

    def test_double_bootstrap_does_not_duplicate_middleware(self):
        app = _fresh_app()
        bootstrap_app(app)
        middleware_count = len(app.user_middleware)
        bootstrap_app(app)
        assert len(app.user_middleware) == middleware_count


# ===========================================================================
# configure_app_state
# ===========================================================================


class TestConfigureAppState:
    def test_sets_scanner_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert isinstance(app.state.scanner_service, DefaultScannerService)

    def test_sets_history_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert isinstance(app.state.history_service, InMemoryHistoryService)

    def test_sets_guard_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert isinstance(app.state.guard_service, DefaultGuardService)

    def test_sets_action_policy_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert isinstance(app.state.action_policy_service, DefaultActionPolicyService)

    def test_sets_action_decision_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert isinstance(app.state.action_decision_service, DefaultActionDecisionService)

    def test_sets_persistence_store_or_none(self):
        app = _fresh_app()
        with patch(_STORE_PATCH, return_value=InMemoryPersistenceStore()):
            configure_app_state(app)
        assert app.state.persistence_store is not None

    def test_persistence_store_none_on_failure(self):
        app = _fresh_app()
        with patch(_STORE_PATCH, side_effect=RuntimeError("no creds")):
            configure_app_state(app)
        assert app.state.persistence_store is None

    def test_configure_is_idempotent_for_scanner(self):
        app = _fresh_app()
        configure_app_state(app)
        original = app.state.scanner_service
        configure_app_state(app)
        assert app.state.scanner_service is original

    def test_configure_is_idempotent_for_history(self):
        app = _fresh_app()
        configure_app_state(app)
        original = app.state.history_service
        configure_app_state(app)
        assert app.state.history_service is original

    def test_sets_action_execute_pipeline_none(self):
        app = _fresh_app()
        configure_app_state(app)
        assert app.state.action_execute_pipeline is None

    def test_returns_app(self):
        app = _fresh_app()
        result = configure_app_state(app)
        assert result is app


# ===========================================================================
# add_request_tracing_middleware
# ===========================================================================


class TestAddRequestTracingMiddleware:
    def test_installs_flag(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)
        assert app.state._request_tracing_middleware_installed is True

    def test_is_idempotent(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)
        count = len(app.user_middleware)
        add_request_tracing_middleware(app)
        assert len(app.user_middleware) == count

    def test_returns_app(self):
        app = _fresh_app()
        result = add_request_tracing_middleware(app)
        assert result is app

    @pytest.mark.anyio
    async def test_injects_request_id_header(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "x-request-id" in response.headers

    @pytest.mark.anyio
    async def test_injects_trace_id_header(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "x-trace-id" in response.headers

    @pytest.mark.anyio
    async def test_injects_response_time_header(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "x-response-time-ms" in response.headers

    @pytest.mark.anyio
    async def test_propagates_incoming_request_id(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping", headers={"X-Request-ID": "test-req-123"})
        assert response.headers["x-request-id"] == "test-req-123"


# ===========================================================================
# add_security_middleware
# ===========================================================================


class TestAddSecurityMiddleware:
    def test_installs_flag(self):
        app = _fresh_app()
        add_security_middleware(app)
        assert app.state._security_middleware_installed is True

    def test_is_idempotent(self):
        app = _fresh_app()
        add_security_middleware(app)
        count = len(app.user_middleware)
        add_security_middleware(app)
        assert len(app.user_middleware) == count

    def test_returns_app(self):
        app = _fresh_app()
        result = add_security_middleware(app)
        assert result is app

    @pytest.mark.anyio
    async def test_injects_x_frame_options(self):
        app = _fresh_app()
        add_security_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert response.headers.get("x-frame-options") == "DENY"

    @pytest.mark.anyio
    async def test_injects_x_content_type_options(self):
        app = _fresh_app()
        add_security_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert response.headers.get("x-content-type-options") == "nosniff"

    @pytest.mark.anyio
    async def test_injects_referrer_policy(self):
        app = _fresh_app()
        add_security_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert response.headers.get("referrer-policy") == "no-referrer"

    @pytest.mark.anyio
    async def test_injects_cache_control(self):
        app = _fresh_app()
        add_security_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert response.headers.get("cache-control") == "no-store"

    @pytest.mark.anyio
    async def test_injects_csp_header(self):
        app = _fresh_app()
        add_security_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "content-security-policy" in response.headers

    @pytest.mark.anyio
    async def test_injects_permissions_policy(self):
        app = _fresh_app()
        add_security_middleware(app)

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "permissions-policy" in response.headers


# ===========================================================================
# InMemoryHistoryService
# ===========================================================================


class TestInMemoryHistoryService:
    def test_empty_on_init(self):
        svc = InMemoryHistoryService()
        assert svc.list_results() == []

    def test_append_and_list(self):
        svc = InMemoryHistoryService()
        svc.append_scan_result({"scan_id": "abc", "verdict": "allow"})
        results = svc.list_results()
        assert len(results) == 1
        assert results[0]["scan_id"] == "abc"

    def test_get_result_found(self):
        svc = InMemoryHistoryService()
        svc.append_scan_result({"scan_id": "xyz", "verdict": "block"})
        result = svc.get_result("xyz")
        assert result is not None
        assert result["verdict"] == "block"

    def test_get_result_not_found(self):
        svc = InMemoryHistoryService()
        assert svc.get_result("nonexistent") is None

    def test_append_isolates_copy(self):
        svc = InMemoryHistoryService()
        original = {"scan_id": "s1", "verdict": "warn"}
        svc.append_scan_result(original)
        original["verdict"] = "mutated"
        assert svc.list_results()[0]["verdict"] == "warn"

    def test_list_results_returns_copy(self):
        svc = InMemoryHistoryService()
        svc.append_scan_result({"scan_id": "s2", "verdict": "allow"})
        results = svc.list_results()
        results.clear()
        assert len(svc.list_results()) == 1

    def test_multiple_appends(self):
        svc = InMemoryHistoryService()
        for i in range(5):
            svc.append_scan_result({"scan_id": f"s{i}"})
        assert len(svc.list_results()) == 5

    def test_get_result_returns_copy(self):
        svc = InMemoryHistoryService()
        svc.append_scan_result({"scan_id": "s3", "verdict": "allow"})
        fetched = svc.get_result("s3")
        fetched["verdict"] = "tampered"
        assert svc.get_result("s3")["verdict"] == "allow"
