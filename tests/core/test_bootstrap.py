from __future__ import annotations

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

    def test_raises_runtime_error_on_count_too_high(self):
        extra = frozenset({f"table_{i}" for i in range(_EXPECTED_TABLE_COUNT + 5)})
        with patch(_BOOTSTRAP_PATCH, return_value=extra):
            with pytest.raises(RuntimeError, match="schema completeness check failed"):
                assert_schema_completeness()

    def test_error_message_contains_actual_count(self):
        fake = frozenset({"only_one"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError) as exc_info:
                assert_schema_completeness()
        assert "1" in str(exc_info.value)

    def test_error_message_contains_expected_count(self):
        fake = frozenset({"only_one"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError) as exc_info:
                assert_schema_completeness()
        assert "19" in str(exc_info.value)

    def test_called_twice_returns_same_result(self):
        first = assert_schema_completeness()
        second = assert_schema_completeness()
        assert first == second


# ===========================================================================
# configure_app_state
# ===========================================================================


class TestConfigureAppState:
    def test_returns_fastapi_instance(self):
        app = _fresh_app()
        result = configure_app_state(app)
        assert isinstance(result, FastAPI)

    def test_returns_same_app_instance(self):
        app = _fresh_app()
        result = configure_app_state(app)
        assert result is app

    def test_sets_settings(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "settings")
        assert app.state.settings is not None

    def test_sets_persistence_store(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "persistence_store")

    def test_persistence_store_is_valid_type_or_none(self):
        app = _fresh_app()
        configure_app_state(app)
        store = app.state.persistence_store
        assert store is None or isinstance(store, (InMemoryPersistenceStore,))

    def test_persistence_store_ready_when_present(self):
        app = _fresh_app()
        configure_app_state(app)
        store = app.state.persistence_store
        if store is not None:
            assert store.ready is True

    def test_sets_scanner_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "scanner_service")
        assert isinstance(app.state.scanner_service, DefaultScannerService)

    def test_sets_history_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "history_service")
        assert isinstance(app.state.history_service, InMemoryHistoryService)

    def test_sets_guard_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "guard_service")
        assert isinstance(app.state.guard_service, DefaultGuardService)

    def test_sets_action_policy_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "action_policy_service")
        assert isinstance(app.state.action_policy_service, DefaultActionPolicyService)

    def test_sets_action_decision_service(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "action_decision_service")
        assert isinstance(app.state.action_decision_service, DefaultActionDecisionService)

    def test_sets_action_execute_pipeline(self):
        app = _fresh_app()
        configure_app_state(app)
        assert hasattr(app.state, "action_execute_pipeline")

    def test_idempotent_does_not_overwrite_existing_settings(self):
        app = _fresh_app()
        configure_app_state(app)
        original_settings = app.state.settings
        configure_app_state(app)
        assert app.state.settings is original_settings

    def test_idempotent_does_not_overwrite_existing_scanner_service(self):
        app = _fresh_app()
        configure_app_state(app)
        original = app.state.scanner_service
        configure_app_state(app)
        assert app.state.scanner_service is original

    def test_persistence_store_failure_sets_none(self):
        app = _fresh_app()
        with patch(_STORE_PATCH, side_effect=RuntimeError("no store")):
            configure_app_state(app)
        assert app.state.persistence_store is None


# ===========================================================================
# add_request_tracing_middleware
# ===========================================================================


class TestAddRequestTracingMiddleware:
    @pytest.mark.anyio
    async def test_x_request_id_header_injected(self):
        app = _fresh_app()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        add_request_tracing_middleware(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "x-request-id" in response.headers

    @pytest.mark.anyio
    async def test_x_trace_id_header_injected(self):
        app = _fresh_app()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        add_request_tracing_middleware(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "x-trace-id" in response.headers

    @pytest.mark.anyio
    async def test_x_response_time_ms_header_injected(self):
        app = _fresh_app()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        add_request_tracing_middleware(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert "x-response-time-ms" in response.headers

    @pytest.mark.anyio
    async def test_x_response_time_ms_is_numeric(self):
        app = _fresh_app()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        add_request_tracing_middleware(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping")
        assert response.headers["x-response-time-ms"].isdigit()

    @pytest.mark.anyio
    async def test_provided_request_id_is_echoed(self):
        app = _fresh_app()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        add_request_tracing_middleware(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping", headers={"X-Request-ID": "test-req-123"})
        assert response.headers["x-request-id"] == "test-req-123"

    @pytest.mark.anyio
    async def test_provided_trace_id_is_echoed(self):
        app = _fresh_app()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        add_request_tracing_middleware(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/ping", headers={"X-Trace-ID": "trace-abc-456"})
        assert response.headers["x-trace-id"] == "trace-abc-456"

    def test_idempotent_flag_set(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)
        assert getattr(app.state, "_request_tracing_middleware_installed", False) is True

    def test_second_call_is_no_op(self):
        app = _fresh_app()
        add_request_tracing_middleware(app)
        routes_after_first = len(app.middleware_stack.__class__.__mro__)
        add_request_tracing_middleware(app)
        routes_after_second = len(app.middleware_stack.__class__.__mro__)
        assert routes_after_first == routes_after_second


# ===========================================================================
# add_security_middleware
# ===========================================================================


class TestAddSecurityMiddleware:
    @pytest.mark.anyio
    async def _get_secure_response(self):
        app = _fresh_app()

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        add_security_middleware(app)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/ping")

    @pytest.mark.anyio
    async def test_x_frame_options_deny(self):
        response = await self._get_secure_response()
        assert response.headers.get("x-frame-options") == "DENY"

    @pytest.mark.anyio
    async def test_x_content_type_options_nosniff(self):
        response = await self._get_secure_response()
        assert response.headers.get("x-content-type-options") == "nosniff"

    @pytest.mark.anyio
    async def test_referrer_policy_no_referrer(self):
        response = await self._get_secure_response()
        assert response.headers.get("referrer-policy") == "no-referrer"

    @pytest.mark.anyio
    async def test_x_xss_protection_header(self):
        response = await self._get_secure_response()
        assert response.headers.get("x-xss-protection") == "1; mode=block"

    @pytest.mark.anyio
    async def test_permissions_policy_header(self):
        response = await self._get_secure_response()
        assert "permissions-policy" in response.headers

    @pytest.mark.anyio
    async def test_cross_origin_opener_policy(self):
        response = await self._get_secure_response()
        assert response.headers.get("cross-origin-opener-policy") == "same-origin"

    @pytest.mark.anyio
    async def test_cross_origin_resource_policy(self):
        response = await self._get_secure_response()
        assert response.headers.get("cross-origin-resource-policy") == "same-origin"

    @pytest.mark.anyio
    async def test_cache_control_no_store(self):
        response = await self._get_secure_response()
        assert response.headers.get("cache-control") == "no-store"

    @pytest.mark.anyio
    async def test_content_security_policy_present(self):
        response = await self._get_secure_response()
        assert "content-security-policy" in response.headers

    @pytest.mark.anyio
    async def test_csp_denies_frame_ancestors(self):
        response = await self._get_secure_response()
        csp = response.headers.get("content-security-policy", "")
        assert "frame-ancestors 'none'" in csp

    def test_idempotent_flag_set(self):
        app = _fresh_app()
        add_security_middleware(app)
        assert getattr(app.state, "_security_middleware_installed", False) is True

    def test_second_call_is_no_op(self):
        app = _fresh_app()
        add_security_middleware(app)
        flag_after_first = app.state._security_middleware_installed
        add_security_middleware(app)
        flag_after_second = app.state._security_middleware_installed
        assert flag_after_first is flag_after_second is True


# ===========================================================================
# bootstrap_app — idempotency
# ===========================================================================


class TestBootstrapAppIdempotency:
    def test_returns_fastapi_instance(self):
        app = _fresh_app()
        result = bootstrap_app(app)
        assert isinstance(result, FastAPI)

    def test_returns_same_app_instance(self):
        app = _fresh_app()
        result = bootstrap_app(app)
        assert result is app

    def test_bootstrap_installed_flag_set(self):
        app = _fresh_app()
        bootstrap_app(app)
        assert getattr(app.state, "_bootstrap_installed", False) is True

    def test_second_call_is_no_op_same_app(self):
        app = _fresh_app()
        bootstrap_app(app)
        scanner_first = app.state.scanner_service
        bootstrap_app(app)
        assert app.state.scanner_service is scanner_first

    def test_third_call_is_no_op(self):
        app = _fresh_app()
        bootstrap_app(app)
        history_first = app.state.history_service
        bootstrap_app(app)
        bootstrap_app(app)
        assert app.state.history_service is history_first

    def test_idempotent_across_different_calls_does_not_change_flag(self):
        app = _fresh_app()
        bootstrap_app(app)
        bootstrap_app(app)
        assert app.state._bootstrap_installed is True

    def test_fresh_app_does_not_have_flag_before_bootstrap(self):
        app = _fresh_app()
        assert getattr(app.state, "_bootstrap_installed", False) is False


# ===========================================================================
# bootstrap_app — schema check gate
# ===========================================================================


class TestBootstrapAppSchemaGate:
    def test_raises_runtime_error_when_schema_check_fails(self):
        app = _fresh_app()
        fake = frozenset({"only_one_table"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError, match="schema completeness check failed"):
                bootstrap_app(app)

    def test_app_state_not_modified_when_schema_check_fails(self):
        app = _fresh_app()
        fake = frozenset({"only_one_table"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError):
                bootstrap_app(app)
        assert not getattr(app.state, "_bootstrap_installed", False)

    def test_app_scanner_service_not_set_when_schema_check_fails(self):
        app = _fresh_app()
        fake = frozenset({"only_one_table"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError):
                bootstrap_app(app)
        assert not hasattr(app.state, "scanner_service")

    def test_app_history_service_not_set_when_schema_check_fails(self):
        app = _fresh_app()
        fake = frozenset({"only_one_table"})
        with patch(_BOOTSTRAP_PATCH, return_value=fake):
            with pytest.raises(RuntimeError):
                bootstrap_app(app)
        assert not hasattr(app.state, "history_service")

    def test_schema_error_propagates_verbatim(self):
        app = _fresh_app()
        with patch(_BOOTSTRAP_PATCH, return_value=frozenset()):
            with pytest.raises(RuntimeError) as exc_info:
                bootstrap_app(app)
        assert "19" in str(exc_info.value)

    def test_bootstrap_succeeds_after_schema_is_patched_correctly(self):
        app = _fresh_app()
        correct = frozenset({f"table_{i}" for i in range(_EXPECTED_TABLE_COUNT)})
        with patch(_BOOTSTRAP_PATCH, return_value=correct):
            result = bootstrap_app(app)
        assert result is app
        assert app.state._bootstrap_installed is True


# ===========================================================================
# InMemoryHistoryService (standalone)
# ===========================================================================


class TestInMemoryHistoryService:
    def test_list_results_empty_on_init(self):
        svc = InMemoryHistoryService()
        assert svc.list_results() == []

    def test_append_and_retrieve(self):
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

    def test_get_result_not_found_returns_none(self):
        svc = InMemoryHistoryService()
        assert svc.get_result("missing") is None

    def test_append_stores_copy(self):
        svc = InMemoryHistoryService()
        item = {"scan_id": "s1", "data": "original"}
        svc.append_scan_result(item)
        item["data"] = "mutated"
        assert svc.list_results()[0]["data"] == "original"

    def test_list_results_returns_copy(self):
        svc = InMemoryHistoryService()
        svc.append_scan_result({"scan_id": "s2"})
        lst = svc.list_results()
        lst.clear()
        assert len(svc.list_results()) == 1
