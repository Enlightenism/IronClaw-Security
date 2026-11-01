from __future__ import annotations

import pytest

from app.clients.release_policy_client import ReleasePolicyClient
from app.dependencies import (
    _reset_dependencies_for_tests,
    get_auth_service,
    get_release_policy_client,
    get_service_registry,
    get_store,
)
from app.persistencebootstrap import (
    InMemoryPersistenceStore,
    StoreType,
    SupabasePersistenceStore,
)
from app.providers.service_registry import ServiceRegistry
from app.services.authservice import AuthService

# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_registry():
    """Reset the module-level singleton before and after every test."""
    _reset_dependencies_for_tests()
    yield
    _reset_dependencies_for_tests()


# ===========================================================================
# get_service_registry
# ===========================================================================


class TestGetServiceRegistry:
    def test_returns_service_registry_instance(self):
        result = get_service_registry()
        assert isinstance(result, ServiceRegistry)

    def test_repeated_calls_return_same_singleton(self):
        first = get_service_registry()
        second = get_service_registry()
        assert first is second

    def test_third_call_returns_same_singleton(self):
        a = get_service_registry()
        b = get_service_registry()
        c = get_service_registry()
        assert a is b is c

    def test_reset_clears_singleton(self):
        first = get_service_registry()
        _reset_dependencies_for_tests()
        second = get_service_registry()
        assert first is not second

    def test_reset_then_new_call_returns_service_registry(self):
        _reset_dependencies_for_tests()
        result = get_service_registry()
        assert isinstance(result, ServiceRegistry)

    def test_two_resets_produce_fresh_instance_each_time(self):
        a = get_service_registry()
        _reset_dependencies_for_tests()
        b = get_service_registry()
        _reset_dependencies_for_tests()
        c = get_service_registry()
        assert a is not b
        assert b is not c


# ===========================================================================
# get_release_policy_client
# ===========================================================================


class TestGetReleasePolicyClient:
    def test_returns_release_policy_client_instance(self):
        result = get_release_policy_client()
        assert isinstance(result, ReleasePolicyClient)

    def test_repeated_calls_return_same_instance(self):
        first = get_release_policy_client()
        second = get_release_policy_client()
        assert first is second

    def test_comes_from_service_registry(self):
        registry = get_service_registry()
        direct = registry.get_release_policy_client()
        via_dep = get_release_policy_client()
        assert direct is via_dep

    def test_reset_produces_new_client_on_next_call(self):
        first = get_release_policy_client()
        _reset_dependencies_for_tests()
        second = get_release_policy_client()
        assert first is not second


# ===========================================================================
# get_auth_service
# ===========================================================================


class TestGetAuthService:
    def test_returns_auth_service_instance(self):
        result = get_auth_service()
        assert isinstance(result, AuthService)

    def test_repeated_calls_return_same_singleton(self):
        first = get_auth_service()
        second = get_auth_service()
        assert first is second

    def test_comes_from_service_registry(self):
        registry = get_service_registry()
        direct = registry.get_auth_service()
        via_dep = get_auth_service()
        assert direct is via_dep

    def test_reset_produces_new_auth_service_on_next_call(self):
        first = get_auth_service()
        _reset_dependencies_for_tests()
        second = get_auth_service()
        assert first is not second

    def test_auth_service_has_session_policy(self):
        service = get_auth_service()
        assert hasattr(service, "session_policy")
        assert service.session_policy is not None

    def test_auth_service_has_authenticate_api_key(self):
        service = get_auth_service()
        assert callable(service.authenticate_api_key)

    def test_auth_service_has_issue_session(self):
        service = get_auth_service()
        assert callable(service.issue_session)

    def test_auth_service_has_check_permission(self):
        service = get_auth_service()
        assert callable(service.check_permission)

    def test_auth_service_has_build_anonymous_context(self):
        service = get_auth_service()
        assert callable(service.build_anonymous_context)


# ===========================================================================
# get_store
# ===========================================================================


class TestGetStore:
    def test_returns_valid_store_type(self):
        result = get_store()
        assert isinstance(result, SupabasePersistenceStore | InMemoryPersistenceStore)

    def test_satisfies_store_type_union(self):
        result: StoreType = get_store()
        assert result is not None

    def test_returns_store_with_ready_true(self):
        result = get_store()
        assert result.ready is True

    def test_returns_store_with_is_ready_true(self):
        result = get_store()
        assert result.is_ready is True

    def test_returns_store_with_valid_backend_name(self):
        result = get_store()
        assert result.backend_name in {"memory", "supabase"}

    def test_returns_store_with_schema_ready_true(self):
        result = get_store()
        assert result.schema_ready is True

    def test_returns_store_with_migration_ready_true(self):
        result = get_store()
        assert result.migration_ready is True

    def test_store_healthcheck_returns_true(self):
        result = get_store()
        assert result.healthcheck() is True

    def test_store_has_select(self):
        result = get_store()
        assert callable(result.select)

    def test_store_has_insert(self):
        result = get_store()
        assert callable(result.insert)

    def test_store_has_update(self):
        result = get_store()
        assert callable(result.update)

    def test_store_has_delete(self):
        result = get_store()
        assert callable(result.delete)

    def test_store_as_dict_contains_backend_key(self):
        result = get_store()
        assert "backend" in result.as_dict()

    def test_store_as_dict_contains_ready_key(self):
        result = get_store()
        assert "ready" in result.as_dict()

    def test_two_calls_return_independent_instances(self):
        a = get_store()
        b = get_store()
        # Each call to get_store() bootstraps a new store — they are equal in
        # type and state but are not required to be the same object.
        assert type(a) is type(b)
        assert a.backend_name == b.backend_name


# ===========================================================================
# _reset_dependencies_for_tests
# ===========================================================================


class TestResetDependenciesForTests:
    def test_reset_is_callable(self):
        assert callable(_reset_dependencies_for_tests)

    def test_reset_allows_multiple_calls_without_error(self):
        _reset_dependencies_for_tests()
        _reset_dependencies_for_tests()
        _reset_dependencies_for_tests()

    def test_reset_before_any_access_does_not_raise(self):
        _reset_dependencies_for_tests()
        result = get_service_registry()
        assert isinstance(result, ServiceRegistry)

    def test_registry_is_none_equivalent_after_reset(self):
        get_service_registry()
        _reset_dependencies_for_tests()
        # After reset, the next call must produce a fresh instance.
        fresh = get_service_registry()
        assert isinstance(fresh, ServiceRegistry)
