from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.persistencebootstrap import (
    _IRONCLAW_DDL_TABLE_REGISTRY,
    MEMORY_MODE,
    SUPABASE_MODE,
    InMemoryPersistenceStore,
    PersistenceBootstrapState,
    PersistenceStore,
    StoreType,
    SupabasePersistenceStore,
    build_rate_limit_store,
    build_store,
    create_rate_limit_store,
    create_store,
    get_checkpoint_store,
    get_organization_store,
    get_persistence_bootstrap_state,
    get_persistence_store,
    get_rate_limit_store,
    get_registered_tables,
    get_review_state_store,
    get_runtime_state_store,
    get_store,
    get_telemetry_store,
)
from app.supabaseclient import IRONCLAW_TABLES

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EXPECTED_TABLE_COUNT = 19

_ALL_EXPECTED_TABLES: frozenset[str] = frozenset(
    {
        "scan_history",
        "scan_patterns",
        "policy_rules",
        "policy_sets",
        "policy_set_memberships",
        "agents",
        "agent_trust_profiles",
        "trust_events",
        "telemetry_events",
        "audit_events",
        "iocs",
        "threat_detections",
        "quarantine_items",
        "review_queue",
        "rate_limit_state",
        "tool_call_log",
        "sandbox_execution_log",
        "webhook_subscriptions",
        "webhook_deliveries",
    }
)

_ENV_PATCH_TARGET = "app.persistencebootstrap._supabase_env_present"
_FACTORY_PATCH_TARGET = "app.persistencebootstrap._build_supabase_store"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_supabase_store() -> MagicMock:
    store = MagicMock(spec=SupabasePersistenceStore)
    store.backend = SUPABASE_MODE
    store.backend_name = SUPABASE_MODE
    store.store_type = SUPABASE_MODE
    store.provider = SUPABASE_MODE
    store.persistence = SUPABASE_MODE
    store.mode = SUPABASE_MODE
    store.fallback_enabled = True
    store.fallback_reason = None
    store.schema_ready = True
    store.migration_ready = True
    store.migrations_ready = True
    store.bootstrap_ready = True
    store.ready = True
    store.is_ready = True
    store.healthcheck.return_value = True
    return store


def _memory_store() -> InMemoryPersistenceStore:
    return InMemoryPersistenceStore()


# ===========================================================================
# get_registered_tables
# ===========================================================================


class TestGetRegisteredTables:

    def test_returns_frozenset(self):
        result = get_registered_tables()
        assert isinstance(result, frozenset)

    def test_equals_ironclaw_tables(self):
        assert get_registered_tables() == IRONCLAW_TABLES

    def test_equals_ddl_registry(self):
        assert get_registered_tables() == _IRONCLAW_DDL_TABLE_REGISTRY

    def test_contains_exactly_19_tables(self):
        assert len(get_registered_tables()) == _EXPECTED_TABLE_COUNT

    def test_contains_all_expected_table_names(self):
        assert get_registered_tables() == _ALL_EXPECTED_TABLES

    def test_is_immutable(self):
        result = get_registered_tables()
        with pytest.raises((AttributeError, TypeError)):
            result.add("injected_table")  # type: ignore[attr-defined]

    def test_rate_limit_state_in_registry(self):
        assert "rate_limit_state" in get_registered_tables()

    def test_scan_history_in_registry(self):
        assert "scan_history" in get_registered_tables()

    def test_audit_events_in_registry(self):
        assert "audit_events" in get_registered_tables()

    def test_webhook_deliveries_in_registry(self):
        assert "webhook_deliveries" in get_registered_tables()


# ===========================================================================
# DDL registry / IRONCLAW_TABLES sync guard
# ===========================================================================


class TestDDLRegistrySyncGuard:

    def test_ddl_registry_equals_ironclaw_tables(self):
        assert _IRONCLAW_DDL_TABLE_REGISTRY == IRONCLAW_TABLES

    def test_no_tables_missing_from_registry(self):
        missing = IRONCLAW_TABLES - _IRONCLAW_DDL_TABLE_REGISTRY
        assert missing == frozenset()

    def test_no_extra_tables_in_registry(self):
        extra = _IRONCLAW_DDL_TABLE_REGISTRY - IRONCLAW_TABLES
        assert extra == frozenset()

    def test_registry_count_matches_ironclaw_tables_count(self):
        assert len(_IRONCLAW_DDL_TABLE_REGISTRY) == len(IRONCLAW_TABLES)

    def test_rate_limit_state_in_both(self):
        assert "rate_limit_state" in _IRONCLAW_DDL_TABLE_REGISTRY
        assert "rate_limit_state" in IRONCLAW_TABLES

    def test_import_time_guard_fires_on_registry_mismatch(self):
        incomplete_registry: frozenset[str] = frozenset({"scan_history"})
        missing = IRONCLAW_TABLES - incomplete_registry
        assert missing
        with pytest.raises(RuntimeError, match="missing tables"):
            if missing:
                raise RuntimeError(f"persistencebootstrap DDL registry is missing tables: {sorted(missing)}")

    def test_import_time_guard_fires_on_extra_tables(self):
        bloated_registry = _IRONCLAW_DDL_TABLE_REGISTRY | frozenset({"ghost_table"})
        extra = bloated_registry - IRONCLAW_TABLES
        assert extra
        with pytest.raises(RuntimeError, match="unknown tables"):
            if extra:
                raise RuntimeError(f"persistencebootstrap DDL registry has unknown tables: {sorted(extra)}")


# ===========================================================================
# get_persistence_store
# ===========================================================================


class TestGetPersistenceStore:

    def test_returns_valid_store_type_memory_mode(self):
        result = get_persistence_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_returns_in_memory_store_when_mode_memory(self):
        result = get_persistence_store(mode=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_returns_store_with_ready_true(self):
        result = get_persistence_store(mode=MEMORY_MODE)
        assert result.ready is True

    def test_returns_store_with_is_ready_true(self):
        result = get_persistence_store(mode=MEMORY_MODE)
        assert result.is_ready is True

    def test_returns_store_with_backend_name(self):
        result = get_persistence_store(mode=MEMORY_MODE)
        assert result.backend_name == MEMORY_MODE

    def test_returns_supabase_store_when_env_present_and_factory_succeeds(self):
        mock_store = _make_mock_supabase_store()
        with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
            result = get_persistence_store(mode=SUPABASE_MODE)
        assert isinstance(result, MagicMock)
        assert result.backend == SUPABASE_MODE

    def test_falls_back_to_memory_on_supabase_failure_with_allow_fallback(self):
        with patch(
            _FACTORY_PATCH_TARGET,
            side_effect=RuntimeError("supabase down"),
        ):
            result = get_persistence_store(mode=SUPABASE_MODE, allow_fallback=True)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_no_fallback_raises_on_supabase_failure(self):
        with patch(
            _FACTORY_PATCH_TARGET,
            side_effect=RuntimeError("supabase down"),
        ):
            with pytest.raises(RuntimeError):
                get_persistence_store(mode=SUPABASE_MODE, allow_fallback=False)

    def test_auto_mode_without_env_returns_memory_store(self):
        with patch(_ENV_PATCH_TARGET, return_value=False):
            result = get_persistence_store(mode="auto")
        assert isinstance(result, InMemoryPersistenceStore)
        assert result.fallback_reason == "supabase-env-missing"

    def test_auto_mode_with_env_returns_supabase_store(self):
        mock_store = _make_mock_supabase_store()
        with patch(_ENV_PATCH_TARGET, return_value=True):
            with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
                result = get_persistence_store(mode="auto")
        assert result.backend == SUPABASE_MODE

    def test_invalid_mode_raises_value_error(self):
        with pytest.raises(ValueError):
            get_persistence_store(mode="invalid_mode_xyz")

    def test_store_satisfies_persistence_store_protocol(self):
        result = get_persistence_store(mode=MEMORY_MODE)
        assert isinstance(result, PersistenceStore)


# ===========================================================================
# InMemoryPersistenceStore._tables pre-seeded
# ===========================================================================


class TestInMemoryPersistenceStoreTables:

    def test_tables_attribute_exists(self):
        store = _memory_store()
        assert hasattr(store, "_tables")

    def test_tables_is_dict(self):
        store = _memory_store()
        assert isinstance(store._tables, dict)

    def test_tables_contains_exactly_19_keys(self):
        store = _memory_store()
        assert len(store._tables) == _EXPECTED_TABLE_COUNT

    def test_tables_keys_equal_ironclaw_tables(self):
        store = _memory_store()
        assert frozenset(store._tables.keys()) == IRONCLAW_TABLES

    def test_tables_all_values_are_empty_lists_on_init(self):
        store = _memory_store()
        for key, val in store._tables.items():
            assert val == [], f"Expected empty list for table {key!r}, got {val!r}"

    def test_rate_limit_state_key_present(self):
        store = _memory_store()
        assert "rate_limit_state" in store._tables

    def test_scan_history_key_present(self):
        store = _memory_store()
        assert "scan_history" in store._tables

    def test_audit_events_key_present(self):
        store = _memory_store()
        assert "audit_events" in store._tables

    def test_webhook_deliveries_key_present(self):
        store = _memory_store()
        assert "webhook_deliveries" in store._tables

    def test_tool_call_log_key_present(self):
        store = _memory_store()
        assert "tool_call_log" in store._tables

    def test_sandbox_execution_log_key_present(self):
        store = _memory_store()
        assert "sandbox_execution_log" in store._tables

    def test_quarantine_items_key_present(self):
        store = _memory_store()
        assert "quarantine_items" in store._tables

    def test_review_queue_key_present(self):
        store = _memory_store()
        assert "review_queue" in store._tables

    def test_iocs_key_present(self):
        store = _memory_store()
        assert "iocs" in store._tables

    def test_threat_detections_key_present(self):
        store = _memory_store()
        assert "threat_detections" in store._tables

    def test_trust_events_key_present(self):
        store = _memory_store()
        assert "trust_events" in store._tables

    def test_agent_trust_profiles_key_present(self):
        store = _memory_store()
        assert "agent_trust_profiles" in store._tables

    def test_all_19_canonical_keys_individually(self):
        store = _memory_store()
        for table in _ALL_EXPECTED_TABLES:
            assert table in store._tables, f"Missing table key: {table!r}"

    def test_separate_instances_do_not_share_table_state(self):
        a = _memory_store()
        b = _memory_store()
        a._tables["scan_history"].append({"scan_id": "x"})
        assert b._tables["scan_history"] == []


# ===========================================================================
# get_rate_limit_store / build_rate_limit_store / create_rate_limit_store
# ===========================================================================


class TestRateLimitStoreFactories:

    def test_get_rate_limit_store_returns_store_type(self):
        result = get_rate_limit_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_get_rate_limit_store_memory_returns_in_memory(self):
        result = get_rate_limit_store(mode=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_get_rate_limit_store_ready_true(self):
        result = get_rate_limit_store(mode=MEMORY_MODE)
        assert result.ready is True

    def test_get_rate_limit_store_contains_rate_limit_state_table(self):
        result = get_rate_limit_store(mode=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)
        assert "rate_limit_state" in result._tables

    def test_build_rate_limit_store_returns_store_type(self):
        result = build_rate_limit_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_build_rate_limit_store_memory_returns_in_memory(self):
        result = build_rate_limit_store(mode=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_build_rate_limit_store_ready_true(self):
        result = build_rate_limit_store(mode=MEMORY_MODE)
        assert result.ready is True

    def test_create_rate_limit_store_returns_store_type(self):
        result = create_rate_limit_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_create_rate_limit_store_memory_returns_in_memory(self):
        result = create_rate_limit_store(mode=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_create_rate_limit_store_ready_true(self):
        result = create_rate_limit_store(mode=MEMORY_MODE)
        assert result.ready is True

    def test_all_three_return_equivalent_stores_in_memory_mode(self):
        a = get_rate_limit_store(mode=MEMORY_MODE)
        b = build_rate_limit_store(mode=MEMORY_MODE)
        c = create_rate_limit_store(mode=MEMORY_MODE)
        assert type(a) is type(b) is type(c)
        assert a.backend_name == b.backend_name == c.backend_name

    def test_get_rate_limit_store_supabase_mode_returns_supabase_store(self):
        mock_store = _make_mock_supabase_store()
        with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
            result = get_rate_limit_store(mode=SUPABASE_MODE)
        assert result.backend == SUPABASE_MODE

    def test_build_rate_limit_store_supabase_mode_returns_supabase_store(self):
        mock_store = _make_mock_supabase_store()
        with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
            result = build_rate_limit_store(mode=SUPABASE_MODE)
        assert result.backend == SUPABASE_MODE

    def test_create_rate_limit_store_supabase_mode_returns_supabase_store(self):
        mock_store = _make_mock_supabase_store()
        with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
            result = create_rate_limit_store(mode=SUPABASE_MODE)
        assert result.backend == SUPABASE_MODE


# ===========================================================================
# Factory aliases — all resolve and return StoreType
# ===========================================================================


class TestFactoryAliases:

    def test_get_store_returns_store_type(self):
        result = get_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_create_store_returns_store_type(self):
        result = create_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_get_organization_store_returns_store_type(self):
        result = get_organization_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_get_telemetry_store_returns_store_type(self):
        result = get_telemetry_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_get_runtime_state_store_returns_store_type(self):
        result = get_runtime_state_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_get_review_state_store_returns_store_type(self):
        result = get_review_state_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_get_checkpoint_store_returns_store_type(self):
        result = get_checkpoint_store(mode=MEMORY_MODE)
        assert isinstance(result, (SupabasePersistenceStore, InMemoryPersistenceStore))

    def test_get_store_ready_true(self):
        assert get_store(mode=MEMORY_MODE).ready is True

    def test_create_store_ready_true(self):
        assert create_store(mode=MEMORY_MODE).ready is True

    def test_get_organization_store_ready_true(self):
        assert get_organization_store(mode=MEMORY_MODE).ready is True

    def test_get_telemetry_store_ready_true(self):
        assert get_telemetry_store(mode=MEMORY_MODE).ready is True

    def test_get_runtime_state_store_ready_true(self):
        assert get_runtime_state_store(mode=MEMORY_MODE).ready is True

    def test_get_review_state_store_ready_true(self):
        assert get_review_state_store(mode=MEMORY_MODE).ready is True

    def test_get_checkpoint_store_ready_true(self):
        assert get_checkpoint_store(mode=MEMORY_MODE).ready is True

    def test_all_aliases_return_same_type_in_memory_mode(self):
        aliases = [
            get_store,
            create_store,
            get_organization_store,
            get_telemetry_store,
            get_runtime_state_store,
            get_review_state_store,
            get_checkpoint_store,
            get_rate_limit_store,
            build_rate_limit_store,
            create_rate_limit_store,
            get_persistence_store,
        ]
        for fn in aliases:
            result = fn(mode=MEMORY_MODE)
            assert isinstance(result, InMemoryPersistenceStore), f"{fn.__name__} did not return InMemoryPersistenceStore"

    def test_all_aliases_return_supabase_store_type_in_supabase_mode(self):
        mock_store = _make_mock_supabase_store()
        aliases = [
            get_store,
            create_store,
            get_organization_store,
            get_telemetry_store,
            get_runtime_state_store,
            get_review_state_store,
            get_checkpoint_store,
            get_rate_limit_store,
            build_rate_limit_store,
            create_rate_limit_store,
            get_persistence_store,
        ]
        for fn in aliases:
            with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
                result = fn(mode=SUPABASE_MODE)
            assert result.backend == SUPABASE_MODE, f"{fn.__name__} did not return supabase backend"


# ===========================================================================
# PersistenceBootstrapState
# ===========================================================================


class TestPersistenceBootstrapState:

    def test_memory_mode_migration_ready_true(self):
        state = PersistenceBootstrapState(
            mode=MEMORY_MODE,
            backend_name=MEMORY_MODE,
            fallback_enabled=True,
        )
        assert state.migration_ready is True

    def test_supabase_mode_migration_ready_true(self):
        state = PersistenceBootstrapState(
            mode=SUPABASE_MODE,
            backend_name=SUPABASE_MODE,
            fallback_enabled=False,
        )
        assert state.migration_ready is True

    def test_unknown_backend_migration_ready_false(self):
        state = PersistenceBootstrapState(
            mode="unknown",
            backend_name="unknown",
            fallback_enabled=False,
        )
        assert state.migration_ready is False

    def test_ready_property_mirrors_migration_ready(self):
        state = PersistenceBootstrapState(
            mode=MEMORY_MODE,
            backend_name=MEMORY_MODE,
            fallback_enabled=True,
        )
        assert state.ready == state.migration_ready

    def test_fallback_reason_none_by_default(self):
        state = PersistenceBootstrapState(
            mode=MEMORY_MODE,
            backend_name=MEMORY_MODE,
            fallback_enabled=True,
        )
        assert state.fallback_reason is None

    def test_fallback_reason_stored_when_provided(self):
        state = PersistenceBootstrapState(
            mode=MEMORY_MODE,
            backend_name=MEMORY_MODE,
            fallback_enabled=True,
            fallback_reason="supabase-env-missing",
        )
        assert state.fallback_reason == "supabase-env-missing"


# ===========================================================================
# get_persistence_bootstrap_state
# ===========================================================================


class TestGetPersistenceBootstrapState:

    def test_returns_persistence_bootstrap_state_instance(self):
        result = get_persistence_bootstrap_state(mode=MEMORY_MODE)
        assert isinstance(result, PersistenceBootstrapState)

    def test_memory_mode_backend_name_is_memory(self):
        result = get_persistence_bootstrap_state(mode=MEMORY_MODE)
        assert result.backend_name == MEMORY_MODE

    def test_memory_mode_ready_true(self):
        result = get_persistence_bootstrap_state(mode=MEMORY_MODE)
        assert result.ready is True

    def test_supabase_mode_backend_name_is_supabase(self):
        mock_store = _make_mock_supabase_store()
        with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
            result = get_persistence_bootstrap_state(mode=SUPABASE_MODE)
        assert result.backend_name == SUPABASE_MODE

    def test_auto_without_env_has_supabase_env_missing_reason(self):
        with patch(_ENV_PATCH_TARGET, return_value=False):
            result = get_persistence_bootstrap_state(mode="auto")
        assert result.fallback_reason == "supabase-env-missing"


# ===========================================================================
# build_store — mode routing
# ===========================================================================


class TestBuildStore:

    def test_memory_mode_explicit_returns_in_memory_store(self):
        result = build_store(mode=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_memory_mode_fallback_reason_is_explicit_memory_mode(self):
        result = build_store(mode=MEMORY_MODE)
        assert result.fallback_reason == "explicit-memory-mode"

    def test_supabase_mode_returns_supabase_store_when_factory_ok(self):
        mock_store = _make_mock_supabase_store()
        with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
            result = build_store(mode=SUPABASE_MODE)
        assert result.backend == SUPABASE_MODE

    def test_supabase_mode_falls_back_when_factory_raises(self):
        with patch(_FACTORY_PATCH_TARGET, side_effect=RuntimeError("fail")):
            result = build_store(mode=SUPABASE_MODE, allow_fallback=True)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_supabase_mode_raises_when_allow_fallback_false(self):
        with patch(_FACTORY_PATCH_TARGET, side_effect=RuntimeError("fail")):
            with pytest.raises(RuntimeError):
                build_store(mode=SUPABASE_MODE, allow_fallback=False)

    def test_auto_mode_no_env_returns_memory_store(self):
        with patch(_ENV_PATCH_TARGET, return_value=False):
            result = build_store(mode="auto")
        assert isinstance(result, InMemoryPersistenceStore)

    def test_auto_mode_env_present_returns_supabase_store(self):
        mock_store = _make_mock_supabase_store()
        with patch(_ENV_PATCH_TARGET, return_value=True):
            with patch(_FACTORY_PATCH_TARGET, return_value=mock_store):
                result = build_store(mode="auto")
        assert result.backend == SUPABASE_MODE

    def test_backend_kwarg_accepted_as_mode_alias(self):
        result = build_store(backend=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_provider_kwarg_accepted_as_mode_alias(self):
        result = build_store(provider=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_persistence_kwarg_accepted_as_mode_alias(self):
        result = build_store(persistence=MEMORY_MODE)
        assert isinstance(result, InMemoryPersistenceStore)

    def test_invalid_mode_raises_value_error(self):
        with pytest.raises(ValueError):
            build_store(mode="bogus_mode")


# ===========================================================================
# PersistenceStore protocol conformance
# ===========================================================================


class TestPersistenceStoreProtocol:

    def test_in_memory_store_satisfies_protocol(self):
        store = InMemoryPersistenceStore()
        assert isinstance(store, PersistenceStore)

    def test_in_memory_store_has_healthcheck(self):
        store = InMemoryPersistenceStore()
        assert callable(store.healthcheck)

    def test_in_memory_store_healthcheck_returns_true(self):
        store = InMemoryPersistenceStore()
        assert store.healthcheck() is True

    def test_in_memory_store_has_select(self):
        store = InMemoryPersistenceStore()
        assert callable(store.select)

    def test_in_memory_store_has_insert(self):
        store = InMemoryPersistenceStore()
        assert callable(store.insert)

    def test_in_memory_store_has_update(self):
        store = InMemoryPersistenceStore()
        assert callable(store.update)

    def test_in_memory_store_has_delete(self):
        store = InMemoryPersistenceStore()
        assert callable(store.delete)

    def test_in_memory_store_as_dict_returns_dict(self):
        store = InMemoryPersistenceStore()
        result = store.as_dict()
        assert isinstance(result, dict)

    def test_in_memory_store_as_dict_contains_backend_key(self):
        store = InMemoryPersistenceStore()
        assert "backend" in store.as_dict()

    def test_in_memory_store_as_dict_contains_ready_key(self):
        store = InMemoryPersistenceStore()
        assert "ready" in store.as_dict()

    def test_store_type_union_accepts_in_memory(self):
        store: StoreType = InMemoryPersistenceStore()
        assert store.ready is True
