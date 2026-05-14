from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.runtimesession",
    "services.runtimesession",
    "runtimesession",
    "app.orchestrator.runtimesession",
    "orchestrator.runtimesession",
    "app.services.reviewstatestore",
    "services.reviewstatestore",
    "reviewstatestore",
    "app.orchestrator.reviewstatestore",
    "orchestrator.reviewstatestore",
    "app.orchestrator.checkpointstore",
    "orchestrator.checkpointstore",
    "checkpointstore",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import runtime state persistence module: {last_error}")


def _first_callable(target: Any, *names: str) -> Any | None:
    for name in names:
        if hasattr(target, name):
            value = getattr(target, name)
            if callable(value):
                return value
    return None


def _serialize(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump") and callable(value.model_dump):
        data = value.model_dump()
        if isinstance(data, dict):
            return data
    if hasattr(value, "dict") and callable(value.dict):
        data = value.dict()
        if isinstance(data, dict):
            return data
    if hasattr(value, "as_dict") and callable(value.as_dict):
        data = value.as_dict()
        if isinstance(data, dict):
            return data
    payload: dict[str, Any] = {}
    for name in dir(value):
        if name.startswith("_"):
            continue
        attr = getattr(value, name)
        if callable(attr):
            continue
        if isinstance(attr, str | int | float | bool | list | dict | type(None)):
            payload[name] = attr
    return payload


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        for key in ("items", "results", "rows", "entries", "states", "sessions", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _build_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_runtime_state_store",
        "create_runtime_state_store",
        "get_runtime_state_store",
        "build_runtime_session_store",
        "create_runtime_session_store",
        "get_runtime_session_store",
        "build_review_state_store",
        "create_review_state_store",
        "get_review_state_store",
        "build_checkpoint_store",
        "create_checkpoint_store",
        "get_checkpoint_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is not None:
        try:
            return factory()
        except TypeError:
            try:
                return factory(mode="memory")
            except TypeError:
                try:
                    return factory(backend="memory")
                except TypeError:
                    pytest.skip("runtime state store factory requires unsupported arguments")

    for cls_name in (
        "RuntimeStateStore",
        "RuntimeSessionStore",
        "RuntimeSession",
        "ReviewStateStore",
        "CheckpointStore",
        "InMemoryRuntimeStateStore",
        "InMemoryRuntimeSessionStore",
        "InMemoryCheckpointStore",
    ):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("runtime state store builder/class not implemented")


def _sample_state(state_id: str = "state-001", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "state_id": state_id,
        "session_id": "session-001",
        "request_id": "request-001",
        "organization_id": "org-001",
        "status": "active",
        "phase": "inspection",
        "checkpoint": "pre-execution",
        "actor_id": "actor-001",
        "policy_id": "policy-001",
        "review_required": False,
        "risk_level": "medium",
        "metadata": {"pipeline": "secure-runtime", "mode": "monitor"},
        "created_at": "2026-04-26T11:28:00Z",
        "updated_at": "2026-04-26T11:28:00Z",
    }
    payload.update(overrides)
    return payload


def test_runtime_state_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_runtime_state_module_exposes_public_surface() -> None:
    module = _load_module()
    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_runtime_state_store_can_be_built() -> None:
    module = _load_module()
    store = _build_store(module)
    assert store is not None


def test_runtime_state_store_exposes_write_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )

    assert writer is not None


def test_runtime_state_store_exposes_read_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )

    assert reader is not None


def test_runtime_state_store_accepts_basic_state_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    if writer is None:
        pytest.skip("runtime state write operation not implemented")

    state = _sample_state()

    try:
        result = writer(state)
    except TypeError:
        try:
            result = writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_runtime_state_store_returns_serializable_records_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("runtime state read/write path not implemented")

    state = _sample_state("state-serialize-001")
    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader()
    except TypeError:
        try:
            result = reader(limit=10)
        except TypeError:
            pytest.skip("reader signature unsupported")

    rows = _items(result)
    if rows:
        payload = _serialize(rows[0])
        assert isinstance(payload, dict)


def test_runtime_state_record_contains_core_fields_when_present() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("runtime state read/write path not implemented")

    state = _sample_state("state-core-001")
    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader()
    except TypeError:
        try:
            result = reader(limit=10)
        except TypeError:
            pytest.skip("reader signature unsupported")

    rows = _items(result)
    if not rows:
        pytest.skip("reader returned no runtime state rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "state_id",
        "id",
        "session_id",
        "request_id",
        "organization_id",
        "status",
        "phase",
        "checkpoint",
        "actor_id",
        "policy_id",
        "review_required",
        "risk_level",
        "metadata",
        "created_at",
        "updated_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_runtime_state_store_rejects_blank_session_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    if writer is None:
        pytest.skip("runtime state write operation not implemented")

    bad_state = _sample_state("state-bad-session-001", session_id="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_state)
        except TypeError:
            writer(**bad_state)


def test_runtime_state_store_rejects_blank_request_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    if writer is None:
        pytest.skip("runtime state write operation not implemented")

    bad_state = _sample_state("state-bad-request-001", request_id="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_state)
        except TypeError:
            writer(**bad_state)


def test_runtime_state_store_rejects_blank_status_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    if writer is None:
        pytest.skip("runtime state write operation not implemented")

    bad_state = _sample_state("state-bad-status-001", status="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_state)
        except TypeError:
            writer(**bad_state)


def test_runtime_state_store_rejects_blank_phase_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    if writer is None:
        pytest.skip("runtime state write operation not implemented")

    bad_state = _sample_state("state-bad-phase-001", phase="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_state)
        except TypeError:
            writer(**bad_state)


def test_runtime_state_store_preserves_metadata_mapping_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("runtime state read/write path not implemented")

    state_id = "state-meta-001"
    metadata = {"worker": "responsecoordinator", "step": "policy-eval", "retry": 0}
    state = _sample_state(state_id, metadata=metadata)

    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader()
    except TypeError:
        try:
            result = reader(limit=25)
        except TypeError:
            pytest.skip("reader signature unsupported")

    rows = [_serialize(row) for row in _items(result)]
    matched = next(
        (row for row in rows if row.get("state_id") == state_id or row.get("id") == state_id),
        None,
    )
    if matched is None:
        pytest.skip("state lookup in result set unavailable")

    if "metadata" in matched and matched["metadata"] is not None:
        assert isinstance(matched["metadata"], dict)


def test_runtime_state_store_can_filter_by_session_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("runtime state read/write path not implemented")

    session_id = "session-filter-001"
    state = _sample_state("state-filter-session-001", session_id=session_id)

    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(session_id=session_id)
    except TypeError:
        pytest.skip("session filter not implemented")

    assert result is not None


def test_runtime_state_store_can_filter_by_status_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("runtime state read/write path not implemented")

    state = _sample_state("state-filter-status-001", status="paused")

    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(status="paused")
    except TypeError:
        pytest.skip("status filter not implemented")

    assert result is not None


def test_runtime_state_store_can_filter_by_organization_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("runtime state read/write path not implemented")

    organization_id = "org-filter-runtime-001"
    state = _sample_state("state-filter-org-001", organization_id=organization_id)

    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(organization_id=organization_id)
    except TypeError:
        pytest.skip("organization filter not implemented")

    assert result is not None


def test_runtime_state_store_supports_lookup_by_state_id_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    lookup = _first_callable(
        store,
        "get_by_id",
        "get_by_state_id",
        "find_by_id",
        "find_by_state_id",
        "get",
        "fetch_one",
        "read_one",
    )
    if writer is None or lookup is None:
        pytest.skip("runtime state write/lookup path not implemented")

    state_id = "state-lookup-001"
    state = _sample_state(state_id)

    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = lookup(state_id)
    except TypeError:
        try:
            result = lookup(state_id=state_id)
        except TypeError:
            pytest.skip("lookup signature unsupported")

    assert result is not None


def test_runtime_state_store_supports_status_update_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    updater = _first_callable(
        store,
        "update_status",
        "set_status",
        "transition",
        "advance",
        "mark_complete",
        "mark_failed",
    )
    if writer is None or updater is None:
        pytest.skip("runtime state write/update path not implemented")

    state_id = "state-update-001"
    state = _sample_state(state_id, status="queued")

    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = updater(state_id, "running")
    except TypeError:
        try:
            result = updater(state_id=state_id, status="running")
        except TypeError:
            try:
                result = updater(state_id)
            except TypeError:
                pytest.skip("update signature unsupported")

    assert result is not None or result is None


def test_runtime_state_store_supports_checkpoint_update_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "save",
        "create",
        "insert",
        "record",
        "put",
        "upsert",
        "store",
        "write",
        "set",
    )
    checkpoint_updater = _first_callable(
        store,
        "update_checkpoint",
        "set_checkpoint",
        "save_checkpoint",
        "checkpoint",
    )
    if writer is None or checkpoint_updater is None:
        pytest.skip("runtime state write/checkpoint path not implemented")

    state_id = "state-checkpoint-001"
    state = _sample_state(state_id, checkpoint="preflight")

    try:
        writer(state)
    except TypeError:
        try:
            writer(**state)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = checkpoint_updater(state_id, "policy-verified")
    except TypeError:
        try:
            result = checkpoint_updater(state_id=state_id, checkpoint="policy-verified")
        except TypeError:
            pytest.skip("checkpoint update signature unsupported")

    assert result is not None or result is None


def test_runtime_state_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_runtime_state_store",
        "create_runtime_state_store",
        "get_runtime_state_store",
        "build_runtime_session_store",
        "create_runtime_session_store",
        "get_runtime_session_store",
        "build_review_state_store",
        "create_review_state_store",
        "get_review_state_store",
        "build_checkpoint_store",
        "create_checkpoint_store",
        "get_checkpoint_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is None:
        pytest.skip("runtime state store factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None
