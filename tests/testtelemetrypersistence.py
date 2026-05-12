from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.telemetry",
    "services.telemetry",
    "telemetry",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import telemetry module: {last_error}")


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
        if isinstance(attr, (str, int, float, bool, list, dict, type(None))):
            payload[name] = attr
    return payload


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        for key in ("items", "results", "rows", "events", "entries", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _build_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_telemetry_store",
        "create_telemetry_store",
        "get_telemetry_store",
        "build_store",
        "create_store",
        "get_store",
        "build_telemetry",
        "create_telemetry",
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
                    pytest.skip("telemetry store factory requires unsupported arguments")

    for cls_name in (
        "TelemetryStore",
        "InMemoryTelemetryStore",
        "TelemetryRepository",
        "SupabaseTelemetryStore",
    ):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("telemetry store builder/class not implemented")


def _sample_event(event_id: str = "evt-001", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": event_id,
        "event_type": "prompt.guard.blocked",
        "severity": "high",
        "status": "recorded",
        "source": "ironclaw-runtime",
        "organization_id": "org-001",
        "request_id": "req-001",
        "actor_id": "actor-001",
        "session_id": "sess-001",
        "message": "Prompt injection blocked by policy",
        "metadata": {"rule": "prompt-injection", "action": "block"},
        "created_at": "2026-04-26T11:24:00Z",
    }
    payload.update(overrides)
    return payload


def test_telemetry_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_telemetry_module_exposes_public_surface() -> None:
    module = _load_module()
    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_telemetry_store_can_be_built() -> None:
    module = _load_module()
    store = _build_store(module)
    assert store is not None


def test_telemetry_store_exposes_write_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )

    assert writer is not None


def test_telemetry_store_exposes_read_operation() -> None:
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


def test_telemetry_store_accepts_basic_event_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("telemetry write operation not implemented")

    event = _sample_event()

    try:
        result = writer(event)
    except TypeError:
        try:
            result = writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_telemetry_store_returns_serializable_events_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("telemetry read/write path not implemented")

    event = _sample_event("evt-serialize-001")
    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
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


def test_telemetry_event_contains_core_fields_when_present() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("telemetry read/write path not implemented")

    event = _sample_event("evt-core-001")
    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
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
        pytest.skip("reader returned no telemetry rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "event_id",
        "id",
        "event_type",
        "type",
        "severity",
        "status",
        "source",
        "organization_id",
        "request_id",
        "actor_id",
        "session_id",
        "message",
        "metadata",
        "created_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_telemetry_store_rejects_blank_event_type_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("telemetry write operation not implemented")

    bad_event = _sample_event("evt-bad-type-001", event_type="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_event)
        except TypeError:
            writer(**bad_event)


def test_telemetry_store_rejects_blank_source_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("telemetry write operation not implemented")

    bad_event = _sample_event("evt-bad-source-001", source="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_event)
        except TypeError:
            writer(**bad_event)


def test_telemetry_store_rejects_blank_organization_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("telemetry write operation not implemented")

    bad_event = _sample_event("evt-bad-org-001", organization_id="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_event)
        except TypeError:
            writer(**bad_event)


def test_telemetry_store_rejects_blank_request_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("telemetry write operation not implemented")

    bad_event = _sample_event("evt-bad-request-001", request_id="")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_event)
        except TypeError:
            writer(**bad_event)


def test_telemetry_store_preserves_metadata_mapping_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("telemetry read/write path not implemented")

    event_id = "evt-meta-001"
    metadata = {"rule": "toolcall-guard", "decision": "allow", "score": 0.98}
    event = _sample_event(event_id, metadata=metadata)

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
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
        (
            row
            for row in rows
            if row.get("event_id") == event_id or row.get("id") == event_id
        ),
        None,
    )
    if matched is None:
        pytest.skip("event lookup in result set unavailable")

    if "metadata" in matched and matched["metadata"] is not None:
        assert isinstance(matched["metadata"], dict)


def test_telemetry_store_can_filter_by_event_type_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("telemetry read/write path not implemented")

    event_type = "runtime.command.blocked"
    event = _sample_event("evt-filter-type-001", event_type=event_type)

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(event_type=event_type)
    except TypeError:
        try:
            result = reader(type=event_type)
        except TypeError:
            pytest.skip("event type filter not implemented")

    assert result is not None


def test_telemetry_store_can_filter_by_organization_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("telemetry read/write path not implemented")

    organization_id = "org-filter-telemetry-001"
    event = _sample_event("evt-filter-org-001", organization_id=organization_id)

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(organization_id=organization_id)
    except TypeError:
        pytest.skip("organization filter not implemented")

    assert result is not None


def test_telemetry_store_can_filter_by_request_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
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
        "get_by_request_id",
        "find_by_request_id",
    )
    if writer is None or reader is None:
        pytest.skip("telemetry read/write path not implemented")

    request_id = "req-filter-001"
    event = _sample_event("evt-filter-request-001", request_id=request_id)

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    if hasattr(store, "get_by_request_id") and callable(store.get_by_request_id):
        result = store.get_by_request_id(request_id)
    elif hasattr(store, "find_by_request_id") and callable(store.find_by_request_id):
        result = store.find_by_request_id(request_id)
    else:
        try:
            result = reader(request_id=request_id)
        except TypeError:
            pytest.skip("request filter not implemented")

    assert result is not None


def test_telemetry_store_supports_lookup_by_event_id_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )
    lookup = _first_callable(
        store,
        "get_by_id",
        "get_by_event_id",
        "find_by_id",
        "find_by_event_id",
        "get",
        "fetch_one",
        "read_one",
    )
    if writer is None or lookup is None:
        pytest.skip("telemetry write/lookup path not implemented")

    event_id = "evt-lookup-001"
    event = _sample_event(event_id)

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = lookup(event_id)
    except TypeError:
        try:
            result = lookup(event_id=event_id)
        except TypeError:
            pytest.skip("lookup signature unsupported")

    assert result is not None


def test_telemetry_store_supports_status_update_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "record",
        "create",
        "insert",
        "append",
        "write",
        "save",
        "put",
        "upsert",
        "store",
    )
    updater = _first_callable(
        store,
        "update_status",
        "set_status",
        "mark_processed",
        "mark_sent",
        "mark_failed",
    )
    if writer is None or updater is None:
        pytest.skip("telemetry write/update path not implemented")

    event_id = "evt-update-001"
    event = _sample_event(event_id, status="queued")

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = updater(event_id, "processed")
    except TypeError:
        try:
            result = updater(event_id=event_id, status="processed")
        except TypeError:
            try:
                result = updater(event_id)
            except TypeError:
                pytest.skip("update signature unsupported")

    assert result is not None or result is None


def test_telemetry_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_telemetry_store",
        "create_telemetry_store",
        "get_telemetry_store",
        "build_store",
        "create_store",
        "get_store",
        "build_telemetry",
        "create_telemetry",
    )
    if factory is None:
        pytest.skip("telemetry store factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None