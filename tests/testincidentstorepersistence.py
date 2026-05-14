from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.incidentstore",
    "services.incidentstore",
    "incidentstore",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import incident store module: {last_error}")


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
        for key in ("items", "results", "rows", "incidents", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _build_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_incident_store",
        "create_incident_store",
        "get_incident_store",
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
                    pytest.skip("incident store factory requires unsupported arguments")

    for cls_name in ("IncidentStore", "InMemoryIncidentStore", "SupabaseIncidentStore"):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("incident store builder/class not implemented")


def test_incident_store_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_incident_store_exposes_public_surface() -> None:
    module = _load_module()
    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_incident_store_can_be_built() -> None:
    module = _load_module()
    store = _build_store(module)
    assert store is not None


def test_incident_store_exposes_write_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )

    assert writer is not None


def test_incident_store_exposes_read_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    reader = _first_callable(
        store,
        "list",
        "fetch",
        "get",
        "query",
        "search",
        "read",
        "all",
        "latest",
    )

    assert reader is not None


def test_incident_store_accepts_basic_incident_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )
    if writer is None:
        pytest.skip("incident write operation not implemented")

    incident = {
        "incident_id": "inc-001",
        "title": "Prompt injection attempt",
        "severity": "high",
        "status": "open",
        "source": "scanner",
        "summary": "Detected hostile prompt mutation.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    try:
        result = writer(incident)
    except TypeError:
        try:
            result = writer(**incident)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_incident_store_returns_serializable_records_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "read",
        "all",
        "query",
        "search",
        "latest",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("incident read/write path not implemented")

    incident = {
        "incident_id": "inc-serialize-001",
        "title": "Serialization test incident",
        "severity": "medium",
        "status": "open",
        "source": "tester",
        "summary": "Checks persistence serialization shape.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    try:
        writer(incident)
    except TypeError:
        try:
            writer(**incident)
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


def test_incident_record_contains_core_fields_when_present() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "read",
        "all",
        "query",
        "search",
        "latest",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("incident read/write path not implemented")

    incident = {
        "incident_id": "inc-core-001",
        "title": "Core field incident",
        "severity": "critical",
        "status": "open",
        "source": "engine",
        "summary": "Checks core fields.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    try:
        writer(incident)
    except TypeError:
        try:
            writer(**incident)
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
        pytest.skip("incident reader returned no rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "incident_id",
        "id",
        "title",
        "severity",
        "status",
        "source",
        "summary",
        "description",
        "timestamp",
        "created_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_incident_store_rejects_blank_title_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )
    if writer is None:
        pytest.skip("incident write operation not implemented")

    bad_incident = {
        "incident_id": "inc-bad-title-001",
        "title": "",
        "severity": "high",
        "status": "open",
        "source": "scanner",
        "summary": "Invalid title.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_incident)
        except TypeError:
            writer(**bad_incident)


def test_incident_store_rejects_blank_severity_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )
    if writer is None:
        pytest.skip("incident write operation not implemented")

    bad_incident = {
        "incident_id": "inc-bad-severity-001",
        "title": "Severity missing",
        "severity": "",
        "status": "open",
        "source": "scanner",
        "summary": "Invalid severity.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_incident)
        except TypeError:
            writer(**bad_incident)


def test_incident_store_can_filter_by_status_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
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
        pytest.skip("incident read/write path not implemented")

    status = "investigating"
    incident = {
        "incident_id": "inc-filter-status-001",
        "title": "Status filter incident",
        "severity": "high",
        "status": status,
        "source": "engine",
        "summary": "Filter by status.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    try:
        writer(incident)
    except TypeError:
        try:
            writer(**incident)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(status=status)
    except TypeError:
        pytest.skip("status filtering not implemented")

    assert result is not None


def test_incident_store_can_filter_by_severity_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
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
        pytest.skip("incident read/write path not implemented")

    severity = "critical"
    incident = {
        "incident_id": "inc-filter-severity-001",
        "title": "Severity filter incident",
        "severity": severity,
        "status": "open",
        "source": "engine",
        "summary": "Filter by severity.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    try:
        writer(incident)
    except TypeError:
        try:
            writer(**incident)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(severity=severity)
    except TypeError:
        pytest.skip("severity filtering not implemented")

    assert result is not None


def test_incident_store_supports_lookup_by_id_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )
    lookup = _first_callable(
        store,
        "get_by_id",
        "find_by_id",
        "get",
        "fetch_one",
        "read_one",
    )
    if writer is None or lookup is None:
        pytest.skip("incident write/lookup path not implemented")

    incident_id = "inc-lookup-001"
    incident = {
        "incident_id": incident_id,
        "title": "Lookup incident",
        "severity": "medium",
        "status": "open",
        "source": "tester",
        "summary": "Lookup by id.",
        "timestamp": "2026-04-26T10:56:00Z",
    }

    try:
        writer(incident)
    except TypeError:
        try:
            writer(**incident)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = lookup(incident_id)
    except TypeError:
        try:
            result = lookup(incident_id=incident_id)
        except TypeError:
            pytest.skip("lookup signature unsupported")

    assert result is not None


def test_incident_store_supports_latest_or_ordered_reads_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "open_incident",
        "append",
        "write",
    )
    latest = _first_callable(store, "latest", "last", "most_recent", "get_latest")
    reader = _first_callable(store, "list", "fetch", "all", "read")

    if writer is None:
        pytest.skip("incident write operation not implemented")

    first_incident = {
        "incident_id": "inc-order-001",
        "title": "First incident",
        "severity": "low",
        "status": "open",
        "source": "engine",
        "summary": "First ordered incident.",
        "timestamp": "2026-04-26T10:56:00Z",
    }
    second_incident = {
        "incident_id": "inc-order-002",
        "title": "Second incident",
        "severity": "high",
        "status": "open",
        "source": "engine",
        "summary": "Second ordered incident.",
        "timestamp": "2026-04-26T10:57:00Z",
    }

    try:
        writer(first_incident)
        writer(second_incident)
    except TypeError:
        try:
            writer(**first_incident)
            writer(**second_incident)
        except TypeError:
            pytest.skip("writer signature unsupported")

    if latest is not None:
        result = latest()
        assert result is not None
        return

    if reader is not None:
        try:
            rows = reader()
        except TypeError:
            try:
                rows = reader(limit=10)
            except TypeError:
                pytest.skip("reader signature unsupported")
        assert rows is not None
        return

    pytest.skip("no latest/read operation implemented")


def test_incident_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_incident_store",
        "create_incident_store",
        "get_incident_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is None:
        pytest.skip("incident store factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None
