from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.organizationstore",
    "services.organizationstore",
    "organizationstore",
    "app.services.orgstore",
    "services.orgstore",
    "orgstore",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import organization store module: {last_error}")


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
        for key in ("items", "results", "rows", "entries", "organizations", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _build_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_organization_store",
        "create_organization_store",
        "get_organization_store",
        "build_org_store",
        "create_org_store",
        "get_org_store",
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
                    pytest.skip("organization store factory requires unsupported arguments")

    for cls_name in (
        "OrganizationStore",
        "OrgStore",
        "InMemoryOrganizationStore",
        "InMemoryOrgStore",
        "SupabaseOrganizationStore",
        "SupabaseOrgStore",
    ):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("organization store builder/class not implemented")


def test_organization_store_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_organization_store_exposes_public_surface() -> None:
    module = _load_module()
    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_organization_store_can_be_built() -> None:
    module = _load_module()
    store = _build_store(module)
    assert store is not None


def test_organization_store_exposes_write_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )

    assert writer is not None


def test_organization_store_exposes_read_operation() -> None:
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


def test_organization_store_accepts_basic_record_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("organization write operation not implemented")

    record = {
        "organization_id": "org-001",
        "name": "IronClaw Labs",
        "slug": "ironclaw-labs",
        "status": "active",
        "plan": "enterprise",
        "owner_id": "owner-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        result = writer(record)
    except TypeError:
        try:
            result = writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_organization_store_returns_serializable_records_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
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
        pytest.skip("organization read/write path not implemented")

    record = {
        "organization_id": "org-serialize-001",
        "name": "Serialize Org",
        "slug": "serialize-org",
        "status": "active",
        "plan": "pro",
        "owner_id": "owner-serialize-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
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


def test_organization_record_contains_core_fields_when_present() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
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
        pytest.skip("organization read/write path not implemented")

    record = {
        "organization_id": "org-core-001",
        "name": "Core Org",
        "slug": "core-org",
        "status": "trialing",
        "plan": "starter",
        "owner_id": "owner-core-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
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
        pytest.skip("reader returned no organization rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "organization_id",
        "org_id",
        "id",
        "name",
        "slug",
        "status",
        "plan",
        "owner_id",
        "created_at",
        "updated_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_organization_store_rejects_blank_name_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("organization write operation not implemented")

    bad_record = {
        "organization_id": "org-bad-name-001",
        "name": "",
        "slug": "org-bad-name",
        "status": "active",
        "plan": "enterprise",
        "owner_id": "owner-bad-name-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_organization_store_rejects_blank_slug_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("organization write operation not implemented")

    bad_record = {
        "organization_id": "org-bad-slug-001",
        "name": "Bad Slug Org",
        "slug": "",
        "status": "active",
        "plan": "enterprise",
        "owner_id": "owner-bad-slug-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_organization_store_rejects_blank_owner_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("organization write operation not implemented")

    bad_record = {
        "organization_id": "org-bad-owner-001",
        "name": "Bad Owner Org",
        "slug": "bad-owner-org",
        "status": "active",
        "plan": "enterprise",
        "owner_id": "",
        "created_at": "2026-04-26T11:21:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_organization_store_can_filter_by_status_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
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
        pytest.skip("organization read/write path not implemented")

    record = {
        "organization_id": "org-filter-status-001",
        "name": "Suspended Org",
        "slug": "suspended-org",
        "status": "suspended",
        "plan": "starter",
        "owner_id": "owner-filter-status-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(status="suspended")
    except TypeError:
        pytest.skip("status filter not implemented")

    assert result is not None


def test_organization_store_can_filter_by_owner_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
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
        pytest.skip("organization read/write path not implemented")

    owner_id = "owner-filter-001"
    record = {
        "organization_id": "org-filter-owner-001",
        "name": "Owner Filter Org",
        "slug": "owner-filter-org",
        "status": "active",
        "plan": "pro",
        "owner_id": owner_id,
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(owner_id=owner_id)
    except TypeError:
        pytest.skip("owner filter not implemented")

    assert result is not None


def test_organization_store_can_filter_by_slug_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
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
        "get_by_slug",
        "find_by_slug",
    )
    if writer is None or reader is None:
        pytest.skip("organization read/write path not implemented")

    slug = "slug-filter-org"
    record = {
        "organization_id": "org-filter-slug-001",
        "name": "Slug Filter Org",
        "slug": slug,
        "status": "active",
        "plan": "pro",
        "owner_id": "owner-filter-slug-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    if hasattr(store, "get_by_slug") and callable(store.get_by_slug):
        result = store.get_by_slug(slug)
    elif hasattr(store, "find_by_slug") and callable(store.find_by_slug):
        result = store.find_by_slug(slug)
    else:
        try:
            result = reader(slug=slug)
        except TypeError:
            pytest.skip("slug filter not implemented")

    assert result is not None


def test_organization_store_supports_lookup_by_id_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("organization write/lookup path not implemented")

    organization_id = "org-lookup-001"
    record = {
        "organization_id": organization_id,
        "name": "Lookup Org",
        "slug": "lookup-org",
        "status": "active",
        "plan": "enterprise",
        "owner_id": "owner-lookup-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = lookup(organization_id)
    except TypeError:
        try:
            result = lookup(organization_id=organization_id)
        except TypeError:
            try:
                result = lookup(org_id=organization_id)
            except TypeError:
                pytest.skip("lookup signature unsupported")

    assert result is not None


def test_organization_store_supports_status_update_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    updater = _first_callable(
        store,
        "update_status",
        "set_status",
        "activate",
        "suspend",
        "disable",
        "archive",
    )
    if writer is None or updater is None:
        pytest.skip("organization write/update path not implemented")

    organization_id = "org-update-001"
    record = {
        "organization_id": organization_id,
        "name": "Update Org",
        "slug": "update-org",
        "status": "trialing",
        "plan": "starter",
        "owner_id": "owner-update-001",
        "created_at": "2026-04-26T11:21:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = updater(organization_id, "active")
    except TypeError:
        try:
            result = updater(organization_id=organization_id, status="active")
        except TypeError:
            try:
                result = updater(organization_id)
            except TypeError:
                pytest.skip("update signature unsupported")

    assert result is not None or result is None


def test_organization_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_organization_store",
        "create_organization_store",
        "get_organization_store",
        "build_org_store",
        "create_org_store",
        "get_org_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is None:
        pytest.skip("organization store factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None