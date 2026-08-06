from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.schemas.threat_detection import (
    IngestStatusEnum,
    IOCTypeEnum,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)
from app.services.ioc_store import (
    InMemoryIOCStoreBackend,
    IOCStore,
    IOCStoreConfigurationError,
    _ingest_result_to_row,
    _is_unconfigured_client_error,
    _looks_like_test_runtime,
    _merge_record_update,
    _overwrite_record_update,
    _parse_extra,
    _parse_tags,
    _record_to_row,
    _row_to_record,
    set_ioc_store_backend,
)
from app.services.threat_feed_ingestion import (
    FeedIngestResult,
    IOCFilterRequest,
    IOCRecord,
    _utcnow_iso,
)

_NOW = _utcnow_iso()
_PAST = "2020-01-01T00:00:00Z"
_FUTURE = "2099-12-31T23:59:59Z"

_PATCH_TARGET = "app.services.ioc_store._get_client"


def _make_record(
    *,
    ioc_id: str = "ioc-aaaa0000bbbb1111",
    ioc_type: str = IOCTypeEnum.IPV4,
    value: str = "1.2.3.4",
    source: str = ThreatFeedSourceEnum.CUSTOM_IOC,
    severity: str = ThreatSeverityLevel.HIGH,
    confidence: float = 0.9,
    tags: list[str] | None = None,
    description: str = "test ioc",
    org_id: str | None = "org-test",
    mitre_technique_id: str | None = None,
    mitre_tactic: str | None = None,
    cve_id: str | None = None,
    first_seen: str = _NOW,
    last_seen: str = _NOW,
    expiry: str | None = None,
    active: bool = True,
    feed_ingest_id: str = "ingest-test0001",
    extra: dict[str, Any] | None = None,
) -> IOCRecord:
    return IOCRecord(
        ioc_id=ioc_id,
        ioc_type=ioc_type,
        value=value,
        source=source,
        severity=severity,
        confidence=confidence,
        tags=tags if tags is not None else ["test"],
        description=description,
        org_id=org_id,
        mitre_technique_id=mitre_technique_id,
        mitre_tactic=mitre_tactic,
        cve_id=cve_id,
        first_seen=first_seen,
        last_seen=last_seen,
        expiry=expiry,
        active=active,
        feed_ingest_id=feed_ingest_id,
        extra=extra if extra is not None else {},
    )


def _make_ingest_result(
    *,
    ingest_id: str = "ingest-abc123",
    source: str = ThreatFeedSourceEnum.CUSTOM_IOC,
    status: str = IngestStatusEnum.SUCCESS,
    iocs_parsed: int = 10,
    iocs_inserted: int = 8,
    iocs_updated: int = 2,
    iocs_skipped: int = 0,
    errors: list[str] | None = None,
    started_at: str = _NOW,
    completed_at: str | None = _NOW,
    org_id: str | None = "org-test",
    metadata: dict[str, Any] | None = None,
) -> FeedIngestResult:
    return FeedIngestResult(
        ingest_id=ingest_id,
        source=source,
        status=status,
        iocs_parsed=iocs_parsed,
        iocs_inserted=iocs_inserted,
        iocs_updated=iocs_updated,
        iocs_skipped=iocs_skipped,
        errors=errors if errors is not None else [],
        started_at=started_at,
        completed_at=completed_at,
        org_id=org_id,
        metadata=metadata if metadata is not None else {},
    )


def _make_builder(data: Any = None, count: int = 0) -> MagicMock:
    resp = MagicMock()
    resp.data = data if data is not None else []
    resp.count = count

    b = MagicMock()
    for method in (
        "select",
        "insert",
        "update",
        "delete",
        "upsert",
        "eq",
        "neq",
        "lt",
        "lte",
        "gt",
        "gte",
        "in_",
        "or_",
        "is_",
        "ilike",
        "contains",
        "limit",
        "range",
        "order",
        "maybe_single",
    ):
        getattr(b, method).return_value = b
    b.not_ = b
    b.execute.return_value = resp
    return b


def _make_supabase_mock() -> MagicMock:
    client = MagicMock()
    client.table.return_value = _make_builder()
    return client


def _row_from_record(record: IOCRecord) -> dict[str, Any]:
    return {
        "ioc_id": record.ioc_id,
        "ioc_type": record.ioc_type,
        "value": record.value,
        "source": record.source,
        "severity": record.severity,
        "confidence": record.confidence,
        "tags": record.tags,
        "description": record.description,
        "org_id": record.org_id,
        "mitre_technique_id": record.mitre_technique_id,
        "mitre_tactic": record.mitre_tactic,
        "cve_id": record.cve_id,
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
        "expiry": record.expiry,
        "active": record.active,
        "feed_ingest_id": record.feed_ingest_id,
        "extra": record.extra,
    }


def _full_row(record: IOCRecord) -> dict[str, Any]:
    return {
        **_row_from_record(record),
        "mitre_technique_id": record.mitre_technique_id,
        "mitre_tactic": record.mitre_tactic,
        "cve_id": record.cve_id,
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
        "expiry": record.expiry,
        "active": record.active,
        "extra": record.extra,
    }


def _sequential_builder(*responses: Any) -> MagicMock:
    it = iter(responses)
    b = _make_builder()
    b.execute.side_effect = lambda: next(it)
    return b


def _resp(data: Any = None, count: int = 0) -> MagicMock:
    r = MagicMock()
    r.data = data if data is not None else []
    r.count = count
    return r


@pytest.fixture(autouse=True)
def reset_global_backend() -> Generator[None, None, None]:
    set_ioc_store_backend(None)
    yield
    set_ioc_store_backend(None)


@pytest.fixture()
def mock_client() -> MagicMock:
    return _make_supabase_mock()


@pytest.fixture()
def store(mock_client: MagicMock) -> Generator[IOCStore, None, None]:
    with patch(_PATCH_TARGET, return_value=mock_client):
        yield IOCStore()


class TestHelpers:
    def test_record_to_row_maps_fields(self) -> None:
        record = _make_record(extra={"a": 1}, tags=["x", "y"])
        row = _record_to_row(record)

        assert row["ioc_id"] == record.ioc_id
        assert row["ioc_type"] == record.ioc_type
        assert row["value"] == record.value
        assert row["tags"] == ["x", "y"]
        assert row["extra"] == {"a": 1}

    def test_row_to_record_parses_json_string_tags_and_extra(self) -> None:
        row = {
            "ioc_id": "ioc-1",
            "ioc_type": IOCTypeEnum.DOMAIN,
            "value": "evil.com",
            "source": ThreatFeedSourceEnum.CUSTOM_IOC,
            "severity": ThreatSeverityLevel.MEDIUM,
            "confidence": 0.5,
            "tags": '["alpha","beta"]',
            "description": "desc",
            "org_id": "org-test",
            "mitre_technique_id": "T1059",
            "mitre_tactic": "execution",
            "cve_id": "CVE-2025-1111",
            "first_seen": _NOW,
            "last_seen": _NOW,
            "expiry": None,
            "active": True,
            "feed_ingest_id": "ingest-1",
            "extra": '{"k":"v"}',
        }

        record = _row_to_record(row)

        assert record.tags == ["alpha", "beta"]
        assert record.extra == {"k": "v"}
        assert record.ioc_id == "ioc-1"

    def test_row_to_record_parses_csv_tags_and_invalid_extra(self) -> None:
        row = {
            "ioc_id": "ioc-2",
            "value": "1.2.3.4",
            "tags": "one, two ,three",
            "extra": "not-json",
        }

        record = _row_to_record(row)

        assert record.tags == ["one", "two", "three"]
        assert record.extra == {}

    def test_ingest_result_to_row_maps_fields(self) -> None:
        result = _make_ingest_result(metadata={"feed": "unit"}, errors=["x"])
        row = _ingest_result_to_row(result)

        assert row["ingest_id"] == result.ingest_id
        assert row["source"] == result.source
        assert row["errors"] == ["x"]
        assert row["metadata"] == {"feed": "unit"}

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (["a", "b"], ["a", "b"]),
            ('["a","b"]', ["a", "b"]),
            ("a,b,c", ["a", "b", "c"]),
            (None, []),
        ],
    )
    def test_parse_tags(self, raw: Any, expected: list[str]) -> None:
        assert _parse_tags(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ({"k": "v"}, {"k": "v"}),
            ('{"k":"v"}', {"k": "v"}),
            ("not-json", {}),
            (None, {}),
        ],
    )
    def test_parse_extra(self, raw: Any, expected: dict[str, Any]) -> None:
        assert _parse_extra(raw) == expected

    def test_merge_record_update_merges_expected_fields(self) -> None:
        existing = {
            "confidence": 0.4,
            "tags": '["old"]',
            "description": "old-desc",
            "extra": '{"old":"value"}',
            "expiry": _FUTURE,
        }
        record = _make_record(
            confidence=0.9,
            tags=["new"],
            description="new-desc",
            expiry=None,
            extra={"new": "value"},
        )

        merged = _merge_record_update(existing, record)

        assert merged["confidence"] == 0.9
        assert "old" in merged["tags"]
        assert "new" in merged["tags"]
        assert merged["description"] == "new-desc"
        assert merged["expiry"] == _FUTURE
        assert merged["extra"] == {"old": "value", "new": "value"}
        assert merged["active"] is True

    def test_overwrite_record_update_replaces_expected_fields(self) -> None:
        record = _make_record(
            ioc_type=IOCTypeEnum.DOMAIN,
            value="evil.com",
            confidence=0.1,
            tags=["replacement"],
            extra={"x": 1},
        )

        payload = _overwrite_record_update(record)

        assert payload["ioc_type"] == IOCTypeEnum.DOMAIN
        assert payload["value"] == "evil.com"
        assert payload["confidence"] == 0.1
        assert payload["tags"] == ["replacement"]
        assert payload["extra"] == {"x": 1}

    @pytest.mark.parametrize(
        "message",
        [
            "missing SUPABASE_URL",
            "missing SUPABASE_SERVICE_ROLE_KEY",
            "missing SUPABASE_ANON_KEY",
            "Supabase credentials not set",
        ],
    )
    def test_is_unconfigured_client_error_detects_markers(self, message: str) -> None:
        assert _is_unconfigured_client_error(RuntimeError(message)) is True

    def test_is_unconfigured_client_error_false_for_other_error(self) -> None:
        assert _is_unconfigured_client_error(RuntimeError("network down")) is False

    def test_looks_like_test_runtime_detects_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.delenv("IRONCLAW_TEST_MODE", raising=False)
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.delenv("PYTEST_VERSION", raising=False)

        assert _looks_like_test_runtime() is False

        monkeypatch.setenv("IRONCLAW_TEST_MODE", "1")
        assert _looks_like_test_runtime() is True


class TestInMemoryIOCStoreBackend:
    def test_upsert_insert_and_get_ioc(self) -> None:
        backend = InMemoryIOCStoreBackend()
        record = _make_record()

        assert backend.upsert_ioc(record) is True

        fetched = backend.get_ioc(record.ioc_id)
        assert fetched is not None
        assert fetched.ioc_id == record.ioc_id

    def test_upsert_existing_merges(self) -> None:
        backend = InMemoryIOCStoreBackend()
        backend.upsert_ioc(_make_record(ioc_id="ioc-1", confidence=0.4, tags=["old"], extra={"a": 1}))
        backend.upsert_ioc(_make_record(ioc_id="ioc-1", confidence=0.9, tags=["new"], extra={"b": 2}))

        fetched = backend.get_ioc("ioc-1")
        assert fetched is not None
        assert fetched.confidence == 0.9
        assert set(fetched.tags) == {"old", "new"}
        assert fetched.extra == {"a": 1, "b": 2}

    def test_bulk_upsert_insert_update_and_overwrite(self) -> None:
        backend = InMemoryIOCStoreBackend()
        r1 = _make_record(ioc_id="ioc-1", confidence=0.4, tags=["old"])
        r2 = _make_record(ioc_id="ioc-1", confidence=0.8, tags=["new"])
        r3 = _make_record(ioc_id="ioc-2", value="2.2.2.2")

        inserted, updated, skipped = backend.bulk_upsert([r1, r2, r3])
        assert (inserted, updated, skipped) == (2, 0, 0)

        inserted, updated, skipped = backend.bulk_upsert([_make_record(ioc_id="ioc-1", confidence=0.95, tags=["x"])])
        assert (inserted, updated, skipped) == (0, 1, 0)

        fetched = backend.get_ioc("ioc-1")
        assert fetched is not None
        assert fetched.confidence == 0.95
        assert "x" in fetched.tags

        inserted, updated, skipped = backend.bulk_upsert(
            [_make_record(ioc_id="ioc-1", confidence=0.1, tags=["replacement"])],
            overwrite=True,
        )
        assert (inserted, updated, skipped) == (0, 1, 0)

        fetched = backend.get_ioc("ioc-1")
        assert fetched is not None
        assert fetched.confidence == 0.1
        assert fetched.tags == ["replacement"]

    def test_lookup_methods_and_scope(self) -> None:
        backend = InMemoryIOCStoreBackend()
        backend.upsert_ioc(_make_record(ioc_id="ioc-1", value="evil.com", ioc_type=IOCTypeEnum.DOMAIN, org_id=None))
        backend.upsert_ioc(
            _make_record(
                ioc_id="ioc-2",
                value="1.2.3.4",
                cve_id="CVE-2025-1111",
                mitre_technique_id="T1059",
                org_id="org-a",
            )
        )
        backend.upsert_ioc(_make_record(ioc_id="ioc-3", value="2.2.2.2", active=False, org_id="org-a"))

        assert len(backend.lookup_by_value("EVIL.COM")) == 1
        assert len(backend.lookup_by_value("1.2.3.4", org_id="org-a")) == 1
        assert backend.lookup_by_value("2.2.2.2", org_id="org-a") == []
        assert len(backend.lookup_by_value("2.2.2.2", org_id="org-a", active_only=False)) == 1
        assert len(backend.lookup_by_cve("cve-2025-1111", org_id="org-a")) == 1
        assert len(backend.lookup_by_mitre_technique("t1059", org_id="org-a")) == 1
        results = backend.lookup_by_values(["EVIL.COM", "1.2.3.4"], org_id="org-a")
        assert {r.ioc_id for r in results} == {"ioc-1", "ioc-2"}

    def test_filter_iocs(self) -> None:
        backend = InMemoryIOCStoreBackend()
        backend.upsert_ioc(
            _make_record(
                ioc_id="ioc-1",
                value="evil.com",
                ioc_type=IOCTypeEnum.DOMAIN,
                severity=ThreatSeverityLevel.CRITICAL,
                tags=["ransomware", "red"],
                mitre_technique_id="T1059",
                cve_id="CVE-2025-1111",
                org_id="org-a",
                source=ThreatFeedSourceEnum.CUSTOM_IOC,
            )
        )
        backend.upsert_ioc(
            _make_record(
                ioc_id="ioc-2",
                value="1.2.3.4",
                ioc_type=IOCTypeEnum.IPV4,
                severity=ThreatSeverityLevel.LOW,
                tags=["blue"],
                org_id="org-a",
                source=ThreatFeedSourceEnum.MITRE_ATTACK,
            )
        )

        req = IOCFilterRequest(
            source=ThreatFeedSourceEnum.CUSTOM_IOC,
            ioc_type=IOCTypeEnum.DOMAIN,
            severity=ThreatSeverityLevel.CRITICAL,
            org_id="org-a",
            active=True,
            mitre_technique_id="T1059",
            cve_id="CVE-2025-1111",
            value_contains="evil",
            tag="ransomware",
            limit=10,
            offset=0,
        )
        results = backend.filter_iocs(req)

        assert len(results) == 1
        assert results[0].ioc_id == "ioc-1"

    def test_deactivate_delete_delete_by_ingest_prune_and_count(self) -> None:
        backend = InMemoryIOCStoreBackend()
        backend.upsert_ioc(_make_record(ioc_id="ioc-1", feed_ingest_id="ingest-a", expiry=_PAST))
        backend.upsert_ioc(_make_record(ioc_id="ioc-2", feed_ingest_id="ingest-a", active=True))
        backend.upsert_ioc(_make_record(ioc_id="ioc-3", feed_ingest_id="ingest-b", active=False))

        assert backend.deactivate_ioc("ioc-2") is True
        assert backend.deactivate_ioc("missing") is False

        pruned = backend.prune_expired()
        assert pruned == 1

        assert backend.count_iocs() == 3
        assert backend.count_iocs(active=True) == 0
        assert backend.count_iocs(active=False) == 3
        assert backend.count_iocs(org_id="org-test") == 3

        assert backend.delete_ioc("ioc-3") is True
        assert backend.delete_ioc("missing") is False
        assert backend.delete_by_ingest_id("ingest-a") == 2

    def test_ingest_log_and_health_check(self) -> None:
        backend = InMemoryIOCStoreBackend()
        r1 = _make_ingest_result(ingest_id="ingest-1", started_at="2026-01-02T00:00:00Z")
        r2 = _make_ingest_result(ingest_id="ingest-2", started_at="2026-01-03T00:00:00Z", source=ThreatFeedSourceEnum.MITRE_ATTACK)

        assert backend.persist_ingest_result(r1) is True
        assert backend.persist_ingest_result(r2) is True

        fetched = backend.get_ingest_result("ingest-1")
        assert fetched is not None
        assert fetched["ingest_id"] == "ingest-1"

        history = backend.list_ingest_history(limit=10, offset=0)
        assert [row["ingest_id"] for row in history] == ["ingest-2", "ingest-1"]

        filtered = backend.list_ingest_history(source=ThreatFeedSourceEnum.MITRE_ATTACK, limit=10, offset=0)
        assert [row["ingest_id"] for row in filtered] == ["ingest-2"]

        assert backend.delete_ingest_log("ingest-1") is True
        assert backend.delete_ingest_log("missing") is False

        health = backend.health_check()
        assert health["status"] == "ok"
        assert health["backend"] == "fallback"


class TestIOCStoreRuntime:
    def test_resolve_backend_takes_instance_backend(self) -> None:
        backend = InMemoryIOCStoreBackend()
        store = IOCStore(backend=backend)

        assert store._resolve_backend() is backend

    def test_resolve_backend_uses_global_backend(self) -> None:
        backend = InMemoryIOCStoreBackend()
        set_ioc_store_backend(backend)

        store = IOCStore()
        assert store._resolve_backend() is backend

    def test_can_use_fallback_true_for_backend(self) -> None:
        backend = InMemoryIOCStoreBackend()
        assert IOCStore(backend=backend)._can_use_fallback() is True

    def test_can_use_fallback_true_for_allow_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.delenv("IRONCLAW_TEST_MODE", raising=False)
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.delenv("PYTEST_VERSION", raising=False)

        assert IOCStore(allow_fallback_store=True)._can_use_fallback() is True

    def test_resolve_client_uses_injected_client(self, mock_client: MagicMock) -> None:
        store = IOCStore(client=mock_client)
        assert store._resolve_client() is mock_client

    def test_resolve_client_raises_configuration_error_for_unconfigured(self) -> None:
        with patch(_PATCH_TARGET, side_effect=RuntimeError("Supabase credentials not set")):
            with pytest.raises(IOCStoreConfigurationError):
                IOCStore()._resolve_client()

    def test_resolve_client_raises_for_none_client(self) -> None:
        with patch(_PATCH_TARGET, return_value=None):
            with pytest.raises(IOCStoreConfigurationError):
                IOCStore()._resolve_client()

    def test_resolve_runtime_uses_client_when_available(self, mock_client: MagicMock) -> None:
        with patch(_PATCH_TARGET, return_value=mock_client):
            runtime_type, runtime = IOCStore()._resolve_runtime()

        assert runtime_type == "client"
        assert runtime is mock_client

    def test_resolve_runtime_falls_back_in_test_runtime(self) -> None:
        with patch(_PATCH_TARGET, side_effect=RuntimeError("Supabase credentials not set")):
            runtime_type, runtime = IOCStore()._resolve_runtime()

        assert runtime_type == "backend"
        assert isinstance(runtime, InMemoryIOCStoreBackend)

    def test_resolve_runtime_raises_when_fallback_not_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.delenv("IRONCLAW_TEST_MODE", raising=False)
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.delenv("PYTEST_VERSION", raising=False)

        with patch(_PATCH_TARGET, side_effect=RuntimeError("Supabase credentials not set")):
            with pytest.raises(IOCStoreConfigurationError):
                IOCStore()._resolve_runtime()

    def test_setters_update_client_and_backend(self, mock_client: MagicMock) -> None:
        store = IOCStore()
        backend = InMemoryIOCStoreBackend()

        store.set_client(mock_client)
        store.set_backend(backend)

        assert store._client is mock_client
        assert store._backend is backend


class TestUpsertIoc:
    def test_insert_new_record_returns_true(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=None)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().upsert_ioc(_make_record())

        assert result is True

    def test_update_existing_merges_confidence(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-aaaa0000bbbb1111",
            "confidence": 0.5,
            "tags": ["old-tag"],
            "description": "old desc",
            "extra": {},
            "expiry": None,
        }
        builder = _sequential_builder(_resp(data=existing_row), _resp(data=[existing_row]))
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().upsert_ioc(_make_record(confidence=0.9, tags=["new-tag"]))

        assert result is True
        payload: dict[str, Any] = builder.update.call_args[0][0]
        assert payload["confidence"] == 0.9

    def test_update_existing_merges_tags(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-aaaa0000bbbb1111",
            "confidence": 0.5,
            "tags": ["alpha"],
            "description": "",
            "extra": {},
            "expiry": None,
        }
        builder = _sequential_builder(_resp(data=existing_row), _resp(data=[existing_row]))
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().upsert_ioc(_make_record(tags=["beta"]))

        assert result is True
        payload = builder.update.call_args[0][0]
        assert "alpha" in payload["tags"]
        assert "beta" in payload["tags"]

    def test_description_non_empty_incoming_wins(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-aaaa0000bbbb1111",
            "confidence": 0.5,
            "tags": [],
            "description": "",
            "extra": {},
            "expiry": None,
        }
        builder = _sequential_builder(_resp(data=existing_row), _resp(data=[existing_row]))
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().upsert_ioc(_make_record(description="new description"))

        payload = builder.update.call_args[0][0]
        assert payload["description"] == "new description"

    def test_upsert_ioc_configuration_error_returns_false_when_fallback_not_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.delenv("IRONCLAW_TEST_MODE", raising=False)
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.delenv("PYTEST_VERSION", raising=False)

        with patch(_PATCH_TARGET, side_effect=RuntimeError("Supabase credentials not set")):
            assert IOCStore().upsert_ioc(_make_record()) is False

    def test_upsert_ioc_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db down")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().upsert_ioc(_make_record())

        assert result is False


class TestBulkUpsert:
    def test_empty_list_returns_zero(self, mock_client: MagicMock) -> None:
        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([])
        assert (inserted, updated, skipped) == (0, 0, 0)

    def test_deduplication_within_batch(self, mock_client: MagicMock) -> None:
        builder = _sequential_builder(
            _resp(data=[]),
            _resp(data=[{"ioc_id": "ioc-aaaa0000bbbb1111"}]),
        )
        mock_client.table.return_value = builder

        r1 = _make_record(ioc_id="ioc-aaaa0000bbbb1111", confidence=0.7)
        r2 = _make_record(ioc_id="ioc-aaaa0000bbbb1111", confidence=0.9)

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().bulk_upsert([r1, r2])

        assert builder.insert.call_count == 1
        insert_payload = builder.insert.call_args[0][0]
        assert isinstance(insert_payload, list)
        assert len(insert_payload) == 1

    def test_bulk_upsert_inserts_new_records(self, mock_client: MagicMock) -> None:
        builder = _sequential_builder(
            _resp(data=[]),
            _resp(data=[{"ioc_id": "x"}, {"ioc_id": "y"}]),
        )
        mock_client.table.return_value = builder

        r1 = _make_record(ioc_id="ioc-0001", value="10.0.0.1")
        r2 = _make_record(ioc_id="ioc-0002", value="10.0.0.2")

        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([r1, r2])

        assert inserted == 2
        assert updated == 0
        assert skipped == 0

    def test_bulk_upsert_updates_existing_records_with_merge(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-0001",
            "confidence": 0.4,
            "tags": ["existing-tag"],
            "description": "existing desc",
            "extra": {"k": "v"},
            "expiry": None,
        }
        builder = _sequential_builder(_resp(data=[existing_row]), _resp(data=[existing_row]))
        mock_client.table.return_value = builder

        r = _make_record(ioc_id="ioc-0001", confidence=0.95, tags=["new-tag"])

        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([r])

        assert inserted == 0
        assert updated == 1
        update_payload = builder.update.call_args[0][0]
        assert update_payload["confidence"] == 0.95
        assert "existing-tag" in update_payload["tags"]
        assert "new-tag" in update_payload["tags"]

    def test_bulk_upsert_overwrite_replaces_row(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-0001",
            "confidence": 0.4,
            "tags": ["old"],
            "description": "old",
            "extra": {},
            "expiry": None,
        }
        builder = _sequential_builder(_resp(data=[existing_row]), _resp(data=[existing_row]))
        mock_client.table.return_value = builder

        r = _make_record(ioc_id="ioc-0001", confidence=0.1, tags=["replacement"])

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().bulk_upsert([r], overwrite=True)

        update_payload = builder.update.call_args[0][0]
        assert update_payload["confidence"] == 0.1
        assert update_payload["tags"] == ["replacement"]

    def test_bulk_upsert_update_error_increments_skipped(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-0001",
            "confidence": 0.4,
            "tags": [],
            "description": "",
            "extra": {},
            "expiry": None,
        }
        builder = _make_builder()
        builder.execute.side_effect = [_resp(data=[existing_row]), _resp(data=[])]
        builder.update.side_effect = [builder, RuntimeError("update failed")]
        mock_client.table.return_value = builder

        r1 = _make_record(ioc_id="ioc-0001")
        r2 = _make_record(ioc_id="ioc-0002")

        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([r1, r2])

        assert inserted == 1
        assert updated == 0
        assert skipped == 1

    def test_bulk_upsert_batch_exception_increments_skipped(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("connection refused")

        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([_make_record(ioc_id="ioc-0001"), _make_record(ioc_id="ioc-0002")])

        assert skipped == 2
        assert inserted == 0
        assert updated == 0

    def test_bulk_upsert_configuration_error_returns_zeroes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.delenv("IRONCLAW_TEST_MODE", raising=False)
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.delenv("PYTEST_VERSION", raising=False)

        with patch(_PATCH_TARGET, side_effect=RuntimeError("Supabase credentials not set")):
            assert IOCStore().bulk_upsert([_make_record()]) == (0, 0, 0)


class TestGetIoc:
    def test_returns_record_when_found(self, mock_client: MagicMock) -> None:
        record = _make_record()
        builder = _make_builder(data=_row_from_record(record))
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().get_ioc(record.ioc_id)

        assert result is not None
        assert result.ioc_id == record.ioc_id

    def test_returns_none_when_not_found(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=None)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().get_ioc("ioc-does-not-exist")

        assert result is None

    def test_exception_returns_none(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().get_ioc("ioc-0001")

        assert result is None


class TestLookupByValue:
    def test_returns_matching_record(self, mock_client: MagicMock) -> None:
        record = _make_record(value="1.2.3.4")
        builder = _make_builder(data=[_row_from_record(record)])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_value("1.2.3.4")

        assert len(results) == 1
        assert results[0].value == "1.2.3.4"
        assert isinstance(results[0], IOCRecord)

    def test_returns_empty_when_not_found(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_value("10.99.99.99")

        assert results == []

    def test_normalizes_domain_to_lowercase(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_value("EVIL.COM")

        eq_calls = [str(c) for c in builder.eq.call_args_list]
        assert any("evil.com" in c for c in eq_calls)

    def test_active_only_false_does_not_apply_active_filter(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_value("1.2.3.4", active_only=False)

        assert not any(call[0] == ("active", True) for call in builder.eq.call_args_list)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("timeout")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_value("1.2.3.4")

        assert results == []

    def test_org_id_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_value("1.2.3.4", org_id="org-xyz")

        builder.or_.assert_called_once()
        or_arg: str = builder.or_.call_args[0][0]
        assert "org-xyz" in or_arg


class TestLookupByValues:
    def test_returns_empty_for_empty_input(self, mock_client: MagicMock) -> None:
        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_values([])
        assert results == []

    def test_returns_matching_records(self, mock_client: MagicMock) -> None:
        r1 = _make_record(ioc_id="ioc-0001", value="1.1.1.1")
        r2 = _make_record(ioc_id="ioc-0002", value="2.2.2.2")
        builder = _make_builder(data=[_full_row(r1), _full_row(r2)])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_values(["1.1.1.1", "2.2.2.2"])

        assert len(results) == 2
        values = {r.value for r in results}
        assert {"1.1.1.1", "2.2.2.2"} == values

    def test_normalizes_values_before_query(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_values(["EVIL.COM", "BADGUY.NET"])

        in_calls = builder.in_.call_args_list
        assert len(in_calls) >= 1
        values_arg = in_calls[0][0][1]
        assert "evil.com" in values_arg
        assert "badguy.net" in values_arg

    def test_active_only_false_does_not_apply_active_filter(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_values(["1.2.3.4"], active_only=False)

        assert not any(call[0] == ("active", True) for call in builder.eq.call_args_list)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("network error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_values(["1.2.3.4"])

        assert results == []


class TestLookupByCve:
    def test_returns_matching_records(self, mock_client: MagicMock) -> None:
        record = _make_record(cve_id="CVE-2024-1234")
        builder = _make_builder(data=[_row_from_record(record)])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_cve("CVE-2024-1234")

        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-1234"

    def test_normalizes_cve_id_to_uppercase(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_cve("cve-2024-1234")

        eq_calls = builder.eq.call_args_list
        assert any(call[0][1] == "CVE-2024-1234" for call in eq_calls)

    def test_returns_empty_when_not_found(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_cve("CVE-0000-0000")

        assert results == []

    def test_active_only_false_does_not_apply_active_filter(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_cve("CVE-2024-1234", active_only=False)

        assert not any(call[0] == ("active", True) for call in builder.eq.call_args_list)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_cve("CVE-2024-1234")

        assert results == []

    def test_org_id_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_cve("CVE-2024-9999", org_id="org-abc")

        builder.or_.assert_called_once()
        or_arg: str = builder.or_.call_args[0][0]
        assert "org-abc" in or_arg


class TestLookupByMitreTechnique:
    def test_returns_matching_records(self, mock_client: MagicMock) -> None:
        record = _make_record(mitre_technique_id="T1059")
        builder = _make_builder(data=[_row_from_record(record)])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_mitre_technique("T1059")

        assert len(results) == 1
        assert results[0].mitre_technique_id == "T1059"

    def test_normalizes_technique_id_to_uppercase(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_mitre_technique("t1059")

        eq_calls = builder.eq.call_args_list
        assert any(call[0][1] == "T1059" for call in eq_calls)

    def test_returns_empty_when_not_found(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_mitre_technique("T9999")

        assert results == []

    def test_active_only_false_does_not_apply_active_filter(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().lookup_by_mitre_technique("T1059", active_only=False)

        assert not any(call[0] == ("active", True) for call in builder.eq.call_args_list)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_mitre_technique("T1059")

        assert results == []


class TestFilterIocs:
    def _make_row(self, ioc_id: str = "ioc-0001", severity: str = ThreatSeverityLevel.HIGH) -> dict[str, Any]:
        return {
            "ioc_id": ioc_id,
            "ioc_type": IOCTypeEnum.IPV4,
            "value": "5.5.5.5",
            "source": ThreatFeedSourceEnum.CUSTOM_IOC,
            "severity": severity,
            "confidence": 0.8,
            "tags": ["filtered"],
            "description": "",
            "org_id": "org-test",
            "mitre_technique_id": None,
            "mitre_tactic": None,
            "cve_id": None,
            "first_seen": _NOW,
            "last_seen": _NOW,
            "expiry": None,
            "active": True,
            "feed_ingest_id": "ingest-test",
            "extra": {},
        }

    def test_returns_filtered_records(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[self._make_row()])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(severity=ThreatSeverityLevel.HIGH, active=True, limit=10, offset=0)

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().filter_iocs(req)

        assert len(results) == 1
        assert results[0].severity == ThreatSeverityLevel.HIGH

    def test_returns_empty_when_no_match(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(severity=ThreatSeverityLevel.CRITICAL, limit=10, offset=0)

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().filter_iocs(req)

        assert results == []

    def test_all_filters_and_range_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(
            source=ThreatFeedSourceEnum.MITRE_ATTACK,
            ioc_type=IOCTypeEnum.DOMAIN,
            severity=ThreatSeverityLevel.HIGH,
            org_id="org-1",
            active=True,
            mitre_technique_id="T1059",
            cve_id="CVE-2025-1111",
            value_contains="evil",
            tag="ransomware",
            limit=10,
            offset=5,
        )

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().filter_iocs(req)

        builder.contains.assert_called_once_with("tags", ["ransomware"])
        builder.ilike.assert_called_once_with("value", "%evil%")
        builder.or_.assert_called_once()
        builder.range.assert_called_once_with(5, 14)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().filter_iocs(IOCFilterRequest())

        assert results == []


class TestDeactivateIoc:
    def test_returns_true_when_record_updated(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-0001"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().deactivate_ioc("ioc-0001")

        assert result is True

    def test_returns_false_when_no_row_updated(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().deactivate_ioc("ioc-does-not-exist")

        assert result is False

    def test_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().deactivate_ioc("ioc-0001")

        assert result is False

    def test_sets_active_false_in_payload(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-0001"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().deactivate_ioc("ioc-0001")

        update_payload = builder.update.call_args[0][0]
        assert update_payload["active"] is False
        assert "last_seen" in update_payload


class TestDeleteIoc:
    def test_returns_true_when_deleted(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-1"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_ioc("ioc-1") is True

    def test_returns_false_when_not_deleted(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_ioc("ioc-1") is False

    def test_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_ioc("ioc-1") is False


class TestDeleteByIngestId:
    def test_returns_deleted_count(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-1"}, {"ioc_id": "ioc-2"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_by_ingest_id("ingest-1") == 2

    def test_exception_returns_zero(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_by_ingest_id("ingest-1") == 0


class TestPruneExpired:
    def test_returns_count_when_rows_pruned(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-1"}, {"ioc_id": "ioc-2"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().prune_expired() == 2

        update_payload = builder.update.call_args[0][0]
        assert update_payload["active"] is False
        builder.lt.assert_called_once()
        builder.is_.assert_called_once_with("expiry", "null")

    def test_exception_returns_zero(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().prune_expired() == 0


class TestCountIocs:
    def test_returns_count(self, mock_client: MagicMock) -> None:
        builder = _make_builder(count=7)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            count = IOCStore().count_iocs(
                source=ThreatFeedSourceEnum.CUSTOM_IOC,
                active=True,
                org_id="org-1",
            )

        assert count == 7
        builder.or_.assert_called_once()

    def test_returns_zero_when_count_missing(self, mock_client: MagicMock) -> None:
        builder = _make_builder()
        builder.execute.return_value.count = None
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().count_iocs() == 0

    def test_exception_returns_zero(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().count_iocs() == 0


class TestPersistIngestResult:
    def test_upsert_success_returns_true(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ingest_id": "ingest-1"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().persist_ingest_result(_make_ingest_result()) is True

        builder.upsert.assert_called_once()

    def test_insert_fallback_after_upsert_failure_returns_true(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ingest_id": "ingest-1"}])
        builder.upsert.side_effect = RuntimeError("upsert unsupported")
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().persist_ingest_result(_make_ingest_result()) is True

        builder.insert.assert_called_once()

    def test_duplicate_insert_conflict_returns_true(self, mock_client: MagicMock) -> None:
        builder = _make_builder()
        builder.upsert.side_effect = RuntimeError("upsert unsupported")
        builder.insert.side_effect = RuntimeError("409 duplicate key value violates unique constraint")
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().persist_ingest_result(_make_ingest_result()) is True

    def test_exception_returns_false(self, mock_client: MagicMock) -> None:
        builder = _make_builder()
        builder.upsert.side_effect = RuntimeError("upsert unsupported")
        builder.insert.side_effect = RuntimeError("other failure")
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().persist_ingest_result(_make_ingest_result()) is False


class TestGetIngestResult:
    def test_returns_row(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data={"ingest_id": "ingest-1"})
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().get_ingest_result("ingest-1")

        assert result == {"ingest_id": "ingest-1"}

    def test_returns_none(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=None)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().get_ingest_result("ingest-1") is None

    def test_exception_returns_none(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().get_ingest_result("ingest-1") is None


class TestListIngestHistory:
    def test_returns_rows(self, mock_client: MagicMock) -> None:
        rows = [{"ingest_id": "ingest-2"}, {"ingest_id": "ingest-1"}]
        builder = _make_builder(data=rows)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().list_ingest_history(
                source=ThreatFeedSourceEnum.CUSTOM_IOC,
                org_id="org-1",
                limit=10,
                offset=5,
            )

        assert result == rows
        builder.order.assert_called_once_with("started_at", desc=True)
        builder.or_.assert_called_once()
        builder.range.assert_called_once_with(5, 14)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().list_ingest_history() == []


class TestDeleteIngestLog:
    def test_returns_true_when_deleted(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ingest_id": "ingest-1"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_ingest_log("ingest-1") is True

    def test_returns_false_when_not_deleted(self, mock_client: MagicMock) -> None:
        builder = _make_builder()
        builder.delete.return_value = builder
        builder.eq.return_value = builder
        response = MagicMock()
        response.data = None
        response.count = 0
        builder.execute.return_value = response
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_ingest_log("ingest-1") is False

    def test_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            assert IOCStore().delete_ingest_log("ingest-1") is False


class TestHealthCheck:
    def test_backend_health_check_path(self) -> None:
        store = IOCStore(backend=InMemoryIOCStoreBackend())

        result = store.health_check()

        assert result["status"] == "ok"
        assert result["backend"] == "fallback"

    def test_client_health_check_ok(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-1"}], count=3)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().health_check()

        assert result["status"] == "ok"
        assert result["backend"] == "supabase"
        assert result["ioc_count"] == 3

    def test_health_check_unconfigured_returns_unconfigured_when_fallback_not_allowed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.delenv("IRONCLAW_TEST_MODE", raising=False)
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.delenv("PYTEST_VERSION", raising=False)

        with patch(_PATCH_TARGET, side_effect=RuntimeError("Supabase credentials not set")):
            result = IOCStore().health_check()

        assert result["status"] == "unconfigured"

    def test_health_check_exception_returns_error(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db failure")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().health_check()

        assert result["status"] == "error"
