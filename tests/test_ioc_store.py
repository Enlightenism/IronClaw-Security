from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.schemas.threat_detection import (
    IngestStatusEnum,
    IOCTypeEnum,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)
from app.services.ioc_store import IOCStore
from app.services.threat_feed_ingestion import (
    FeedIngestResult,
    IOCFilterRequest,
    IOCRecord,
    _utcnow_iso,
)

_NOW = _utcnow_iso()
_PAST = "2020-01-01T00:00:00Z"
_FUTURE = "2099-12-31T23:59:59Z"


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


def _make_builder(data=None, count=0) -> MagicMock:
    resp = MagicMock()
    resp.data = data if data is not None else []
    resp.count = count
    b = MagicMock()
    b.select.return_value = b
    b.insert.return_value = b
    b.update.return_value = b
    b.delete.return_value = b
    b.eq.return_value = b
    b.neq.return_value = b
    b.lt.return_value = b
    b.lte.return_value = b
    b.gt.return_value = b
    b.gte.return_value = b
    b.in_.return_value = b
    b.or_.return_value = b
    b.not_ = b
    b.is_.return_value = b
    b.ilike.return_value = b
    b.contains.return_value = b
    b.limit.return_value = b
    b.range.return_value = b
    b.order.return_value = b
    b.maybe_single.return_value = b
    b.execute.return_value = resp
    return b


def _make_supabase_mock() -> MagicMock:
    client = MagicMock()
    client.table.return_value = _make_builder()
    return client


@pytest.fixture()
def mock_client() -> MagicMock:
    return _make_supabase_mock()


@pytest.fixture()
def store(mock_client: MagicMock) -> IOCStore:
    with patch("app.services.ioc_store._get_client", return_value=mock_client):
        yield IOCStore()


# ---------------------------------------------------------------------------
# upsert_ioc
# ---------------------------------------------------------------------------


class TestUpsertIoc:
    def test_insert_new_record_returns_true(self, mock_client: MagicMock) -> None:
        resp_none = MagicMock()
        resp_none.data = None

        builder = _make_builder()
        builder.execute.return_value = resp_none
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            result = store.upsert_ioc(_make_record())

        assert result is True

    def test_update_existing_merges_confidence(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-aaaa0000bbbb1111",
            "confidence": 0.5,
            "tags": ["old-tag"],
            "description": "old desc",
            "extra": {},
        }
        resp_existing = MagicMock()
        resp_existing.data = existing_row

        resp_ok = MagicMock()
        resp_ok.data = [existing_row]

        table_mock = _make_builder()
        table_mock.maybe_single.return_value = table_mock

        call_count = [0]

        def execute_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return resp_existing
            return resp_ok

        table_mock.execute.side_effect = execute_side_effect
        mock_client.table.return_value = table_mock

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            result = store.upsert_ioc(_make_record(confidence=0.9, tags=["new-tag"]))

        assert result is True
        call_args = table_mock.update.call_args
        payload: dict[str, Any] = call_args[0][0]
        assert payload["confidence"] == 0.9

    def test_update_existing_merges_tags(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-aaaa0000bbbb1111",
            "confidence": 0.5,
            "tags": ["alpha"],
            "description": "",
            "extra": {},
        }
        resp_existing = MagicMock()
        resp_existing.data = existing_row

        resp_ok = MagicMock()
        resp_ok.data = [existing_row]

        table_mock = _make_builder()
        call_count = [0]

        def execute_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return resp_existing
            return resp_ok

        table_mock.execute.side_effect = execute_side_effect
        mock_client.table.return_value = table_mock

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            result = store.upsert_ioc(_make_record(tags=["beta"]))

        assert result is True
        payload = table_mock.update.call_args[0][0]
        assert "alpha" in payload["tags"]
        assert "beta" in payload["tags"]

    def test_upsert_ioc_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db down")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            result = store.upsert_ioc(_make_record())

        assert result is False

    def test_description_non_empty_incoming_wins(self, mock_client: MagicMock) -> None:
        existing_row = {
            "ioc_id": "ioc-aaaa0000bbbb1111",
            "confidence": 0.5,
            "tags": [],
            "description": "",
            "extra": {},
        }
        resp_existing = MagicMock()
        resp_existing.data = existing_row

        resp_ok = MagicMock()
        resp_ok.data = [existing_row]

        table_mock = _make_builder()
        call_count = [0]

        def execute_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return resp_existing
            return resp_ok

        table_mock.execute.side_effect = execute_side_effect
        mock_client.table.return_value = table_mock

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.upsert_ioc(_make_record(description="new description"))

        payload = table_mock.update.call_args[0][0]
        assert payload["description"] == "new description"


# ---------------------------------------------------------------------------
# bulk_upsert
# ---------------------------------------------------------------------------


class TestBulkUpsert:
    def test_empty_list_returns_zero(self, mock_client: MagicMock) -> None:
        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            inserted, updated, skipped = store.bulk_upsert([])
        assert (inserted, updated, skipped) == (0, 0, 0)

    def test_deduplication_within_batch(self, mock_client: MagicMock) -> None:
        resp_empty = MagicMock()
        resp_empty.data = []

        resp_insert = MagicMock()
        resp_insert.data = [{"ioc_id": "ioc-aaaa0000bbbb1111"}]

        table_mock = _make_builder()
        call_count = [0]

        def execute_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return resp_empty
            return resp_insert

        table_mock.execute.side_effect = execute_side_effect
        mock_client.table.return_value = table_mock

        r1 = _make_record(ioc_id="ioc-aaaa0000bbbb1111", confidence=0.7)
        r2 = _make_record(ioc_id="ioc-aaaa0000bbbb1111", confidence=0.9)

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            inserted, updated, skipped = store.bulk_upsert([r1, r2])

        assert table_mock.insert.call_count == 1
        insert_payload = table_mock.insert.call_args[0][0]
        assert isinstance(insert_payload, list)
        assert len(insert_payload) == 1

    def test_bulk_upsert_inserts_new_records(self, mock_client: MagicMock) -> None:
        resp_empty = MagicMock()
        resp_empty.data = []

        resp_insert = MagicMock()
        resp_insert.data = [{"ioc_id": "x"}, {"ioc_id": "y"}]

        table_mock = _make_builder()
        call_count = [0]

        def execute_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return resp_empty
            return resp_insert

        table_mock.execute.side_effect = execute_side_effect
        mock_client.table.return_value = table_mock

        r1 = _make_record(ioc_id="ioc-0001", value="10.0.0.1")
        r2 = _make_record(ioc_id="ioc-0002", value="10.0.0.2")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            inserted, updated, skipped = store.bulk_upsert([r1, r2])

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
        resp_existing = MagicMock()
        resp_existing.data = [existing_row]

        resp_update = MagicMock()
        resp_update.data = [existing_row]

        table_mock = _make_builder()
        call_count = [0]

        def execute_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return resp_existing
            return resp_update

        table_mock.execute.side_effect = execute_side_effect
        mock_client.table.return_value = table_mock

        r = _make_record(ioc_id="ioc-0001", confidence=0.95, tags=["new-tag"])

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            inserted, updated, skipped = store.bulk_upsert([r])

        assert inserted == 0
        assert updated == 1
        update_payload = table_mock.update.call_args[0][0]
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
        resp_existing = MagicMock()
        resp_existing.data = [existing_row]

        resp_update = MagicMock()
        resp_update.data = [existing_row]

        table_mock = _make_builder()
        call_count = [0]

        def execute_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return resp_existing
            return resp_update

        table_mock.execute.side_effect = execute_side_effect
        mock_client.table.return_value = table_mock

        r = _make_record(ioc_id="ioc-0001", confidence=0.1, tags=["replacement"])

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.bulk_upsert([r], overwrite=True)

        update_payload = table_mock.update.call_args[0][0]
        assert update_payload["confidence"] == 0.1

    def test_bulk_upsert_batch_exception_increments_skipped(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("connection refused")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            inserted, updated, skipped = store.bulk_upsert([_make_record(ioc_id="ioc-0001"), _make_record(ioc_id="ioc-0002")])

        assert skipped == 2
        assert inserted == 0
        assert updated == 0


# ---------------------------------------------------------------------------
# lookup_by_value
# ---------------------------------------------------------------------------


class TestLookupByValue:
    def _row_from_record(self, record: IOCRecord) -> dict[str, Any]:
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

    def test_returns_matching_record(self, mock_client: MagicMock) -> None:
        record = _make_record(value="1.2.3.4")
        row = self._row_from_record(record)

        builder = _make_builder(data=[row])
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.lookup_by_value("1.2.3.4")

        assert len(results) == 1
        assert results[0].value == "1.2.3.4"
        assert isinstance(results[0], IOCRecord)

    def test_returns_empty_when_not_found(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.lookup_by_value("10.99.99.99")

        assert results == []

    def test_normalizes_domain_to_lowercase(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.lookup_by_value("EVIL.COM")

        eq_calls = [str(c) for c in builder.eq.call_args_list]
        assert any("evil.com" in c for c in eq_calls)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("timeout")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.lookup_by_value("1.2.3.4")

        assert results == []

    def test_org_id_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.lookup_by_value("1.2.3.4", org_id="org-xyz")

        builder.or_.assert_called_once()
        or_arg: str = builder.or_.call_args[0][0]
        assert "org-xyz" in or_arg


# ---------------------------------------------------------------------------
# lookup_by_values
# ---------------------------------------------------------------------------


class TestLookupByValues:
    def test_returns_empty_for_empty_input(self, mock_client: MagicMock) -> None:
        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.lookup_by_values([])
        assert results == []

    def test_returns_matching_records(self, mock_client: MagicMock) -> None:
        record1 = _make_record(ioc_id="ioc-0001", value="1.1.1.1")
        record2 = _make_record(ioc_id="ioc-0002", value="2.2.2.2")

        rows = [
            {
                "ioc_id": record1.ioc_id,
                "ioc_type": record1.ioc_type,
                "value": record1.value,
                "source": record1.source,
                "severity": record1.severity,
                "confidence": record1.confidence,
                "tags": record1.tags,
                "description": record1.description,
                "org_id": record1.org_id,
                "mitre_technique_id": None,
                "mitre_tactic": None,
                "cve_id": None,
                "first_seen": _NOW,
                "last_seen": _NOW,
                "expiry": None,
                "active": True,
                "feed_ingest_id": record1.feed_ingest_id,
                "extra": {},
            },
            {
                "ioc_id": record2.ioc_id,
                "ioc_type": record2.ioc_type,
                "value": record2.value,
                "source": record2.source,
                "severity": record2.severity,
                "confidence": record2.confidence,
                "tags": record2.tags,
                "description": record2.description,
                "org_id": record2.org_id,
                "mitre_technique_id": None,
                "mitre_tactic": None,
                "cve_id": None,
                "first_seen": _NOW,
                "last_seen": _NOW,
                "expiry": None,
                "active": True,
                "feed_ingest_id": record2.feed_ingest_id,
                "extra": {},
            },
        ]

        builder = _make_builder(data=rows)
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.lookup_by_values(["1.1.1.1", "2.2.2.2"])

        assert len(results) == 2
        values = {r.value for r in results}
        assert "1.1.1.1" in values
        assert "2.2.2.2" in values

    def test_normalizes_values_before_query(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.lookup_by_values(["EVIL.COM", "BADGUY.NET"])

        in_calls = builder.in_.call_args_list
        assert len(in_calls) >= 1
        values_arg = in_calls[0][0][1]
        assert "evil.com" in values_arg
        assert "badguy.net" in values_arg

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("network error")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.lookup_by_values(["1.2.3.4"])

        assert results == []


# ---------------------------------------------------------------------------
# filter_iocs
# ---------------------------------------------------------------------------


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

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.filter_iocs(req)

        assert len(results) == 1
        assert results[0].severity == ThreatSeverityLevel.HIGH

    def test_returns_empty_when_no_match(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(severity=ThreatSeverityLevel.CRITICAL, limit=10, offset=0)

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.filter_iocs(req)

        assert results == []

    def test_source_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(source=ThreatFeedSourceEnum.MITRE_ATTACK, limit=10, offset=0)

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.filter_iocs(req)

        eq_calls = builder.eq.call_args_list
        assert any(call[0][0] == "source" and call[0][1] == ThreatFeedSourceEnum.MITRE_ATTACK for call in eq_calls)

    def test_tag_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(tag="ransomware", limit=10, offset=0)

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.filter_iocs(req)

        builder.contains.assert_called_once_with("tags", ["ransomware"])

    def test_value_contains_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(value_contains="evil", limit=10, offset=0)

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.filter_iocs(req)

        builder.ilike.assert_called_once_with("value", "%evil%")

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            results = store.filter_iocs(IOCFilterRequest())

        assert results == []


# ---------------------------------------------------------------------------
# prune_expired
# ---------------------------------------------------------------------------


class TestPruneExpired:
    def test_deactivates_expired_records_returns_count(self, mock_client: MagicMock) -> None:
        pruned_rows = [{"ioc_id": "ioc-exp-0001"}, {"ioc_id": "ioc-exp-0002"}]
        builder = _make_builder(data=pruned_rows)
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            count = store.prune_expired()

        assert count == 2

    def test_returns_zero_when_nothing_pruned(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            count = store.prune_expired()

        assert count == 0

    def test_active_false_and_lt_expiry_filters_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.prune_expired()

        builder.eq.assert_called_once_with("active", True)
        builder.lt.assert_called_once()

    def test_exception_returns_zero(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            count = store.prune_expired()

        assert count == 0


# ---------------------------------------------------------------------------
# persist_ingest_result
# ---------------------------------------------------------------------------


class TestPersistIngestResult:
    def test_returns_true_on_success(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ingest_id": "ingest-abc123"}])
        mock_client.table.return_value = builder

        result_obj = _make_ingest_result()

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            ok = store.persist_ingest_result(result_obj)

        builder.insert.assert_called_once()
        assert ok is True

    def test_serializes_all_fields(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ingest_id": "ingest-abc123"}])
        mock_client.table.return_value = builder

        result_obj = _make_ingest_result(
            ingest_id="ingest-abc123",
            iocs_parsed=10,
            iocs_inserted=8,
            iocs_updated=2,
            iocs_skipped=0,
        )

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            store.persist_ingest_result(result_obj)

        insert_payload: dict[str, Any] = builder.insert.call_args[0][0]
        assert insert_payload["ingest_id"] == "ingest-abc123"
        assert insert_payload["iocs_parsed"] == 10
        assert insert_payload["iocs_inserted"] == 8
        assert insert_payload["iocs_updated"] == 2
        assert insert_payload["iocs_skipped"] == 0

    def test_returns_false_on_exception(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("write error")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            ok = store.persist_ingest_result(_make_ingest_result())

        assert ok is False


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_returns_ok_status_with_count(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[], count=42)
        mock_client.table.return_value = builder

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            result = store.health_check()

        assert result["status"] == "ok"
        assert result["ioc_count"] == 42

    def test_returns_error_status_on_exception(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db down")

        with patch("app.services.ioc_store._get_client", return_value=mock_client):
            store = IOCStore()
            result = store.health_check()

        assert result["status"] == "error"
        assert "detail" in result
