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

_PATCH_TARGET = "app.services.ioc_store._get_client"


# ---------------------------------------------------------------------------
# Builders / factories
# ---------------------------------------------------------------------------


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
    """Return a fully-chained Supabase query builder mock."""
    resp = MagicMock()
    resp.data = data if data is not None else []
    resp.count = count

    b = MagicMock()
    for method in (
        "select",
        "insert",
        "update",
        "delete",
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


def _sequential_builder(*responses: Any) -> MagicMock:
    """
    Return a builder whose execute() returns each response in order.
    Eliminates the repeated call_count / side_effect boilerplate.
    """
    it = iter(responses)
    b = _make_builder()
    b.execute.side_effect = lambda: next(it)
    return b


def _resp(data: Any = None, count: int = 0) -> MagicMock:
    r = MagicMock()
    r.data = data if data is not None else []
    r.count = count
    return r


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_client() -> MagicMock:
    return _make_supabase_mock()


@pytest.fixture()
def store(mock_client: MagicMock) -> IOCStore:
    with patch(_PATCH_TARGET, return_value=mock_client):
        yield IOCStore()


# ---------------------------------------------------------------------------
# upsert_ioc
# ---------------------------------------------------------------------------


class TestUpsertIoc:
    def test_insert_new_record_returns_true(self, mock_client: MagicMock) -> None:
        # maybe_single().execute() returns data=None → triggers insert path
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
        # first execute() → select existing; second → update confirmation
        builder = _sequential_builder(_resp(data=existing_row), _resp(data=[existing_row]))
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().upsert_ioc(_make_record(confidence=0.9, tags=["new-tag"]))

        assert result is True
        payload: dict[str, Any] = builder.update.call_args[0][0]
        # _merge_record_update takes max(existing=0.5, incoming=0.9) → 0.9
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

    def test_upsert_ioc_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db down")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().upsert_ioc(_make_record())

        assert result is False

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


# ---------------------------------------------------------------------------
# bulk_upsert
# ---------------------------------------------------------------------------


class TestBulkUpsert:
    def test_empty_list_returns_zero(self, mock_client: MagicMock) -> None:
        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([])
        assert (inserted, updated, skipped) == (0, 0, 0)

    def test_deduplication_within_batch(self, mock_client: MagicMock) -> None:
        # Both records share the same ioc_id; dedup keeps the last one.
        # select returns empty → both treated as new, but only 1 unique id after dedup.
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
        # select returns empty → both records go to insert path
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
        # select returns existing row → update path; second execute → update result
        builder = _sequential_builder(_resp(data=[existing_row]), _resp(data=[existing_row]))
        mock_client.table.return_value = builder

        r = _make_record(ioc_id="ioc-0001", confidence=0.95, tags=["new-tag"])

        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([r])

        assert inserted == 0
        assert updated == 1
        update_payload = builder.update.call_args[0][0]
        # max(0.4, 0.95) → 0.95
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
        # overwrite=True uses _record_to_row → confidence comes directly from record
        assert update_payload["confidence"] == 0.1

    def test_bulk_upsert_batch_exception_increments_skipped(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("connection refused")

        with patch(_PATCH_TARGET, return_value=mock_client):
            inserted, updated, skipped = IOCStore().bulk_upsert([_make_record(ioc_id="ioc-0001"), _make_record(ioc_id="ioc-0002")])

        assert skipped == 2
        assert inserted == 0
        assert updated == 0


# ---------------------------------------------------------------------------
# get_ioc
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# lookup_by_value
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# lookup_by_values
# ---------------------------------------------------------------------------


def _full_row(record: IOCRecord) -> dict[str, Any]:
    return {
        **_row_from_record(record),
        "mitre_technique_id": None,
        "mitre_tactic": None,
        "cve_id": None,
        "first_seen": _NOW,
        "last_seen": _NOW,
        "expiry": None,
        "active": True,
        "extra": {},
    }


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

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("network error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_values(["1.2.3.4"])

        assert results == []


# ---------------------------------------------------------------------------
# lookup_by_cve
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# lookup_by_mitre_technique
# ---------------------------------------------------------------------------


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

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().lookup_by_mitre_technique("T1059")

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

    def test_source_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(source=ThreatFeedSourceEnum.MITRE_ATTACK, limit=10, offset=0)

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().filter_iocs(req)

        eq_calls = builder.eq.call_args_list
        assert any(call[0][0] == "source" and call[0][1] == ThreatFeedSourceEnum.MITRE_ATTACK for call in eq_calls)

    def test_tag_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(tag="ransomware", limit=10, offset=0)

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().filter_iocs(req)

        builder.contains.assert_called_once_with("tags", ["ransomware"])

    def test_value_contains_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        req = IOCFilterRequest(value_contains="evil", limit=10, offset=0)

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().filter_iocs(req)

        builder.ilike.assert_called_once_with("value", "%evil%")

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().filter_iocs(IOCFilterRequest())

        assert results == []


# ---------------------------------------------------------------------------
# deactivate_ioc
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# delete_ioc
# ---------------------------------------------------------------------------


class TestDeleteIoc:
    def test_returns_true_when_deleted(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-0001"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().delete_ioc("ioc-0001")

        assert result is True

    def test_returns_false_when_no_row_deleted(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().delete_ioc("ioc-does-not-exist")

        assert result is False

    def test_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().delete_ioc("ioc-0001")

        assert result is False


# ---------------------------------------------------------------------------
# delete_by_ingest_id
# ---------------------------------------------------------------------------


class TestDeleteByIngestId:
    def test_returns_count_of_deleted_records(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-0001"}, {"ioc_id": "ioc-0002"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            count = IOCStore().delete_by_ingest_id("ingest-test0001")

        assert count == 2

    def test_returns_zero_when_nothing_deleted(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            count = IOCStore().delete_by_ingest_id("ingest-none")

        assert count == 0

    def test_exception_returns_zero(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            count = IOCStore().delete_by_ingest_id("ingest-test0001")

        assert count == 0


# ---------------------------------------------------------------------------
# prune_expired
# ---------------------------------------------------------------------------


class TestPruneExpired:
    def test_deactivates_expired_records_returns_count(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ioc_id": "ioc-exp-0001"}, {"ioc_id": "ioc-exp-0002"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            count = IOCStore().prune_expired()

        assert count == 2

    def test_returns_zero_when_nothing_pruned(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            count = IOCStore().prune_expired()

        assert count == 0

    def test_active_false_and_lt_expiry_filters_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().prune_expired()

        # prune_expired does: .eq("active", True).lt("expiry", now_iso).not_.is_("expiry", "null")
        builder.eq.assert_called_once_with("active", True)
        builder.lt.assert_called_once()

    def test_exception_returns_zero(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            count = IOCStore().prune_expired()

        assert count == 0


# ---------------------------------------------------------------------------
# count_iocs
# ---------------------------------------------------------------------------


class TestCountIocs:
    def test_returns_count_from_response(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[], count=17)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().count_iocs()

        assert result == 17

    def test_source_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[], count=5)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().count_iocs(source=ThreatFeedSourceEnum.CUSTOM_IOC)

        eq_calls = builder.eq.call_args_list
        assert any(call[0][0] == "source" for call in eq_calls)

    def test_returns_zero_on_none_count(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[], count=0)
        builder.execute.return_value.count = None
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().count_iocs()

        assert result == 0

    def test_exception_returns_zero(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().count_iocs()

        assert result == 0


# ---------------------------------------------------------------------------
# persist_ingest_result
# ---------------------------------------------------------------------------


class TestPersistIngestResult:
    def test_returns_true_on_success(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ingest_id": "ingest-abc123"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            ok = IOCStore().persist_ingest_result(_make_ingest_result())

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

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().persist_ingest_result(result_obj)

        insert_payload: dict[str, Any] = builder.insert.call_args[0][0]
        assert insert_payload["ingest_id"] == "ingest-abc123"
        assert insert_payload["iocs_parsed"] == 10
        assert insert_payload["iocs_inserted"] == 8
        assert insert_payload["iocs_updated"] == 2
        assert insert_payload["iocs_skipped"] == 0

    def test_returns_false_on_exception(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("write error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            ok = IOCStore().persist_ingest_result(_make_ingest_result())

        assert ok is False


# ---------------------------------------------------------------------------
# get_ingest_result
# ---------------------------------------------------------------------------


class TestGetIngestResult:
    def test_returns_dict_when_found(self, mock_client: MagicMock) -> None:
        row = {"ingest_id": "ingest-abc123", "status": IngestStatusEnum.SUCCESS}
        builder = _make_builder(data=row)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().get_ingest_result("ingest-abc123")

        assert result is not None
        assert result["ingest_id"] == "ingest-abc123"

    def test_returns_none_when_not_found(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=None)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().get_ingest_result("ingest-does-not-exist")

        assert result is None

    def test_exception_returns_none(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().get_ingest_result("ingest-abc123")

        assert result is None


# ---------------------------------------------------------------------------
# list_ingest_history
# ---------------------------------------------------------------------------


class TestListIngestHistory:
    def test_returns_list_of_dicts(self, mock_client: MagicMock) -> None:
        rows = [
            {"ingest_id": "ingest-001", "status": IngestStatusEnum.SUCCESS},
            {"ingest_id": "ingest-002", "status": IngestStatusEnum.PARTIAL},
        ]
        builder = _make_builder(data=rows)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().list_ingest_history()

        assert len(results) == 2

    def test_returns_empty_when_no_history(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().list_ingest_history()

        assert results == []

    def test_source_filter_applied(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            IOCStore().list_ingest_history(source=ThreatFeedSourceEnum.CUSTOM_IOC)

        eq_calls = builder.eq.call_args_list
        assert any(call[0][0] == "source" for call in eq_calls)

    def test_exception_returns_empty_list(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            results = IOCStore().list_ingest_history()

        assert results == []


# ---------------------------------------------------------------------------
# delete_ingest_log
# ---------------------------------------------------------------------------


class TestDeleteIngestLog:
    def test_returns_true_on_success(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[{"ingest_id": "ingest-abc123"}])
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().delete_ingest_log("ingest-abc123")

        assert result is True

    def test_exception_returns_false(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db error")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().delete_ingest_log("ingest-abc123")

        assert result is False


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_returns_ok_status_with_count(self, mock_client: MagicMock) -> None:
        builder = _make_builder(data=[], count=42)
        mock_client.table.return_value = builder

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().health_check()

        assert result["status"] == "ok"
        assert result["ioc_count"] == 42

    def test_returns_error_status_on_exception(self, mock_client: MagicMock) -> None:
        mock_client.table.side_effect = RuntimeError("db down")

        with patch(_PATCH_TARGET, return_value=mock_client):
            result = IOCStore().health_check()

        assert result["status"] == "error"
        assert "detail" in result
