from __future__ import annotations

from collections.abc import Generator
import csv
from datetime import UTC, datetime, timedelta
import io
from pathlib import Path
import tomllib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.billing_store import (
    MeterEventRecord,
    SubscriptionMeterStore,
    SubscriptionRecord,
)
from app.services.report_export import (
    ReportExportService,
    _parse_ts,
    get_report_export_service,
    reset_report_export_service,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_subscription(
    org_id: str = "org-test-001",
    plan_name: str = "pro",
    status: str = "active",
    included_units: int = 25_000,
    used_units: int = 2_500,
    overage_units: int = 0,
) -> SubscriptionRecord:
    now = datetime.now(UTC)
    return SubscriptionRecord(
        subscription_id=f"sub-test-{org_id}",
        org_id=org_id,
        plan_name=plan_name,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        billing_email=f"billing@{org_id}.dev",
        period_start=now.replace(day=1),
        period_end=now.replace(day=28),
        included_units=included_units,
        used_units=used_units,
        overage_units=overage_units,
        price_usd_monthly=299,
    )


def _make_meter_event(
    org_id: str = "org-test-001",
    event_type: str = "scan",
    quantity: int = 100,
    occurred_at: datetime | None = None,
) -> MeterEventRecord:
    return MeterEventRecord(
        event_id=f"mtr-test-{org_id}-{event_type}",
        org_id=org_id,
        event_type=event_type,  # type: ignore[arg-type]
        quantity=quantity,
        occurred_at=occurred_at or datetime.now(UTC),
    )


def _make_audit_record(
    timestamp: str | None = None,
    actor: str = "ironclaw",
    action: str = "policy_decision",
) -> dict[str, Any]:
    ts = timestamp or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {"timestamp": ts, "actor": actor, "action": action, "outcome": "block"}


def _build_service(
    subs: list[SubscriptionRecord] | None = None,
    events: list[MeterEventRecord] | None = None,
    audit_records: list[dict[str, Any]] | None = None,
) -> ReportExportService:
    meter_store = MagicMock(spec=SubscriptionMeterStore)
    meter_store.list_subscriptions.return_value = subs or []
    meter_store.list_meter_events.return_value = events or []

    audit_store = MagicMock()
    if audit_records is None:
        audit_store.list_entries.side_effect = AttributeError("list_entries not available")
    else:
        audit_store.list_entries.return_value = audit_records

    return ReportExportService(
        subscription_meter_store=meter_store,
        audit_store=audit_store,
    )


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    reset_report_export_service()
    yield
    reset_report_export_service()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_csv(payload: bytes) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(payload.decode("utf-8")))
    headers = reader.fieldnames or []
    rows = list(reader)
    return list(headers), rows


# ---------------------------------------------------------------------------
# ReportExportService — construction
# ---------------------------------------------------------------------------


def test_service_constructs_with_defaults() -> None:
    svc = ReportExportService()
    assert svc is not None


def test_service_constructs_with_injected_stores() -> None:
    svc = _build_service()
    assert svc is not None


def test_supported_report_types_returns_all_four() -> None:
    svc = _build_service()
    types = svc.supported_report_types()
    assert set(types) == {"meter_events", "subscriptions", "audit_log", "usage_summary"}


def test_supported_formats_always_includes_csv() -> None:
    svc = _build_service()
    assert "csv" in svc.supported_formats()


def test_pdf_available_returns_bool() -> None:
    svc = _build_service()
    assert isinstance(svc.pdf_available(), bool)


# ---------------------------------------------------------------------------
# CSV — meter_events
# ---------------------------------------------------------------------------


def test_meter_events_csv_returns_bytes_and_content_type() -> None:
    events = [_make_meter_event()]
    svc = _build_service(events=events)
    payload, ct = svc.export(report_type="meter_events", fmt="csv")
    assert isinstance(payload, bytes)
    assert ct == "text/csv; charset=utf-8"


def test_meter_events_csv_headers() -> None:
    svc = _build_service(events=[_make_meter_event()])
    payload, _ = svc.export(report_type="meter_events", fmt="csv")
    headers, _ = _parse_csv(payload)
    assert headers == ["event_id", "org_id", "event_type", "quantity", "occurred_at"]


def test_meter_events_csv_row_values() -> None:
    now = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    event = _make_meter_event(org_id="org-a", event_type="scan", quantity=42, occurred_at=now)
    svc = _build_service(events=[event])
    payload, _ = svc.export(report_type="meter_events", fmt="csv")
    _, rows = _parse_csv(payload)
    assert len(rows) == 1
    row = rows[0]
    assert row["org_id"] == "org-a"
    assert row["event_type"] == "scan"
    assert row["quantity"] == "42"
    assert "2026-05-01" in row["occurred_at"]


def test_meter_events_csv_empty_produces_headers_only() -> None:
    svc = _build_service(events=[])
    payload, _ = svc.export(report_type="meter_events", fmt="csv")
    headers, rows = _parse_csv(payload)
    assert headers == ["event_id", "org_id", "event_type", "quantity", "occurred_at"]
    assert rows == []


def test_meter_events_csv_multiple_events() -> None:
    events = [
        _make_meter_event(org_id="org-a", event_type="scan", quantity=10),
        _make_meter_event(org_id="org-a", event_type="guard_request", quantity=5),
        _make_meter_event(org_id="org-b", event_type="execution", quantity=3),
    ]
    svc = _build_service(events=events)
    payload, _ = svc.export(report_type="meter_events", fmt="csv")
    _, rows = _parse_csv(payload)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# CSV — subscriptions
# ---------------------------------------------------------------------------


def test_subscriptions_csv_headers() -> None:
    subs = [_make_subscription()]
    svc = _build_service(subs=subs)
    payload, ct = svc.export(report_type="subscriptions", fmt="csv")
    headers, _ = _parse_csv(payload)
    assert "subscription_id" in headers
    assert "org_id" in headers
    assert "plan_name" in headers
    assert "status" in headers
    assert "billing_email" in headers
    assert ct == "text/csv; charset=utf-8"


def test_subscriptions_csv_row_values() -> None:
    sub = _make_subscription(org_id="org-z", plan_name="enterprise", included_units=60_000, used_units=9_999)
    svc = _build_service(subs=[sub])
    payload, _ = svc.export(report_type="subscriptions", fmt="csv")
    _, rows = _parse_csv(payload)
    assert len(rows) == 1
    row = rows[0]
    assert row["org_id"] == "org-z"
    assert row["plan_name"] == "enterprise"
    assert row["used_units"] == "9999"


def test_subscriptions_csv_empty_produces_headers_only() -> None:
    svc = _build_service(subs=[])
    payload, _ = svc.export(report_type="subscriptions", fmt="csv")
    headers, rows = _parse_csv(payload)
    assert "subscription_id" in headers
    assert rows == []


def test_subscriptions_csv_multiple_orgs() -> None:
    subs = [
        _make_subscription(org_id="org-1"),
        _make_subscription(org_id="org-2"),
        _make_subscription(org_id="org-3"),
    ]
    svc = _build_service(subs=subs)
    payload, _ = svc.export(report_type="subscriptions", fmt="csv")
    _, rows = _parse_csv(payload)
    assert len(rows) == 3
    org_ids = {r["org_id"] for r in rows}
    assert org_ids == {"org-1", "org-2", "org-3"}


def test_subscriptions_csv_included_units_reflects_plan_tier() -> None:
    """Verify that included_units in the CSV output matches the plan tier written in."""
    sub_free = _make_subscription(org_id="org-free", plan_name="free", included_units=5_000)
    sub_pro = _make_subscription(org_id="org-pro", plan_name="pro", included_units=25_000)
    sub_ent = _make_subscription(org_id="org-ent", plan_name="enterprise", included_units=60_000)
    svc = _build_service(subs=[sub_free, sub_pro, sub_ent])
    payload, _ = svc.export(report_type="subscriptions", fmt="csv")
    _, rows = _parse_csv(payload)
    by_org = {r["org_id"]: r for r in rows}
    assert by_org["org-free"]["included_units"] == "5000"
    assert by_org["org-pro"]["included_units"] == "25000"
    assert by_org["org-ent"]["included_units"] == "60000"


# ---------------------------------------------------------------------------
# CSV — audit_log
# ---------------------------------------------------------------------------


def test_audit_log_csv_with_records() -> None:
    records = [_make_audit_record(), _make_audit_record(actor="admin")]
    svc = _build_service(audit_records=records)
    payload, ct = svc.export(report_type="audit_log", fmt="csv")
    assert ct == "text/csv; charset=utf-8"
    _, rows = _parse_csv(payload)
    assert len(rows) == 2


def test_audit_log_csv_fallback_when_list_entries_unavailable() -> None:
    svc = _build_service(audit_records=None)
    payload, ct = svc.export(report_type="audit_log", fmt="csv")
    assert ct == "text/csv; charset=utf-8"
    assert b"timestamp" in payload


def test_audit_log_csv_empty_records_returns_default_headers() -> None:
    svc = _build_service(audit_records=[])
    payload, _ = svc.export(report_type="audit_log", fmt="csv")
    assert b"timestamp" in payload


# ---------------------------------------------------------------------------
# CSV — usage_summary
# ---------------------------------------------------------------------------


def test_usage_summary_csv_headers() -> None:
    subs = [_make_subscription()]
    events = [
        _make_meter_event(event_type="scan", quantity=200),
        _make_meter_event(event_type="guard_request", quantity=50),
    ]
    svc = _build_service(subs=subs, events=events)
    payload, ct = svc.export(report_type="usage_summary", fmt="csv")
    headers, _ = _parse_csv(payload)
    assert ct == "text/csv; charset=utf-8"
    for col in ["org_id", "plan_name", "status", "included_units", "used_units", "scans", "guard_requests"]:
        assert col in headers


def test_usage_summary_csv_aggregates_event_totals() -> None:
    subs = [_make_subscription(org_id="org-agg")]
    events = [
        _make_meter_event(org_id="org-agg", event_type="scan", quantity=100),
        _make_meter_event(org_id="org-agg", event_type="scan", quantity=50),
        _make_meter_event(org_id="org-agg", event_type="guard_request", quantity=30),
    ]
    svc = _build_service(subs=subs, events=events)
    payload, _ = svc.export(report_type="usage_summary", fmt="csv")
    _, rows = _parse_csv(payload)
    assert len(rows) == 1
    row = rows[0]
    assert row["scans"] == "150"
    assert row["guard_requests"] == "30"
    assert row["executions"] == "0"


def test_usage_summary_csv_cross_org_isolation() -> None:
    subs = [
        _make_subscription(org_id="org-x"),
        _make_subscription(org_id="org-y"),
    ]
    events = [
        _make_meter_event(org_id="org-x", event_type="scan", quantity=500),
        _make_meter_event(org_id="org-y", event_type="scan", quantity=200),
    ]
    svc = _build_service(subs=subs, events=events)
    payload, _ = svc.export(report_type="usage_summary", fmt="csv")
    _, rows = _parse_csv(payload)
    by_org = {r["org_id"]: r for r in rows}
    assert by_org["org-x"]["scans"] == "500"
    assert by_org["org-y"]["scans"] == "200"


def test_usage_summary_csv_contains_report_generated_at() -> None:
    subs = [_make_subscription()]
    svc = _build_service(subs=subs, events=[])
    payload, _ = svc.export(report_type="usage_summary", fmt="csv")
    headers, rows = _parse_csv(payload)
    assert "report_generated_at" in headers
    assert rows[0]["report_generated_at"] != ""


def test_usage_summary_all_meter_event_types_present() -> None:
    """Verify all five MeterEventType values appear as columns in usage_summary."""
    subs = [_make_subscription(org_id="org-all")]
    events = [
        _make_meter_event(org_id="org-all", event_type="scan", quantity=10),
        _make_meter_event(org_id="org-all", event_type="guard_request", quantity=5),
        _make_meter_event(org_id="org-all", event_type="execution", quantity=3),
        _make_meter_event(org_id="org-all", event_type="incident", quantity=1),
        _make_meter_event(org_id="org-all", event_type="quarantine", quantity=2),
    ]
    svc = _build_service(subs=subs, events=events)
    payload, _ = svc.export(report_type="usage_summary", fmt="csv")
    _, rows = _parse_csv(payload)
    row = rows[0]
    assert row["scans"] == "10"
    assert row["guard_requests"] == "5"
    assert row["executions"] == "3"
    assert row["incidents"] == "1"
    assert row["quarantines"] == "2"


# ---------------------------------------------------------------------------
# Temporal filtering — since / until
# ---------------------------------------------------------------------------


def test_meter_events_filtered_by_since() -> None:
    now = datetime.now(UTC)
    old = _make_meter_event(occurred_at=now - timedelta(days=10))
    recent = _make_meter_event(occurred_at=now - timedelta(hours=1))
    svc = _build_service(events=[old, recent])
    svc._meter_store.list_meter_events.return_value = [old, recent]
    payload, _ = svc.export(
        report_type="meter_events",
        fmt="csv",
        since=now - timedelta(days=1),
    )
    _, rows = _parse_csv(payload)
    assert len(rows) == 1
    assert rows[0]["event_id"] == recent.event_id


def test_meter_events_filtered_by_until() -> None:
    now = datetime.now(UTC)
    old = _make_meter_event(org_id="org-old", event_type="scan", quantity=1, occurred_at=now - timedelta(days=5))
    future = _make_meter_event(org_id="org-future", event_type="scan", quantity=1, occurred_at=now + timedelta(days=5))
    svc = _build_service(events=[old, future])
    svc._meter_store.list_meter_events.return_value = [old, future]
    payload, _ = svc.export(
        report_type="meter_events",
        fmt="csv",
        until=now,
    )
    _, rows = _parse_csv(payload)
    assert all(r["org_id"] == "org-old" for r in rows)


def test_meter_events_since_and_until_window() -> None:
    now = datetime.now(UTC)
    in_window = _make_meter_event(occurred_at=now - timedelta(hours=12))
    before_window = _make_meter_event(
        org_id="org-before",
        event_type="scan",
        quantity=1,
        occurred_at=now - timedelta(days=3),
    )
    after_window = _make_meter_event(
        org_id="org-after",
        event_type="scan",
        quantity=1,
        occurred_at=now + timedelta(hours=1),
    )
    svc = _build_service(events=[in_window, before_window, after_window])
    svc._meter_store.list_meter_events.return_value = [in_window, before_window, after_window]
    payload, _ = svc.export(
        report_type="meter_events",
        fmt="csv",
        since=now - timedelta(days=1),
        until=now,
    )
    _, rows = _parse_csv(payload)
    assert len(rows) == 1
    assert rows[0]["event_id"] == in_window.event_id


def test_audit_log_filtered_by_since() -> None:
    now = datetime.now(UTC)
    old_ts = (now - timedelta(days=10)).isoformat().replace("+00:00", "Z")
    recent_ts = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    old_rec = _make_audit_record(timestamp=old_ts)
    recent_rec = _make_audit_record(timestamp=recent_ts)
    svc = _build_service(audit_records=[old_rec, recent_rec])
    payload, _ = svc.export(
        report_type="audit_log",
        fmt="csv",
        since=now - timedelta(days=1),
    )
    _, rows = _parse_csv(payload)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# org_id passthrough
# ---------------------------------------------------------------------------


def test_meter_events_passes_org_id_to_store() -> None:
    svc = _build_service(events=[])
    svc.export(report_type="meter_events", fmt="csv", org_id="org-filter")
    svc._meter_store.list_meter_events.assert_called_once_with(org_id="org-filter")


def test_subscriptions_passes_org_id_to_store() -> None:
    svc = _build_service(subs=[])
    svc.export(report_type="subscriptions", fmt="csv", org_id="org-filter")
    svc._meter_store.list_subscriptions.assert_called_once_with(org_id="org-filter")


def test_usage_summary_passes_org_id_to_both_store_calls() -> None:
    svc = _build_service(subs=[], events=[])
    svc.export(report_type="usage_summary", fmt="csv", org_id="org-filter")
    svc._meter_store.list_subscriptions.assert_called_once_with(org_id="org-filter")
    svc._meter_store.list_meter_events.assert_called_once_with(org_id="org-filter")


# ---------------------------------------------------------------------------
# PDF — format guard
# ---------------------------------------------------------------------------


def test_pdf_export_raises_runtime_error_when_reportlab_missing() -> None:
    svc = _build_service(events=[_make_meter_event()])
    with patch("app.services.report_export._PDF_AVAILABLE", False):
        with pytest.raises(RuntimeError, match="reportlab"):
            svc.export(report_type="meter_events", fmt="pdf")


def test_reportlab_declared_as_optional_pdf_dependency() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    optional = data["project"]["optional-dependencies"]

    assert any(item.startswith("reportlab") for item in optional["pdf"])
    assert any(item.startswith("reportlab") for item in optional["dev"])
    assert any(item.startswith("reportlab") for item in optional["all"])


def test_pdf_available_reflects_module_flag() -> None:
    svc = _build_service()
    import app.services.report_export as mod

    assert svc.pdf_available() == mod._PDF_AVAILABLE


def test_optional_pdf_import_guard_is_defined() -> None:
    import app.services.report_export as mod

    assert isinstance(mod._PDF_AVAILABLE, bool)
    assert mod._PDF_IMPORT_ERROR is None or isinstance(mod._PDF_IMPORT_ERROR, str)


# ---------------------------------------------------------------------------
# Invalid inputs
# ---------------------------------------------------------------------------


def test_export_raises_on_unsupported_format() -> None:
    svc = _build_service()
    with pytest.raises(ValueError, match="Unsupported export format"):
        svc.export(report_type="meter_events", fmt="xml")  # type: ignore[arg-type]


def test_export_raises_on_unsupported_report_type_csv() -> None:
    svc = _build_service()
    with pytest.raises(ValueError, match="Unsupported report_type"):
        svc.export(report_type="unknown_report", fmt="csv")  # type: ignore[arg-type]


def test_export_raises_on_unsupported_report_type_pdf() -> None:
    svc = _build_service()
    with patch("app.services.report_export._PDF_AVAILABLE", True):
        with pytest.raises(ValueError, match="Unsupported report_type"):
            svc.export(report_type="unknown_report", fmt="pdf")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _parse_ts helper
# ---------------------------------------------------------------------------


def test_parse_ts_isoformat_z_suffix() -> None:
    result = _parse_ts("2026-05-01T10:00:00Z")
    assert result.tzinfo is not None
    assert result.year == 2026
    assert result.month == 5


def test_parse_ts_isoformat_plus_offset() -> None:
    result = _parse_ts("2026-05-01T10:00:00+00:00")
    assert result.tzinfo is not None


def test_parse_ts_datetime_with_tz() -> None:
    dt = datetime(2026, 1, 1, tzinfo=UTC)
    assert _parse_ts(dt) == dt


def test_parse_ts_datetime_without_tz_gets_utc() -> None:
    dt = datetime(2026, 1, 1)
    result = _parse_ts(dt)
    assert result.tzinfo is UTC


def test_parse_ts_empty_string_returns_min() -> None:
    result = _parse_ts("")
    assert result == datetime.min.replace(tzinfo=UTC)


def test_parse_ts_none_returns_min() -> None:
    result = _parse_ts(None)
    assert result == datetime.min.replace(tzinfo=UTC)


def test_parse_ts_invalid_string_returns_min() -> None:
    result = _parse_ts("not-a-date")
    assert result == datetime.min.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


def test_get_report_export_service_returns_same_instance() -> None:
    svc1 = get_report_export_service()
    svc2 = get_report_export_service()
    assert svc1 is svc2


def test_reset_report_export_service_clears_singleton() -> None:
    svc1 = get_report_export_service()
    reset_report_export_service()
    svc2 = get_report_export_service()
    assert svc1 is not svc2


# ---------------------------------------------------------------------------
# Content-type contract
# ---------------------------------------------------------------------------


def test_csv_content_type_all_report_types() -> None:
    svc = _build_service(
        subs=[_make_subscription()],
        events=[_make_meter_event()],
        audit_records=[_make_audit_record()],
    )
    for rtype in ["meter_events", "subscriptions", "audit_log", "usage_summary"]:
        _, ct = svc.export(report_type=rtype, fmt="csv")  # type: ignore[arg-type]
        assert ct == "text/csv; charset=utf-8", f"wrong content-type for {rtype}"


def test_csv_payload_is_non_empty_bytes_for_all_report_types() -> None:
    svc = _build_service(
        subs=[_make_subscription()],
        events=[_make_meter_event()],
        audit_records=[_make_audit_record()],
    )
    for rtype in ["meter_events", "subscriptions", "audit_log", "usage_summary"]:
        payload, _ = svc.export(report_type=rtype, fmt="csv")  # type: ignore[arg-type]
        assert len(payload) > 0, f"empty payload for {rtype}"
