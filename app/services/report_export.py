"""Report export helpers.

PDF rendering is intentionally optional: the core CSV export path remains
available without additional packages, while PDF generation requires the
optional `reportlab` dependency. Install it with:

    pip install -e ".[pdf]"

or:

    pip install reportlab
"""

from __future__ import annotations

# pyright: reportMissingImports=false
import csv
from datetime import UTC, datetime
import io
import logging
from typing import Any, Literal

from app.services.audit_store import AuditStore, get_audit_store
from app.services.billing_store import (
    MeterEventRecord,
    SubscriptionMeterStore,
    SubscriptionRecord,
    get_subscription_meter_store,
)

logger = logging.getLogger(__name__)

ExportFormat = Literal["csv", "pdf"]
ReportType = Literal["meter_events", "subscriptions", "audit_log", "usage_summary"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PDF_AVAILABLE = False
_PDF_IMPORT_ERROR: str | None = None
try:
    from reportlab.lib import colors  # type: ignore[import-untyped]
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (  # type: ignore[import-untyped]
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _PDF_AVAILABLE = True
except ImportError as exc:
    _PDF_IMPORT_ERROR = str(exc)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# CSV builders
# ---------------------------------------------------------------------------


def _rows_to_csv(headers: list[str], rows: list[list[Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


def _meter_events_csv(events: list[MeterEventRecord]) -> bytes:
    headers = ["event_id", "org_id", "event_type", "quantity", "occurred_at"]
    rows = [
        [
            e.event_id,
            e.org_id,
            e.event_type,
            e.quantity,
            _iso(e.occurred_at),
        ]
        for e in events
    ]
    return _rows_to_csv(headers, rows)


def _subscriptions_csv(subs: list[SubscriptionRecord]) -> bytes:
    headers = [
        "subscription_id",
        "org_id",
        "plan_name",
        "status",
        "billing_email",
        "period_start",
        "period_end",
        "included_units",
        "used_units",
        "overage_units",
        "price_usd_monthly",
    ]
    rows = [
        [
            s.subscription_id,
            s.org_id,
            s.plan_name,
            s.status,
            s.billing_email,
            _iso(s.period_start),
            _iso(s.period_end),
            s.included_units,
            s.used_units,
            s.overage_units,
            s.price_usd_monthly,
        ]
        for s in subs
    ]
    return _rows_to_csv(headers, rows)


def _audit_log_csv(records: list[dict[str, Any]]) -> bytes:
    if not records:
        return b"timestamp,actor,action,resource,outcome,detail\n"
    all_keys: list[str] = list(records[0].keys())
    rows = [[str(r.get(k, "")) for k in all_keys] for r in records]
    return _rows_to_csv(all_keys, rows)


def _usage_summary_csv(
    subs: list[SubscriptionRecord],
    events: list[MeterEventRecord],
) -> bytes:
    # Aggregate events per org per event_type
    totals: dict[tuple[str, str], int] = {}
    for e in events:
        key = (e.org_id, e.event_type)
        totals[key] = totals.get(key, 0) + e.quantity

    headers = [
        "org_id",
        "plan_name",
        "status",
        "included_units",
        "used_units",
        "overage_units",
        "scans",
        "guard_requests",
        "executions",
        "incidents",
        "quarantines",
        "report_generated_at",
    ]
    now_iso = _iso(_utcnow())
    rows = []
    for s in subs:
        rows.append(
            [
                s.org_id,
                s.plan_name,
                s.status,
                s.included_units,
                s.used_units,
                s.overage_units,
                totals.get((s.org_id, "scan"), 0),
                totals.get((s.org_id, "guard_request"), 0),
                totals.get((s.org_id, "execution"), 0),
                totals.get((s.org_id, "incident"), 0),
                totals.get((s.org_id, "quarantine"), 0),
                now_iso,
            ]
        )
    return _rows_to_csv(headers, rows)


# ---------------------------------------------------------------------------
# PDF builders
# ---------------------------------------------------------------------------

_IRONCLAW_PRIMARY = (1, 41, 44)  # dark teal rgb 0-1 floats


def _make_pdf_table_style(header_bg: tuple[float, float, float]) -> TableStyle:
    assert _PDF_AVAILABLE
    r, g, b = header_bg
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.Color(r, g, b)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.96, 0.96)]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.Color(0.75, 0.75, 0.75)),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )


def _build_pdf(
    title: str,
    headers: list[str],
    rows: list[list[Any]],
) -> bytes:
    if not _PDF_AVAILABLE:
        raise RuntimeError('reportlab is not installed for PDF export. Install it with: pip install -e ".[pdf]" or pip install reportlab')

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()
    story: list[Any] = []

    story.append(Paragraph(f"<b>IronClaw Security — {title}</b>", styles["Title"]))
    story.append(
        Paragraph(
            f"Generated: {_iso(_utcnow())}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.4 * cm))

    table_data = [headers] + [[str(c) for c in row] for row in rows]
    col_count = len(headers)
    page_width = landscape(A4)[0] - 3 * cm
    col_width = page_width / max(col_count, 1)

    tbl = Table(table_data, colWidths=[col_width] * col_count, repeatRows=1)
    tbl.setStyle(_make_pdf_table_style(_IRONCLAW_PRIMARY))
    story.append(tbl)

    doc.build(story)
    return buf.getvalue()


def _meter_events_pdf(events: list[MeterEventRecord]) -> bytes:
    headers = ["event_id", "org_id", "event_type", "quantity", "occurred_at"]
    rows = [[e.event_id, e.org_id, e.event_type, e.quantity, _iso(e.occurred_at)] for e in events]
    return _build_pdf("Meter Events Report", headers, rows)


def _subscriptions_pdf(subs: list[SubscriptionRecord]) -> bytes:
    headers = [
        "subscription_id",
        "org_id",
        "plan",
        "status",
        "billing_email",
        "period_start",
        "period_end",
        "included",
        "used",
        "overage",
        "price_usd/mo",
    ]
    rows = [
        [
            s.subscription_id,
            s.org_id,
            s.plan_name,
            s.status,
            s.billing_email,
            _iso(s.period_start),
            _iso(s.period_end),
            s.included_units,
            s.used_units,
            s.overage_units,
            s.price_usd_monthly,
        ]
        for s in subs
    ]
    return _build_pdf("Subscriptions Report", headers, rows)


def _audit_log_pdf(records: list[dict[str, Any]]) -> bytes:
    if not records:
        return _build_pdf("Audit Log Report", ["(no records)"], [])
    all_keys = list(records[0].keys())
    rows = [[str(r.get(k, "")) for k in all_keys] for r in records]
    return _build_pdf("Audit Log Report", all_keys, rows)


def _usage_summary_pdf(
    subs: list[SubscriptionRecord],
    events: list[MeterEventRecord],
) -> bytes:
    totals: dict[tuple[str, str], int] = {}
    for e in events:
        key = (e.org_id, e.event_type)
        totals[key] = totals.get(key, 0) + e.quantity

    headers = [
        "org_id",
        "plan",
        "status",
        "included",
        "used",
        "overage",
        "scans",
        "guard_req",
        "exec",
        "incidents",
        "quarantine",
    ]
    rows = [
        [
            s.org_id,
            s.plan_name,
            s.status,
            s.included_units,
            s.used_units,
            s.overage_units,
            totals.get((s.org_id, "scan"), 0),
            totals.get((s.org_id, "guard_request"), 0),
            totals.get((s.org_id, "execution"), 0),
            totals.get((s.org_id, "incident"), 0),
            totals.get((s.org_id, "quarantine"), 0),
        ]
        for s in subs
    ]
    return _build_pdf("Usage Summary Report", headers, rows)


# ---------------------------------------------------------------------------
# Public export entry point
# ---------------------------------------------------------------------------


class ReportExportService:
    """
    CSV / PDF export for IronClaw usage reports.

    Owns only export rendering — no store mutation, no route handling.
    All data reads go through injected store instances.
    """

    def __init__(
        self,
        subscription_meter_store: SubscriptionMeterStore | None = None,
        audit_store: AuditStore | None = None,
    ) -> None:
        self._meter_store: SubscriptionMeterStore = subscription_meter_store or get_subscription_meter_store()
        self._audit_store: AuditStore = audit_store or get_audit_store()

    # ------------------------------------------------------------------
    # Core export dispatcher
    # ------------------------------------------------------------------

    def export(
        self,
        *,
        report_type: ReportType,
        fmt: ExportFormat,
        org_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> tuple[bytes, str]:
        """
        Returns (payload_bytes, content_type).

        content_type is one of:
            "text/csv; charset=utf-8"
            "application/pdf"
        """
        logger.info(
            "report_export.export report_type=%s fmt=%s org_id=%s since=%s until=%s",
            report_type,
            fmt,
            org_id,
            since,
            until,
        )

        if fmt == "csv":
            payload = self._build_csv(
                report_type=report_type,
                org_id=org_id,
                since=since,
                until=until,
            )
            return payload, "text/csv; charset=utf-8"

        if fmt == "pdf":
            payload = self._build_pdf_report(
                report_type=report_type,
                org_id=org_id,
                since=since,
                until=until,
            )
            return payload, "application/pdf"

        raise ValueError(f"Unsupported export format: {fmt!r}")

    # ------------------------------------------------------------------
    # CSV dispatch
    # ------------------------------------------------------------------

    def _build_csv(
        self,
        *,
        report_type: ReportType,
        org_id: str | None,
        since: datetime | None,
        until: datetime | None,
    ) -> bytes:
        if report_type == "meter_events":
            events = self._filtered_events(org_id=org_id, since=since, until=until)
            return _meter_events_csv(events)

        if report_type == "subscriptions":
            subs = self._meter_store.list_subscriptions(org_id=org_id)
            return _subscriptions_csv(subs)

        if report_type == "audit_log":
            records = self._filtered_audit(since=since, until=until)
            return _audit_log_csv(records)

        if report_type == "usage_summary":
            subs = self._meter_store.list_subscriptions(org_id=org_id)
            events = self._filtered_events(org_id=org_id, since=since, until=until)
            return _usage_summary_csv(subs, events)

        raise ValueError(f"Unsupported report_type: {report_type!r}")

    # ------------------------------------------------------------------
    # PDF dispatch
    # ------------------------------------------------------------------

    def _build_pdf_report(
        self,
        *,
        report_type: ReportType,
        org_id: str | None,
        since: datetime | None,
        until: datetime | None,
    ) -> bytes:
        if report_type == "meter_events":
            events = self._filtered_events(org_id=org_id, since=since, until=until)
            return _meter_events_pdf(events)

        if report_type == "subscriptions":
            subs = self._meter_store.list_subscriptions(org_id=org_id)
            return _subscriptions_pdf(subs)

        if report_type == "audit_log":
            records = self._filtered_audit(since=since, until=until)
            return _audit_log_pdf(records)

        if report_type == "usage_summary":
            subs = self._meter_store.list_subscriptions(org_id=org_id)
            events = self._filtered_events(org_id=org_id, since=since, until=until)
            return _usage_summary_pdf(subs, events)

        raise ValueError(f"Unsupported report_type: {report_type!r}")

    # ------------------------------------------------------------------
    # Filtered data helpers
    # ------------------------------------------------------------------

    def _filtered_events(
        self,
        *,
        org_id: str | None,
        since: datetime | None,
        until: datetime | None,
    ) -> list[MeterEventRecord]:
        events = self._meter_store.list_meter_events(org_id=org_id)
        if since is not None:
            events = [e for e in events if e.occurred_at >= since]
        if until is not None:
            events = [e for e in events if e.occurred_at <= until]
        return events

    def _filtered_audit(
        self,
        *,
        since: datetime | None,
        until: datetime | None,
    ) -> list[dict[str, Any]]:
        try:
            all_records: list[dict[str, Any]] = self._audit_store.list_entries()
        except Exception:
            logger.warning("audit_store.list_entries unavailable during export", exc_info=True)
            all_records = []

        if since is not None:
            all_records = [r for r in all_records if _parse_ts(r.get("timestamp") or r.get("occurred_at") or "") >= since]
        if until is not None:
            all_records = [r for r in all_records if _parse_ts(r.get("timestamp") or r.get("occurred_at") or "") <= until]
        return all_records

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def pdf_available(self) -> bool:
        return _PDF_AVAILABLE

    def supported_formats(self) -> list[str]:
        fmts = ["csv"]
        if _PDF_AVAILABLE:
            fmts.append("pdf")
        return fmts

    def supported_report_types(self) -> list[str]:
        return ["meter_events", "subscriptions", "audit_log", "usage_summary"]


# ---------------------------------------------------------------------------
# Timestamp parsing helper
# ---------------------------------------------------------------------------


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_REPORT_EXPORT_SERVICE: ReportExportService | None = None


def get_report_export_service() -> ReportExportService:
    global _REPORT_EXPORT_SERVICE
    if _REPORT_EXPORT_SERVICE is None:
        _REPORT_EXPORT_SERVICE = ReportExportService()
    return _REPORT_EXPORT_SERVICE


def reset_report_export_service() -> None:
    global _REPORT_EXPORT_SERVICE
    _REPORT_EXPORT_SERVICE = None
