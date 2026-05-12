from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models.uipages import PageSection, UIPageDefinition


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _build_access_overview_items() -> list[dict[str, Any]]:
    return [
        {"label": "Access Layer", "value": "Available", "tone": "success"},
        {"label": "Audit Visibility", "value": "Enabled", "tone": "success"},
        {"label": "Recent Events Feed", "value": "Ready", "tone": "success"},
        {"label": "Export Posture", "value": "Controlled", "tone": "warning"},
    ]


def _build_access_counts_items() -> list[dict[str, Any]]:
    return [
        {"label": "Total Access Events", "value": 0, "tone": "neutral"},
        {"label": "Allowed Reads", "value": 0, "tone": "success"},
        {"label": "Flagged Reads", "value": 0, "tone": "warning"},
        {"label": "Denied Reads", "value": 0, "tone": "danger"},
        {"label": "Sensitive Exports", "value": 0, "tone": "warning"},
        {"label": "Latest Event At", "value": "Not yet recorded", "tone": "neutral"},
    ]


def _build_control_flags_items() -> list[dict[str, Any]]:
    return [
        {"label": "Telemetry Retention", "value": "Tracked"},
        {"label": "Actor Attribution", "value": "Required"},
        {"label": "Session Correlation", "value": "Enabled"},
        {"label": "Request Correlation", "value": "Enabled"},
        {"label": "Redaction Guard", "value": "Available"},
    ]


def _build_recent_events_items() -> list[dict[str, Any]]:
    return [
        {
            "timestamp": "Pending live wiring",
            "actor": "system",
            "action": "telemetry-access-summary",
            "result": "No events yet",
            "detail": "Recent access events will appear here after telemetry access reads are recorded.",
        }
    ]


def _build_operator_notes_items() -> list[dict[str, str]]:
    return [
        {"text": "Telemetry access summary is prepared for dashboard and audit-facing UI use."},
        {"text": "Counts remain stable-safe defaults until live telemetry access persistence is attached."},
        {"text": "Actor, session, and request correlation should remain first-class in future wiring."},
        {"text": "Avoid duplicate telemetry logic; keep this page as the UI-facing summary layer only."},
    ]


def build_telemetry_access_summary_page() -> UIPageDefinition:
    return UIPageDefinition(
        pageid="telemetry-access-summary",
        title="Telemetry Access Summary",
        path="/ui/telemetry-access-summary",
        summary="Telemetry access posture, baseline counts, audit-facing controls, and recent access activity readiness.",
        sections=[
            PageSection(
                sectionid="access-overview",
                title="Access Overview",
                kind="stats",
                description="Current telemetry access posture for audit visibility and controlled reads.",
                items=_build_access_overview_items(),
            ),
            PageSection(
                sectionid="access-counts",
                title="Access Counts",
                kind="stats",
                description="Baseline telemetry access counters ready for future live wiring.",
                items=_build_access_counts_items(),
            ),
            PageSection(
                sectionid="control-flags",
                title="Control Flags",
                kind="details",
                description="Current control expectations for telemetry access attribution and handling.",
                items=_build_control_flags_items(),
            ),
            PageSection(
                sectionid="recent-events",
                title="Recent Events",
                kind="table",
                description="Most recent telemetry access activity prepared for audit-facing display.",
                items=_build_recent_events_items(),
            ),
            PageSection(
                sectionid="operator-notes",
                title="Operator Notes",
                kind="list",
                description="Current operating notes for telemetry access visibility.",
                items=_build_operator_notes_items(),
            ),
        ],
        metadata={
            "owner": "telemetry-access-summary",
            "source": "app/ui/telemetryaccesssummary.py",
            "tags": ["telemetry", "access", "audit", "ui"],
        },
    )


def _lookup(items: list[dict[str, Any]], label: str, default: Any = None) -> Any:
    for item in items:
        if item.get("label") == label:
            return item.get("value", default)
    return default


def _to_bool(value: Any, *, true_values: set[str] | None = None) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        allowed = true_values or {"true", "active", "available", "enabled", "ready", "required", "yes", "tracked"}
        return normalized in allowed
    return bool(value)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_telemetry_access_summary_page() -> dict[str, Any]:
    page = build_telemetry_access_summary_page()
    section_map = {section.sectionid: section for section in page.sections}

    overview_items = section_map["access-overview"].items
    counts_items = section_map["access-counts"].items
    control_items = section_map["control-flags"].items
    recent_event_items = section_map["recent-events"].items

    return {
        "pageid": page.pageid,
        "title": page.title,
        "path": page.path,
        "summary": page.summary,
        "generatedat": _utc_now_iso(),
        "accessavailable": _to_bool(_lookup(overview_items, "Access Layer")),
        "auditvisibilityenabled": _to_bool(_lookup(overview_items, "Audit Visibility")),
        "recenteventsready": _to_bool(_lookup(overview_items, "Recent Events Feed")),
        "exportcontrolled": _to_bool(
            _lookup(overview_items, "Export Posture"),
            true_values={"controlled", "restricted", "limited"},
        ),
        "counts": {
            "totalevents": _to_int(_lookup(counts_items, "Total Access Events", 0)),
            "allowedreads": _to_int(_lookup(counts_items, "Allowed Reads", 0)),
            "flaggedreads": _to_int(_lookup(counts_items, "Flagged Reads", 0)),
            "deniedreads": _to_int(_lookup(counts_items, "Denied Reads", 0)),
            "sensitiveexports": _to_int(_lookup(counts_items, "Sensitive Exports", 0)),
            "latesteventat": _lookup(counts_items, "Latest Event At", "Not yet recorded"),
        },
        "controls": {
            "retentiontracked": _to_bool(
                _lookup(control_items, "Telemetry Retention"),
                true_values={"tracked", "enabled", "true", "yes"},
            ),
            "actorattributionrequired": _to_bool(
                _lookup(control_items, "Actor Attribution"),
                true_values={"required", "true", "yes"},
            ),
            "sessioncorrelationenabled": _to_bool(_lookup(control_items, "Session Correlation")),
            "requestcorrelationenabled": _to_bool(_lookup(control_items, "Request Correlation")),
            "redactionguardavailable": _to_bool(_lookup(control_items, "Redaction Guard")),
        },
        "recentevents": recent_event_items,
        "metadata": page.metadata,
    }


# Canonical alias expected by app.api.telemetryaccess
get_telemetry_access_summary = get_telemetry_access_summary_page