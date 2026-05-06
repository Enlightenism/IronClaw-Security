from __future__ import annotations


from datetime import UTC, datetime
from typing import Any


from app.models.uipages import PageSection, UIPageDefinition



_RUNTIME_OVERVIEW_ITEMS: list[dict[str, Any]] = [
    {
        "label": "Pipeline",
        "value": "Available",
        "tone": "success",
    },
    {
        "label": "Boundary",
        "value": "Active",
        "tone": "success",
    },
    {
        "label": "Review Queue",
        "value": "Enabled",
        "tone": "success",
    },
    {
        "label": "Execution Mode",
        "value": "Dry Run",
        "tone": "neutral",
    },
]


_RISK_THRESHOLD_ITEMS: list[dict[str, Any]] = [
    {
        "range": "0-49",
        "decision": "Allow",
        "detail": "Requests may continue through guarded dry-run execution.",
    },
    {
        "range": "50-89",
        "decision": "Review",
        "detail": "Requests are diverted into review workflow before execution.",
    },
    {
        "range": "90+",
        "decision": "Block",
        "detail": "Requests are halted before executor invocation.",
    },
]


_ACTIVE_EXECUTOR_ITEMS: list[dict[str, Any]] = [
    {
        "label": "Executor Name",
        "value": "dryrunexecutor",
    },
    {
        "label": "Mode",
        "value": "dryrun",
    },
    {
        "label": "Sandbox Required",
        "value": "true",
    },
    {
        "label": "Fallback Executor",
        "value": "dryrunexecutor",
    },
    {
        "label": "Default File Path",
        "value": "app/api/actionexecute.py",
    },
]


_RUNTIME_METRIC_ITEMS: list[dict[str, Any]] = [
    {
        "label": "Total Events",
        "value": 0,
        "tone": "neutral",
    },
    {
        "label": "Allowed",
        "value": 0,
        "tone": "success",
    },
    {
        "label": "Review",
        "value": 0,
        "tone": "warning",
    },
    {
        "label": "Blocked",
        "value": 0,
        "tone": "danger",
    },
    {
        "label": "Quarantined",
        "value": 0,
        "tone": "danger",
    },
    {
        "label": "Latest Event At",
        "value": "Not yet recorded",
        "tone": "neutral",
    },
]


_RUNTIME_NOTE_ITEMS: list[dict[str, str]] = [
    {
        "text": "Guarded execution pipeline is available.",
    },
    {
        "text": "Runtime boundary is enforcing dry-run execution for safe requests.",
    },
    {
        "text": "High-risk actions remain halted before executor invocation.",
    },
    {
        "text": "Runtime metrics block is present and ready for future live wiring.",
    },
]



def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()



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
        allowed = true_values or {"true", "active", "available", "enabled", "yes"}
        return normalized in allowed
    return bool(value)



def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default



def build_runtime_status_page() -> UIPageDefinition:
    return UIPageDefinition(
        pageid="runtime-status",
        title="Runtime Status",
        path="/ui/runtime-status",
        summary="Runtime health, execution boundary posture, active executor mode, and baseline counters.",
        sections=[
            PageSection(
                sectionid="runtime-overview",
                title="Runtime Overview",
                kind="stats",
                description="Current secure runtime availability and guarded execution posture.",
                items=list(_RUNTIME_OVERVIEW_ITEMS),
            ),
            PageSection(
                sectionid="risk-thresholds",
                title="Risk Thresholds",
                kind="table",
                description="Configured risk score bands used by the runtime boundary.",
                items=list(_RISK_THRESHOLD_ITEMS),
            ),
            PageSection(
                sectionid="active-executor",
                title="Active Executor",
                kind="details",
                description="Current runtime executor selection and fallback behavior.",
                items=list(_ACTIVE_EXECUTOR_ITEMS),
            ),
            PageSection(
                sectionid="runtime-metrics",
                title="Runtime Metrics",
                kind="stats",
                description="Baseline counters ready for future live wiring.",
                items=list(_RUNTIME_METRIC_ITEMS),
            ),
            PageSection(
                sectionid="runtime-notes",
                title="Operator Notes",
                kind="list",
                description="Current operating notes for the guarded runtime.",
                items=list(_RUNTIME_NOTE_ITEMS),
            ),
        ],
        metadata={
            "owner": "runtime-status",
            "source": "app/ui/runtimestatus.py",
            "tags": ["runtime", "boundary", "executor", "ui"],
        },
    )



def get_runtime_status_page() -> dict[str, Any]:
    page = build_runtime_status_page()
    section_map = {section.sectionid: section for section in page.sections}

    overview_items = section_map["runtime-overview"].items
    executor_items = section_map["active-executor"].items
    metrics_items = section_map["runtime-metrics"].items

    return {
        "status": "ok",
        "pageid": page.pageid,
        "title": page.title,
        "path": page.path,
        "summary": page.summary,
        "generatedat": _utc_now_iso(),
        "runtimeavailable": _to_bool(_lookup(overview_items, "Pipeline")),
        "boundaryactive": _to_bool(_lookup(overview_items, "Boundary")),
        "reviewqueueenabled": _to_bool(_lookup(overview_items, "Review Queue")),
        "executor": {
            "executorname": str(_lookup(executor_items, "Executor Name", "")),
            "fallbackexecutorname": str(_lookup(executor_items, "Fallback Executor", "")),
            "defaultmode": str(_lookup(executor_items, "Mode", "")),
            "sandboxrequired": _to_bool(
                _lookup(executor_items, "Sandbox Required"),
                true_values={"true", "yes", "required"},
            ),
        },
        "metrics": {
            "totalrequests": _to_int(_lookup(metrics_items, "Total Events", 0)),
            "allowcount": _to_int(_lookup(metrics_items, "Allowed", 0)),
            "reviewcount": _to_int(_lookup(metrics_items, "Review", 0)),
            "blockedcount": _to_int(_lookup(metrics_items, "Blocked", 0)),
            "quarantinecount": _to_int(_lookup(metrics_items, "Quarantined", 0)),
            "latesteventat": _lookup(metrics_items, "Latest Event At", "Not yet recorded"),
        },
        "policy": {
            "policymode": "dryrun",
            "defaultaction": "review",
        },
        "defaultfilepath": str(_lookup(executor_items, "Default File Path", "")),
        "metadata": page.metadata,
    }