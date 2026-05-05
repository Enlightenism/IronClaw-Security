from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/quarantine/overview", tags=["quarantine-overview"])


def _metric(
    *,
    id: str,
    label: str,
    value: Any,
    tone: str = "neutral",
    trend: str | None = None,
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "label": label,
        "value": value,
        "tone": tone,
        "trend": trend,
        "help_text": help_text,
    }


def _filter(
    *,
    name: str,
    label: str,
    value: Any | None,
    field_type: str = "text",
    placeholder: str | None = None,
    options: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": field_type,
        "value": value,
        "placeholder": placeholder,
        "options": options or [],
    }


def _column(
    *,
    key: str,
    label: str,
    kind: str = "text",
) -> dict[str, str]:
    return {
        "key": key,
        "label": label,
        "kind": kind,
    }


def _row(
    *,
    quarantine_id: str,
    created_at: str,
    artifact_type: str,
    source: str,
    status: str,
    risk_level: str,
    principal_id: str | None,
    retention_state: str,
) -> dict[str, Any]:
    return {
        "quarantine_id": quarantine_id,
        "created_at": created_at,
        "artifact_type": artifact_type,
        "source": source,
        "status": status,
        "risk_level": risk_level,
        "principal_id": principal_id,
        "retention_state": retention_state,
        "detail_path": f"/quarantine/overview?quarantine_id={quarantine_id}",
    }


def _section(
    *,
    id: str,
    title: str,
    description: str,
    items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "description": description,
        "items": items or [],
    }


def _item(
    *,
    label: str,
    value: Any,
    tone: str = "neutral",
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "label": label,
        "value": value,
        "tone": tone,
        "help_text": help_text,
    }


@router.get("")
def quarantine_overview_page(
    status: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    source: str | None = Query(default=None),
    principal_id: str | None = Query(default=None),
    artifact_type: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    effective_source = source or "sandbox"
    effective_artifact_type = artifact_type or "file"

    filters = [
        _filter(
            name="period",
            label="Period",
            value=period,
            field_type="select",
            options=[
                {"label": "Last 24 hours", "value": "24h"},
                {"label": "Last 7 days", "value": "7d"},
                {"label": "Last 30 days", "value": "30d"},
            ],
        ),
        _filter(
            name="status",
            label="Status",
            value=status,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Queued", "value": "queued"},
                {"label": "Isolated", "value": "isolated"},
                {"label": "Under Review", "value": "under-review"},
                {"label": "Released", "value": "released"},
                {"label": "Deleted", "value": "deleted"},
            ],
        ),
        _filter(
            name="risk_level",
            label="Risk Level",
            value=risk_level,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Low", "value": "low"},
                {"label": "Medium", "value": "medium"},
                {"label": "High", "value": "high"},
                {"label": "Critical", "value": "critical"},
            ],
        ),
        _filter(
            name="source",
            label="Source",
            value=source,
            placeholder="sandbox",
        ),
        _filter(
            name="principal_id",
            label="Principal ID",
            value=principal_id,
            placeholder="cust_123",
        ),
        _filter(
            name="artifact_type",
            label="Artifact Type",
            value=artifact_type,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "File", "value": "file"},
                {"label": "Prompt", "value": "prompt"},
                {"label": "Download", "value": "download"},
                {"label": "Execution Output", "value": "execution-output"},
            ],
        ),
    ]

    metrics = [
        _metric(
            id="quarantined_items",
            label="Quarantined Items",
            value=12,
            tone="warning",
            trend="+2",
            help_text="Artifacts currently held in quarantine or recently processed.",
        ),
        _metric(
            id="high_risk_items",
            label="High Risk Items",
            value=4,
            tone="warning",
            trend="+1",
            help_text="Artifacts assessed as high or critical risk.",
        ),
        _metric(
            id="released_items",
            label="Released Items",
            value=5,
            tone="positive",
            trend="+1",
            help_text="Quarantined artifacts that were reviewed and safely released.",
        ),
        _metric(
            id="mean_hold_minutes",
            label="Mean Hold Minutes",
            value=41,
            tone="neutral",
            trend="-6",
            help_text="Average time an item remains in quarantine before disposition.",
        ),
    ]

    sections = [
        _section(
            id="quarantine-posture",
            title="Quarantine Posture",
            description="High-level state of isolation and containment workflows.",
            items=[
                _item(
                    label="Primary Source",
                    value=effective_source,
                    tone="neutral",
                    help_text="Main subsystem sending items into quarantine.",
                ),
                _item(
                    label="Default Artifact Type",
                    value=effective_artifact_type,
                    tone="neutral",
                    help_text="Current artifact type emphasized in this overview.",
                ),
                _item(
                    label="Isolation Enforcement",
                    value="active",
                    tone="positive",
                    help_text="Suspicious artifacts are isolated from normal execution paths.",
                ),
                _item(
                    label="Disposition Workflow",
                    value="available",
                    tone="positive",
                    help_text="Operators can review, release, or retain items based on risk.",
                ),
            ],
        ),
        _section(
            id="review-guidance",
            title="Review Guidance",
            description="Suggested checks for safe handling of quarantined artifacts.",
            items=[
                _item(
                    label="Inspect Related Incident",
                    value="recommended",
                    tone="neutral",
                    help_text="Cross-check whether the item is linked to an active incident or triage queue.",
                ),
                _item(
                    label="Review Guard Verdict",
                    value="recommended",
                    tone="neutral",
                    help_text="Confirm the risk decision, mode, and sandbox lane before release.",
                ),
                _item(
                    label="Verify Audit Trail",
                    value="recommended",
                    tone="neutral",
                    help_text="Inspect actor and system actions associated with the quarantined artifact.",
                ),
                _item(
                    label="Escalate Critical Items",
                    value="required",
                    tone="warning",
                    help_text="Critical-risk artifacts should remain isolated until reviewed thoroughly.",
                ),
            ],
        ),
    ]

    columns = [
        _column(key="created_at", label="Created At"),
        _column(key="quarantine_id", label="Quarantine ID"),
        _column(key="artifact_type", label="Artifact Type"),
        _column(key="source", label="Source"),
        _column(key="status", label="Status"),
        _column(key="risk_level", label="Risk Level"),
        _column(key="principal_id", label="Principal ID"),
        _column(key="retention_state", label="Retention State"),
        _column(key="detail_path", label="Detail Path", kind="link"),
    ]

    rows = [
        _row(
            quarantine_id="q_001",
            created_at="2026-04-23T18:24:00Z",
            artifact_type=artifact_type or "file",
            source=source or "sandbox",
            status=status or "isolated",
            risk_level=risk_level or "high",
            principal_id=principal_id or "cust_demo_001",
            retention_state="retained",
        ),
        _row(
            quarantine_id="q_002",
            created_at="2026-04-23T18:31:00Z",
            artifact_type=artifact_type or "download",
            source=source or "download-analyzer",
            status=status or "under-review",
            risk_level=risk_level or "critical",
            principal_id=principal_id or "cust_demo_001",
            retention_state="retained",
        ),
        _row(
            quarantine_id="q_003",
            created_at="2026-04-23T18:39:00Z",
            artifact_type=artifact_type or "execution-output",
            source=source or "file-return-guard",
            status=status or "released",
            risk_level=risk_level or "medium",
            principal_id=principal_id or "cust_demo_001",
            retention_state="scheduled-delete",
        ),
    ]

    return {
        "page": "quarantine-overview",
        "title": "Quarantine Overview",
        "summary": "Review isolated artifacts, containment state, and disposition workflow pivots.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "table": {
            "title": "Quarantined Artifacts",
            "columns": columns,
            "rows": rows,
            "empty_state": {
                "title": "No quarantined items found",
                "description": "Adjust your filters or widen the reporting period to inspect more isolated artifacts.",
            },
        },
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh quarantine overview",
                "method": "GET",
                "path": "/quarantine/overview",
                "query": {
                    "status": status,
                    "risk_level": risk_level,
                    "source": source,
                    "principal_id": principal_id,
                    "artifact_type": artifact_type,
                    "period": period,
                },
                "description": "Reload quarantine results using the active filters.",
            },
            {
                "id": "open-incident-triage",
                "title": "Open incident triage",
                "method": "GET",
                "path": "/ui/uiincidenttriage",
                "query": {
                    "period": period,
                    "principal_id": principal_id,
                },
                "description": "Compare quarantined artifacts with active incident investigation workflows.",
            },
            {
                "id": "open-review-queue",
                "title": "Open review queue",
                "method": "GET",
                "path": "/ui/review",
                "query": {
                    "period": period,
                    "principal_id": principal_id,
                },
                "description": "Pivot into human review decisions associated with quarantined items.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Inspect related actor and system actions around quarantine events.",
            },
        ],
    }