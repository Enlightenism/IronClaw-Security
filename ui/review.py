from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/review", tags=["ui-review"])


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
    review_id: str,
    created_at: str,
    queue: str,
    category: str,
    severity: str,
    status: str,
    principal_id: str | None,
    source: str,
    score: int | float | None,
) -> dict[str, Any]:
    return {
        "review_id": review_id,
        "created_at": created_at,
        "queue": queue,
        "category": category,
        "severity": severity,
        "status": status,
        "principal_id": principal_id,
        "source": source,
        "score": score,
        "detail_path": f"/reviews/detail?review_id={review_id}",
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
def ui_review_page(
    queue: str | None = Query(default=None),
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    principal_id: str | None = Query(default=None),
    source: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    effective_queue = queue or "human-review"
    effective_source = source or "promptguard"

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
            name="queue",
            label="Queue",
            value=queue,
            placeholder="human-review",
        ),
        _filter(
            name="category",
            label="Category",
            value=category,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Prompt Injection", "value": "prompt-injection"},
                {"label": "Policy Override", "value": "policy-override"},
                {"label": "Execution Risk", "value": "execution-risk"},
                {"label": "Customer Key Risk", "value": "customer-key-risk"},
            ],
        ),
        _filter(
            name="severity",
            label="Severity",
            value=severity,
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
            name="status",
            label="Status",
            value=status,
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "Pending", "value": "pending"},
                {"label": "In Review", "value": "in-review"},
                {"label": "Approved", "value": "approved"},
                {"label": "Rejected", "value": "rejected"},
                {"label": "Escalated", "value": "escalated"},
            ],
        ),
        _filter(
            name="principal_id",
            label="Principal ID",
            value=principal_id,
            placeholder="cust_123",
        ),
        _filter(
            name="source",
            label="Source",
            value=source,
            placeholder="promptguard",
        ),
    ]

    metrics = [
        _metric(
            id="pending_reviews",
            label="Pending Reviews",
            value=9,
            tone="warning",
            trend="+2",
            help_text="Review items waiting for analyst or operator action.",
        ),
        _metric(
            id="high_risk_reviews",
            label="High Risk Reviews",
            value=3,
            tone="warning",
            trend="+1",
            help_text="Reviews associated with high-confidence or high-impact signals.",
        ),
        _metric(
            id="resolved_reviews",
            label="Resolved Reviews",
            value=14,
            tone="positive",
            trend="+5",
            help_text="Items that reached a terminal review outcome within the selected period.",
        ),
        _metric(
            id="mean_review_minutes",
            label="Mean Review Minutes",
            value=26,
            tone="neutral",
            trend="-3",
            help_text="Average elapsed time from queueing to first human decision.",
        ),
    ]

    sections = [
        _section(
            id="queue-posture",
            title="Queue Posture",
            description="High-level operating state of the human review workflow.",
            items=[
                _item(
                    label="Active Queue",
                    value=effective_queue,
                    tone="neutral",
                    help_text="The queue currently being reviewed by the UI.",
                ),
                _item(
                    label="Primary Source",
                    value=effective_source,
                    tone="neutral",
                    help_text="Primary subsystem feeding items into the review queue.",
                ),
                _item(
                    label="Escalation Available",
                    value="yes",
                    tone="positive",
                    help_text="Review items can be escalated into incident, quarantine, or policy workflows.",
                ),
                _item(
                    label="Disposition Tracking",
                    value="enabled",
                    tone="positive",
                    help_text="Human decisions and follow-up states are expected to be tracked.",
                ),
            ],
        ),
        _section(
            id="review-guidance",
            title="Review Guidance",
            description="Suggested checks for consistent handling of queued review items.",
            items=[
                _item(
                    label="Check Request Context",
                    value="recommended",
                    tone="neutral",
                    help_text="Inspect session, request, and principal context before disposition.",
                ),
                _item(
                    label="Inspect Audit Trail",
                    value="recommended",
                    tone="neutral",
                    help_text="Review nearby audit events to understand actor behavior and timing.",
                ),
                _item(
                    label="Compare Usage Signals",
                    value="recommended",
                    tone="neutral",
                    help_text="Cross-check telemetry and usage patterns before approving risky activity.",
                ),
                _item(
                    label="Escalate Critical Findings",
                    value="required",
                    tone="warning",
                    help_text="Critical reviews should be moved into higher-severity response workflows quickly.",
                ),
            ],
        ),
    ]

    columns = [
        _column(key="created_at", label="Created At"),
        _column(key="review_id", label="Review ID"),
        _column(key="queue", label="Queue"),
        _column(key="category", label="Category"),
        _column(key="severity", label="Severity"),
        _column(key="status", label="Status"),
        _column(key="principal_id", label="Principal ID"),
        _column(key="source", label="Source"),
        _column(key="score", label="Score", kind="number"),
        _column(key="detail_path", label="Detail Path", kind="link"),
    ]

    rows = [
        _row(
            review_id="rev_001",
            created_at="2026-04-23T18:20:00Z",
            queue=effective_queue,
            category=category or "prompt-injection",
            severity=severity or "high",
            status=status or "pending",
            principal_id=principal_id or "cust_demo_001",
            source=source or "promptguard",
            score=92,
        ),
        _row(
            review_id="rev_002",
            created_at="2026-04-23T18:27:00Z",
            queue=effective_queue,
            category=category or "policy-override",
            severity=severity or "medium",
            status=status or "in-review",
            principal_id=principal_id or "cust_demo_001",
            source=source or "policy",
            score=71,
        ),
        _row(
            review_id="rev_003",
            created_at="2026-04-23T18:35:00Z",
            queue=effective_queue,
            category=category or "customer-key-risk",
            severity=severity or "critical",
            status=status or "escalated",
            principal_id=principal_id or "cust_demo_001",
            source=source or "customerkeys",
            score=97,
        ),
    ]

    return {
        "page": "ui-review",
        "title": "Review Queue",
        "summary": "Inspect queued review items, human triage posture, and workflow pivots for security decisions.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "table": {
            "title": "Queued Review Items",
            "columns": columns,
            "rows": rows,
            "empty_state": {
                "title": "No review items found",
                "description": "Adjust your filters or widen the reporting period to inspect more queued items.",
            },
        },
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh review queue",
                "method": "GET",
                "path": "/ui/review",
                "query": {
                    "queue": queue,
                    "category": category,
                    "severity": severity,
                    "status": status,
                    "principal_id": principal_id,
                    "source": source,
                    "period": period,
                },
                "description": "Reload the review queue using the active filters.",
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
                "description": "Escalate or compare queued reviews with incident triage workflows.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Inspect related actor activity around queued review items.",
            },
            {
                "id": "open-usage-reports",
                "title": "Open usage reports",
                "method": "GET",
                "path": "/ui/usagereports",
                "query": {
                    "period": period,
                    "principal_id": principal_id,
                },
                "description": "Compare human review queue signals with metered usage activity.",
            },
        ],
    }