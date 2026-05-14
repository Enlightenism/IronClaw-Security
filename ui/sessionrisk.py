from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/sessionrisk", tags=["ui-session-risk"])


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


def _event(
    *,
    event_id: str,
    timestamp: str,
    category: str,
    verdict: str,
    score: float,
    source: str,
    detail_path: str,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "category": category,
        "verdict": verdict,
        "score": score,
        "source": source,
        "detail_path": detail_path,
    }


@router.get("")
def ui_session_risk_page(
    session_id: str | None = Query(default=None),
    principal_id: str | None = Query(default=None),
    source: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    effective_session_id = session_id or "sess_demo_001"
    effective_principal_id = principal_id or "cust_demo_001"
    effective_source = source or "ui-console"

    filters = [
        _filter(
            name="session_id",
            label="Session ID",
            value=session_id,
            placeholder="sess_123",
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
            field_type="select",
            options=[
                {"label": "Any", "value": ""},
                {"label": "UI Console", "value": "ui-console"},
                {"label": "API", "value": "api"},
                {"label": "CLI", "value": "cli"},
                {"label": "Customer Portal", "value": "customer-portal"},
                {"label": "Integration", "value": "integration"},
            ],
        ),
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
    ]

    metrics = [
        _metric(
            id="session_risk_score",
            label="Session Risk Score",
            value=78,
            tone="warning",
            trend="+6",
            help_text="Aggregate session risk score based on telemetry, guard verdicts, and related activity.",
        ),
        _metric(
            id="risk_events",
            label="Risk Events",
            value=5,
            tone="warning",
            trend="+2",
            help_text="Number of risk-relevant events associated with this session.",
        ),
        _metric(
            id="blocked_actions",
            label="Blocked Actions",
            value=1,
            tone="positive",
            trend="+1",
            help_text="Actions successfully blocked during the selected time window.",
        ),
        _metric(
            id="active_incidents",
            label="Linked Incidents",
            value=1,
            tone="neutral",
            trend="0",
            help_text="Incident records currently linked to this session context.",
        ),
    ]

    sections = [
        _section(
            id="session-identity",
            title="Session Identity",
            description="Core identifiers used to correlate session-level risk and activity.",
            items=[
                _item(
                    label="Session ID",
                    value=effective_session_id,
                    tone="neutral",
                    help_text="Stable session identifier used across request and event flows.",
                ),
                _item(
                    label="Principal ID",
                    value=effective_principal_id,
                    tone="neutral",
                    help_text="Primary principal associated with the session.",
                ),
                _item(
                    label="Source",
                    value=effective_source,
                    tone="neutral",
                    help_text="Primary request origin associated with this session.",
                ),
                _item(
                    label="Risk Posture",
                    value="elevated",
                    tone="warning",
                    help_text="Current high-level risk state for this session.",
                ),
            ],
        ),
        _section(
            id="risk-signals",
            title="Risk Signals",
            description="Signals that contribute to the current session risk posture.",
            items=[
                _item(
                    label="Prompt Injection Indicators",
                    value="present",
                    tone="warning",
                    help_text="The session shows indicators of prompt abuse or manipulation attempts.",
                ),
                _item(
                    label="Guard Verdict Escalation",
                    value="observed",
                    tone="warning",
                    help_text="At least one request in the session escalated from allow to warn or block behavior.",
                ),
                _item(
                    label="History Correlation",
                    value="enabled",
                    tone="positive",
                    help_text="Session history is available for deeper decision context and operator review.",
                ),
                _item(
                    label="Containment Availability",
                    value="ready",
                    tone="positive",
                    help_text="Related activity can be escalated into review, quarantine, or incident workflows.",
                ),
            ],
        ),
        _section(
            id="operator-guidance",
            title="Operator Guidance",
            description="Suggested next checks when a session shows elevated risk behavior.",
            items=[
                _item(
                    label="Open Request Context",
                    value="recommended",
                    tone="neutral",
                    help_text="Inspect the request context attached to recent session activity.",
                ),
                _item(
                    label="Review Usage Events",
                    value="recommended",
                    tone="neutral",
                    help_text="Check metered and telemetry-linked events for repeated suspicious patterns.",
                ),
                _item(
                    label="Inspect Audit Trail",
                    value="recommended",
                    tone="neutral",
                    help_text="Correlate operator and system actions affecting the session.",
                ),
                _item(
                    label="Escalate High Confidence Abuse",
                    value="required",
                    tone="warning",
                    help_text="Sessions with persistent high-risk behavior should be escalated quickly.",
                ),
            ],
        ),
    ]

    recent_events = [
        _event(
            event_id="evt_101",
            timestamp="2026-04-23T19:00:00Z",
            category="prompt-injection",
            verdict="warn",
            score=82,
            source=effective_source,
            detail_path="/ui/usageevents/evt_101/detail",
        ),
        _event(
            event_id="evt_102",
            timestamp="2026-04-23T19:04:00Z",
            category="request-anomaly",
            verdict="allow",
            score=61,
            source=effective_source,
            detail_path="/ui/usageevents/evt_102/detail",
        ),
        _event(
            event_id="evt_103",
            timestamp="2026-04-23T19:08:00Z",
            category="policy-escalation",
            verdict="block",
            score=91,
            source=effective_source,
            detail_path="/ui/usageevents/evt_103/detail",
        ),
    ]

    event_columns = [
        {"key": "timestamp", "label": "Timestamp", "kind": "text"},
        {"key": "event_id", "label": "Event ID", "kind": "text"},
        {"key": "category", "label": "Category", "kind": "text"},
        {"key": "verdict", "label": "Verdict", "kind": "text"},
        {"key": "score", "label": "Score", "kind": "number"},
        {"key": "source", "label": "Source", "kind": "text"},
        {"key": "detail_path", "label": "Detail Path", "kind": "link"},
    ]

    return {
        "page": "ui-session-risk",
        "title": "Session Risk",
        "summary": "Review session-level risk posture, contributing signals, and related event pivots.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "tables": [
            {
                "id": "recent-risk-events",
                "title": "Recent Risk Events",
                "columns": event_columns,
                "rows": recent_events,
                "empty_state": {
                    "title": "No session events found",
                    "description": "Adjust your filters to inspect a different session or wider time range.",
                },
            },
        ],
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh session risk",
                "method": "GET",
                "path": "/ui/sessionrisk",
                "query": {
                    "session_id": session_id,
                    "principal_id": principal_id,
                    "source": source,
                    "period": period,
                },
                "description": "Reload the session risk view using the active filters.",
            },
            {
                "id": "open-request-context",
                "title": "Open request context",
                "method": "GET",
                "path": "/ui/requestcontext",
                "query": {
                    "mode": "enforce",
                    "target_type": "text",
                    "source": effective_source,
                },
                "description": "Inspect request context patterns associated with this session.",
            },
            {
                "id": "open-usage-reports",
                "title": "Open usage reports",
                "method": "GET",
                "path": "/ui/usagereports",
                "query": {
                    "session_id": effective_session_id,
                    "principal_id": effective_principal_id,
                    "period": period,
                },
                "description": "Pivot into usage and telemetry activity for this session.",
            },
            {
                "id": "open-incident-triage",
                "title": "Open incident triage",
                "method": "GET",
                "path": "/ui/uiincidenttriage",
                "query": {
                    "principal_id": effective_principal_id,
                    "period": period,
                },
                "description": "Compare session risk posture with linked incident investigation flows.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Inspect related actor and system actions around the session lifecycle.",
            },
        ],
    }
