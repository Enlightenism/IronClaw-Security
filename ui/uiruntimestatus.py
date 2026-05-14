from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/uiruntimestatus", tags=["ui-runtime-status"])


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


@router.get("")
def ui_runtime_status_page(
    environment: str | None = Query(default=None),
    lane: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    effective_environment = environment or "local"
    effective_lane = lane or "default"

    metrics = [
        _metric(
            id="active_workers",
            label="Active Workers",
            value=6,
            tone="positive",
            trend="+1",
            help_text="Workers currently available for guarded execution or supporting tasks.",
        ),
        _metric(
            id="busy_workers",
            label="Busy Workers",
            value=2,
            tone="neutral",
            trend="0",
            help_text="Workers actively handling requests or background jobs.",
        ),
        _metric(
            id="sandbox_capacity",
            label="Sandbox Capacity",
            value="72%",
            tone="neutral",
            trend="-3%",
            help_text="Estimated available capacity across active sandbox lanes.",
        ),
        _metric(
            id="runtime_alerts",
            label="Runtime Alerts",
            value=1,
            tone="warning",
            trend="+1",
            help_text="Operational alerts related to runtime execution or availability.",
        ),
    ]

    filters = [
        _filter(
            name="environment",
            label="Environment",
            value=environment,
            field_type="select",
            options=[
                {"label": "Local", "value": "local"},
                {"label": "Development", "value": "development"},
                {"label": "Staging", "value": "staging"},
                {"label": "Production", "value": "production"},
            ],
        ),
        _filter(
            name="lane",
            label="Lane",
            value=lane,
            field_type="select",
            options=[
                {"label": "Default", "value": "default"},
                {"label": "Prompt Guard", "value": "promptguard"},
                {"label": "Detonation", "value": "detonation"},
                {"label": "Review", "value": "review"},
                {"label": "Quarantine", "value": "quarantine"},
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

    sections = [
        _section(
            id="runtime-overview",
            title="Runtime Overview",
            description="Top-level runtime posture for guarded execution and supporting services.",
            items=[
                _item(
                    label="Environment",
                    value=effective_environment,
                    tone="neutral",
                    help_text="Deployment environment currently being inspected.",
                ),
                _item(
                    label="Selected Lane",
                    value=effective_lane,
                    tone="neutral",
                    help_text="Execution or workflow lane emphasized in this runtime view.",
                ),
                _item(
                    label="Dispatcher State",
                    value="ready",
                    tone="positive",
                    help_text="Routing and dispatch surfaces are available for new work.",
                ),
                _item(
                    label="Execution Pipeline",
                    value="active",
                    tone="positive",
                    help_text="Guarded runtime pipeline is able to process supported requests.",
                ),
            ],
        ),
        _section(
            id="sandbox-health",
            title="Sandbox Health",
            description="High-level posture for isolated execution and detonation paths.",
            items=[
                _item(
                    label="Isolation Mode",
                    value="enforced",
                    tone="positive",
                    help_text="Sandbox boundaries remain active for risky or isolated workloads.",
                ),
                _item(
                    label="Network Guard",
                    value="available",
                    tone="positive",
                    help_text="Runtime network controls are available for restricted execution paths.",
                ),
                _item(
                    label="File Return Guard",
                    value="available",
                    tone="positive",
                    help_text="Returned artifacts can be checked before being exposed externally.",
                ),
                _item(
                    label="Detonation Path",
                    value="standby",
                    tone="neutral",
                    help_text="Risky artifacts can be diverted into detonation or deeper analysis paths.",
                ),
            ],
        ),
        _section(
            id="operator-guidance",
            title="Operator Guidance",
            description="Suggested next checks when runtime status changes or warnings appear.",
            items=[
                _item(
                    label="Review Diagnostics",
                    value="recommended",
                    tone="neutral",
                    help_text="Inspect broader system diagnostics if runtime posture shifts.",
                ),
                _item(
                    label="Inspect Quarantine",
                    value="recommended",
                    tone="neutral",
                    help_text="Check quarantined artifacts if runtime warnings correlate with risky output.",
                ),
                _item(
                    label="Check Audit Trails",
                    value="recommended",
                    tone="neutral",
                    help_text="Use audit and usage views to correlate operator and system actions.",
                ),
                _item(
                    label="Escalate Critical Drift",
                    value="required",
                    tone="warning",
                    help_text="Unexpected failures in isolation or execution controls should be escalated immediately.",
                ),
            ],
        ),
    ]

    return {
        "page": "ui-runtime-status",
        "title": "Runtime Status",
        "summary": "Review worker posture, sandbox readiness, and runtime control health across IronClaw execution lanes.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh runtime status",
                "method": "GET",
                "path": "/ui/uiruntimestatus",
                "query": {
                    "environment": environment,
                    "lane": lane,
                    "period": period,
                },
                "description": "Reload runtime status using the active environment and lane filters.",
            },
            {
                "id": "open-system-diagnostics",
                "title": "Open system diagnostics",
                "method": "GET",
                "path": "/ui/uisystemdiagnostics",
                "query": {
                    "environment": environment,
                    "period": period,
                },
                "description": "Pivot to broader health and diagnostics coverage for the selected environment.",
            },
            {
                "id": "open-quarantine-overview",
                "title": "Open quarantine overview",
                "method": "GET",
                "path": "/quarantine/overview",
                "query": {
                    "period": period,
                },
                "description": "Inspect isolated artifacts if runtime controls flagged suspicious behavior.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Review runtime-related actor and system activity in the audit log.",
            },
        ],
    }
