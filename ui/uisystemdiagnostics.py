from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/uisystemdiagnostics", tags=["ui-system-diagnostics"])


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
def ui_system_diagnostics_page(
    environment: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    effective_environment = environment or "local"
    effective_profile = profile or "gen1"

    metrics = [
        _metric(
            id="healthy_components",
            label="Healthy Components",
            value=12,
            tone="positive",
            trend="+1",
            help_text="Components currently reporting healthy diagnostic state.",
        ),
        _metric(
            id="degraded_components",
            label="Degraded Components",
            value=1,
            tone="warning",
            trend="0",
            help_text="Components operating with warnings or reduced confidence.",
        ),
        _metric(
            id="failed_checks",
            label="Failed Checks",
            value=0,
            tone="positive",
            trend="-1",
            help_text="Diagnostic checks that failed in the selected time window.",
        ),
        _metric(
            id="runtime_restarts",
            label="Runtime Restarts",
            value=2,
            tone="neutral",
            trend="+1",
            help_text="Observed runtime or worker restart events in the period.",
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
            name="profile",
            label="Profile",
            value=profile,
            field_type="select",
            options=[
                {"label": "Gen1", "value": "gen1"},
                {"label": "Security", "value": "security"},
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

    sections = [
        _section(
            id="runtime-health",
            title="Runtime Health",
            description="Core process and execution health for the current deployment profile.",
            items=[
                _item(
                    label="Environment",
                    value=effective_environment,
                    tone="neutral",
                    help_text="Deployment environment under review.",
                ),
                _item(
                    label="Runtime Profile",
                    value=effective_profile,
                    tone="neutral",
                    help_text="Active diagnostic profile or operating mode.",
                ),
                _item(
                    label="API Surface",
                    value="healthy",
                    tone="positive",
                    help_text="Primary API routes are expected to be reachable and responding.",
                ),
                _item(
                    label="Worker State",
                    value="ready",
                    tone="positive",
                    help_text="Background workers and runtime processes are available.",
                ),
            ],
        ),
        _section(
            id="security-controls",
            title="Security Controls",
            description="High-level posture of the main guard and platform controls.",
            items=[
                _item(
                    label="Authentication",
                    value="enforced",
                    tone="positive",
                    help_text="API key authentication is expected to be active on protected surfaces.",
                ),
                _item(
                    label="Guardrails",
                    value="active",
                    tone="positive",
                    help_text="Prompt, execution, and request-level controls are available.",
                ),
                _item(
                    label="Quarantine Pipeline",
                    value="available",
                    tone="positive",
                    help_text="Isolation and containment paths can receive flagged artifacts.",
                ),
                _item(
                    label="Audit Logging",
                    value="enabled",
                    tone="positive",
                    help_text="Security-relevant events are expected to be retained for investigation.",
                ),
            ],
        ),
        _section(
            id="integration-state",
            title="Integration State",
            description="Operational posture for configured external integrations and providers.",
            items=[
                _item(
                    label="Registry Status",
                    value="loaded",
                    tone="positive",
                    help_text="Integration registry initialized successfully.",
                ),
                _item(
                    label="Provider Connectivity",
                    value="monitoring",
                    tone="neutral",
                    help_text="Providers should be monitored for health and compatibility drift.",
                ),
                _item(
                    label="Secrets Availability",
                    value="configured",
                    tone="positive",
                    help_text="Required credentials are expected to be present for enabled integrations.",
                ),
                _item(
                    label="Verification Coverage",
                    value="partial",
                    tone="warning",
                    help_text="Some integrations may still need deeper verification or rollout checks.",
                ),
            ],
        ),
        _section(
            id="operator-guidance",
            title="Operator Guidance",
            description="Suggested operator checks when diagnostics show warnings or drift.",
            items=[
                _item(
                    label="Inspect Health Snapshot",
                    value="recommended",
                    tone="neutral",
                    help_text="Start with current runtime and health snapshot surfaces.",
                ),
                _item(
                    label="Review Audit Signals",
                    value="recommended",
                    tone="neutral",
                    help_text="Check audit and usage trails if a component changed state unexpectedly.",
                ),
                _item(
                    label="Validate Integration Secrets",
                    value="recommended",
                    tone="neutral",
                    help_text="Confirm provider credentials and configuration if integrations degrade.",
                ),
                _item(
                    label="Escalate Critical Failures",
                    value="required",
                    tone="warning",
                    help_text="Any failed core security control should be escalated immediately.",
                ),
            ],
        ),
    ]

    return {
        "page": "ui-system-diagnostics",
        "title": "System Diagnostics",
        "summary": "Review runtime health, control posture, and operator guidance for the current IronClaw deployment.",
        "filters": filters,
        "metrics": metrics,
        "sections": sections,
        "actions": [
            {
                "id": "refresh",
                "title": "Refresh diagnostics",
                "method": "GET",
                "path": "/ui/uisystemdiagnostics",
                "query": {
                    "environment": environment,
                    "profile": profile,
                    "period": period,
                },
                "description": "Reload system diagnostics for the selected environment and profile.",
            },
            {
                "id": "open-runtime-status",
                "title": "Open runtime status",
                "method": "GET",
                "path": "/ui/uiruntimestatus",
                "query": {
                    "environment": environment,
                },
                "description": "Pivot into runtime-specific status and readiness details.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "query": {
                    "period": period,
                },
                "description": "Inspect related audit events around component state changes.",
            },
            {
                "id": "open-quarantine-overview",
                "title": "Open quarantine overview",
                "method": "GET",
                "path": "/quarantine/overview",
                "query": {
                    "period": period,
                },
                "description": "Review containment state if diagnostics indicate suspicious activity.",
            },
        ],
    }
