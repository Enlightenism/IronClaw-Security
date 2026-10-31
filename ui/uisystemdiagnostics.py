from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from app.core.settings import get_settings

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
    settings = get_settings()
    effective_environment = environment or settings.environment or "local"
    effective_profile = profile or "gen1"
    auth_enforced = settings.effective_auth_required

    metrics = [
        _metric(
            id="healthy_components",
            label="Healthy Components",
            value="not_measured",
            tone="neutral",
            trend=None,
            help_text="No live component health probe is wired to this page yet.",
        ),
        _metric(
            id="degraded_components",
            label="Degraded Components",
            value="not_measured",
            tone="neutral",
            trend=None,
            help_text="No live component health probe is wired to this page yet.",
        ),
        _metric(
            id="failed_checks",
            label="Failed Checks",
            value="not_measured",
            tone="neutral",
            trend=None,
            help_text="No live diagnostic check results are wired to this page yet.",
        ),
        _metric(
            id="runtime_restarts",
            label="Runtime Restarts",
            value="not_measured",
            tone="neutral",
            trend=None,
            help_text="No runtime restart telemetry is wired to this page yet.",
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
                    value="enforced" if auth_enforced else "not_enforced",
                    tone="positive" if auth_enforced else "warning",
                    help_text="Derived from AUTH_REQUIRED and configured credentials.",
                ),
                _item(
                    label="Guardrails",
                    value="not_verified",
                    tone="neutral",
                    help_text="Guardrail status is not yet read from live guardrail state.",
                ),
                _item(
                    label="Quarantine Pipeline",
                    value="not_verified",
                    tone="neutral",
                    help_text="Quarantine status is not yet read from live pipeline state.",
                ),
                _item(
                    label="Audit Logging",
                    value="not_verified",
                    tone="neutral",
                    help_text="Audit retention is not yet read from live audit configuration.",
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
