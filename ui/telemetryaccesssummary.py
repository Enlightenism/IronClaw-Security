from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/telemetryaccesssummary", tags=["ui-telemetry-access-summary"])


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


@router.get("")
def telemetry_access_summary_page(
    principal_id: str | None = Query(default=None),
    principal_type: str | None = Query(default=None),
    period: str = Query(default="24h"),
) -> dict[str, Any]:
    """UI metadata endpoint for telemetry access posture.

    This page is intentionally presentation-oriented so the UI can render:
    - summary KPIs
    - policy/access posture sections
    - quick navigation actions into related pages
    """
    effective_principal_id = principal_id or "cust_demo_001"
    effective_principal_type = principal_type or "customer"

    metrics = [
        _metric(
            id="telemetry_reads",
            label="Telemetry Reads",
            value=42,
            tone="neutral",
            trend="+6%",
            help_text="Number of telemetry access read operations during the selected period.",
        ),
        _metric(
            id="sensitive_events_viewed",
            label="Sensitive Events Viewed",
            value=3,
            tone="warning",
            trend="+1",
            help_text="Events marked sensitive or higher-risk that were viewed.",
        ),
        _metric(
            id="denied_access_attempts",
            label="Denied Access Attempts",
            value=1,
            tone="positive",
            trend="-2",
            help_text="Blocked attempts to access telemetry outside policy bounds.",
        ),
        _metric(
            id="active_filters_used",
            label="Active Filters Used",
            value=5,
            tone="neutral",
            help_text="Distinct telemetry filters used to narrow report scope.",
        ),
    ]

    sections = [
        _section(
            id="identity",
            title="Principal Context",
            description="Identity and scope context used for telemetry access evaluation.",
            items=[
                _item(
                    label="Principal ID",
                    value=effective_principal_id,
                ),
                _item(
                    label="Principal Type",
                    value=effective_principal_type,
                ),
                _item(
                    label="Reporting Period",
                    value=period,
                ),
                _item(
                    label="Access Scope",
                    value="telemetry:read",
                    help_text="Effective access scope required to view telemetry summaries.",
                ),
            ],
        ),
        _section(
            id="policy-posture",
            title="Policy Posture",
            description="High-level posture of telemetry access controls and enforcement.",
            items=[
                _item(
                    label="Policy Mode",
                    value="enforce",
                    tone="positive",
                    help_text="Telemetry access checks are enforced rather than monitor-only.",
                ),
                _item(
                    label="Redaction Status",
                    value="active",
                    tone="positive",
                    help_text="Sensitive fields are redacted or constrained before UI exposure.",
                ),
                _item(
                    label="Audit Logging",
                    value="enabled",
                    tone="positive",
                    help_text="Every telemetry access request is audit logged.",
                ),
                _item(
                    label="Drilldown Access",
                    value="allowed",
                    tone="neutral",
                    help_text="Principal can open event detail pages for permitted records.",
                ),
            ],
        ),
        _section(
            id="risk-signals",
            title="Risk Signals",
            description="Signals that help operators understand unusual telemetry access patterns.",
            items=[
                _item(
                    label="Burst Reads Detected",
                    value=False,
                    tone="positive",
                    help_text="Whether the principal performed a sudden spike in telemetry reads.",
                ),
                _item(
                    label="Cross-Tenant Access Attempts",
                    value=0,
                    tone="positive",
                    help_text="Attempts to view telemetry outside the principal's allowed tenant boundary.",
                ),
                _item(
                    label="Sensitive Drilldowns",
                    value=3,
                    tone="warning",
                    help_text="Count of sensitive or high-risk event detail views.",
                ),
                _item(
                    label="Latest Verdict",
                    value="allow",
                    tone="positive",
                    help_text="Most recent telemetry access authorization verdict.",
                ),
            ],
        ),
    ]

    actions = [
        {
            "id": "open-usage-reports",
            "title": "Open Usage Reports",
            "method": "GET",
            "path": "/ui/usagereports",
            "query": {
                "principal_id": effective_principal_id,
                "period": period,
            },
            "description": "View detailed usage reporting filtered to the same principal context.",
        },
        {
            "id": "open-request-context",
            "title": "Open Request Context",
            "method": "GET",
            "path": "/ui/requestcontext",
            "query": {
                "target_type": "text",
                "mode": "enforce",
            },
            "description": "Jump to request context tooling for related scan and decision flows.",
        },
        {
            "id": "open-customer-keys",
            "title": "Open Customer Keys",
            "method": "GET",
            "path": "/ui/customerkeys",
            "description": "Review the customer API keys associated with telemetry-producing activity.",
        },
    ]

    return {
        "page": "telemetry-access-summary",
        "title": "Telemetry Access Summary",
        "summary": "Review telemetry access posture, audit visibility, and risk signals for a principal.",
        "principal": {
            "principal_id": effective_principal_id,
            "principal_type": effective_principal_type,
            "period": period,
        },
        "metrics": metrics,
        "sections": sections,
        "actions": actions,
    }
