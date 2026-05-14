from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/docs_quickstart", tags=["ui-docs-quickstart"])


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


def _step(
    *,
    id: str,
    title: str,
    description: str,
    command: str | None = None,
    code: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "description": description,
        "command": command,
        "code": code,
        "path": path,
    }


def _endpoint(
    *,
    label: str,
    method: str,
    path: str,
    description: str,
) -> dict[str, str]:
    return {
        "label": label,
        "method": method,
        "path": path,
        "description": description,
    }


@router.get("")
def ui_docs_quickstart_page(
    audience: str | None = Query(default=None),
    sdk: str | None = Query(default=None),
    environment: str | None = Query(default=None),
) -> dict[str, Any]:
    effective_audience = audience or "developer"
    effective_sdk = sdk or "python"
    effective_environment = environment or "local"

    metrics = [
        _metric(
            id="first_request_steps",
            label="First Request Steps",
            value=4,
            tone="positive",
            trend="ready",
            help_text="Minimum steps to go from key creation to first guarded request.",
        ),
        _metric(
            id="supported_sdks",
            label="Supported SDK Paths",
            value=3,
            tone="neutral",
            trend="+1",
            help_text="Language or integration examples available in the quickstart view.",
        ),
        _metric(
            id="protected_surfaces",
            label="Protected Surfaces",
            value=5,
            tone="positive",
            trend="covered",
            help_text="Core routes highlighted for secure first-use onboarding.",
        ),
        _metric(
            id="operator_followups",
            label="Operator Follow-Ups",
            value=4,
            tone="neutral",
            trend="available",
            help_text="Operational pages linked after initial developer setup.",
        ),
    ]

    sections = [
        _section(
            id="quickstart-context",
            title="Quickstart Context",
            description="Who this onboarding path is for and what it emphasizes first.",
            items=[
                _item(
                    label="Audience",
                    value=effective_audience,
                    tone="neutral",
                    help_text="The primary reader for this quickstart flow.",
                ),
                _item(
                    label="SDK Preference",
                    value=effective_sdk,
                    tone="neutral",
                    help_text="Preferred implementation path for first integration.",
                ),
                _item(
                    label="Environment",
                    value=effective_environment,
                    tone="neutral",
                    help_text="Target environment for first-use examples and commands.",
                ),
                _item(
                    label="Security Focus",
                    value="enabled",
                    tone="positive",
                    help_text="Onboarding is oriented around authenticated guarded usage, not anonymous access.",
                ),
            ],
        ),
        _section(
            id="onboarding-guidance",
            title="Onboarding Guidance",
            description="Recommended sequence for getting value from IronClaw quickly and safely.",
            items=[
                _item(
                    label="Create Customer Key",
                    value="required",
                    tone="warning",
                    help_text="Start with tenant-scoped API credentials before calling protected routes.",
                ),
                _item(
                    label="Send Guarded Request",
                    value="required",
                    tone="warning",
                    help_text="Verify the authenticated request flow with a simple protected action.",
                ),
                _item(
                    label="Inspect Usage Visibility",
                    value="recommended",
                    tone="neutral",
                    help_text="Check usage, telemetry, and audit views after the first request succeeds.",
                ),
                _item(
                    label="Review Runtime Posture",
                    value="recommended",
                    tone="neutral",
                    help_text="Use diagnostics and runtime views if onboarding behavior is unexpected.",
                ),
            ],
        ),
    ]

    steps = [
        _step(
            id="create-key",
            title="Create a customer key",
            description="Create or review a tenant-scoped customer API key before calling protected surfaces.",
            path="/ui/customerkeys",
        ),
        _step(
            id="store-key",
            title="Set your API key header",
            description="Send the customer key using X-API-Key or Bearer authorization on protected requests.",
            code="X-API-Key: <your-customer-key>",
        ),
        _step(
            id="send-request",
            title="Make your first guarded request",
            description="Call a protected endpoint and confirm the request is accepted by the auth layer.",
            command='curl -H "X-API-Key: <your-customer-key>" http://localhost:8000/ui/usagereports',
            path="/ui/usagereports",
        ),
        _step(
            id="inspect-results",
            title="Inspect operational visibility",
            description="Review audit, telemetry, and request context surfaces after the first request succeeds.",
            path="/ui/uiauditlog",
        ),
    ]

    endpoints = [
        _endpoint(
            label="Customer Keys",
            method="GET",
            path="/ui/customerkeys",
            description="Review or manage customer API keys used for authenticated access.",
        ),
        _endpoint(
            label="Usage Reports",
            method="GET",
            path="/ui/usagereports",
            description="Inspect metered activity and related request outcomes.",
        ),
        _endpoint(
            label="Audit Log",
            method="GET",
            path="/ui/uiauditlog",
            description="Review authenticated activity and operator-visible audit trails.",
        ),
        _endpoint(
            label="Request Context",
            method="GET",
            path="/ui/requestcontext",
            description="Inspect contextual information used for guarded decisioning.",
        ),
        _endpoint(
            label="System Diagnostics",
            method="GET",
            path="/ui/uisystemdiagnostics",
            description="Review runtime and platform state if onboarding behavior looks abnormal.",
        ),
    ]

    return {
        "page": "ui-docs-quickstart",
        "title": "Docs Quickstart",
        "summary": "Follow the shortest secure path from API key creation to first guarded request and operational visibility.",
        "metrics": metrics,
        "sections": sections,
        "steps": steps,
        "endpoints": endpoints,
        "actions": [
            {
                "id": "open-customer-keys",
                "title": "Open customer keys",
                "method": "GET",
                "path": "/ui/customerkeys",
                "description": "Start onboarding by creating or inspecting customer-scoped API keys.",
            },
            {
                "id": "open-usage-reports",
                "title": "Open usage reports",
                "method": "GET",
                "path": "/ui/usagereports",
                "description": "Validate first-request activity through the usage reporting view.",
            },
            {
                "id": "open-audit-log",
                "title": "Open audit log",
                "method": "GET",
                "path": "/ui/uiauditlog",
                "description": "Inspect authenticated actions recorded during onboarding and first use.",
            },
            {
                "id": "open-system-diagnostics",
                "title": "Open system diagnostics",
                "method": "GET",
                "path": "/ui/uisystemdiagnostics",
                "description": "Review runtime posture if setup or request verification needs troubleshooting.",
            },
        ],
    }
