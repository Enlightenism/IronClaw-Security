from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(prefix="/ui/requestcontext", tags=["ui-request-context"])


def _field(
    *,
    name: str,
    label: str,
    field_type: str,
    required: bool,
    placeholder: str | None = None,
    help_text: str | None = None,
    default: Any | None = None,
    options: list[dict[str, Any]] | None = None,
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": field_type,
        "required": required,
        "placeholder": placeholder,
        "help_text": help_text,
        "default": default,
        "options": options or [],
        "validation": validation or {},
    }


def _section(
    *,
    id: str,
    title: str,
    description: str,
    fields: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "title": title,
        "description": description,
        "fields": fields or [],
    }


def _metric(
    *,
    metric_id: str,
    label: str,
    value: Any,
    tone: str = "neutral",
    help_text: str | None = None,
) -> dict[str, Any]:
    return {
        "metric_id": metric_id,
        "label": label,
        "value": value,
        "tone": tone,
        "help_text": help_text,
    }


def _example_payload(
    *,
    target_type: str = "text",
    target_value: str = "Summarize this document safely.",
    mode: str = "enforce",
    source: str = "ui-console",
    session_id: str = "sess_demo_001",
    user_id: str = "user_demo_001",
    context: str = "Interactive request from customer UI",
    customer_key_id: str = "ck_demo_primary",
    trace_id: str = "trace_demo_001",
) -> dict[str, Any]:
    return {
        "target_type": target_type,
        "target_value": target_value,
        "mode": mode,
        "source": source,
        "session_id": session_id,
        "user_id": user_id,
        "customer_key_id": customer_key_id,
        "trace_id": trace_id,
        "context": context,
    }


def _target_type_options() -> list[dict[str, str]]:
    return [
        {"label": "Text", "value": "text"},
        {"label": "URL", "value": "url"},
        {"label": "GitHub Repository", "value": "githubrepo"},
        {"label": "Archive", "value": "archive"},
    ]


def _mode_options() -> list[dict[str, str]]:
    return [
        {"label": "Enforce", "value": "enforce"},
        {"label": "Monitor", "value": "monitor"},
        {"label": "Strict", "value": "strict"},
    ]


def _source_options() -> list[dict[str, str]]:
    return [
        {"label": "UI Console", "value": "ui-console"},
        {"label": "Customer Portal", "value": "customer-portal"},
        {"label": "API", "value": "api"},
        {"label": "CLI", "value": "cli"},
        {"label": "Security Review", "value": "security-review"},
        {"label": "Integration", "value": "integration"},
    ]


def _result_preview(target_type: str, mode: str) -> dict[str, Any]:
    return {
        "scan_request": {
            "method": "POST",
            "path": "/scan",
            "body_shape": {
                "target_type": target_type,
                "target_value": "<user-supplied>",
                "mode": mode,
                "source": "<optional-source>",
                "session_id": "<optional-session-id>",
                "user_id": "<optional-user-id>",
                "customer_key_id": "<optional-customer-key-id>",
                "trace_id": "<optional-trace-id>",
                "context": "<optional-context>",
            },
        },
        "decision_request": {
            "method": "POST",
            "path": "/brain/decision",
            "body_shape": {
                "target_type": target_type,
                "target_value": "<user-supplied>",
                "mode": mode,
                "use_history": True,
                "max_history": 20,
                "source": "<optional-source>",
                "session_id": "<optional-session-id>",
                "user_id": "<optional-user-id>",
                "customer_key_id": "<optional-customer-key-id>",
                "trace_id": "<optional-trace-id>",
                "context": "<optional-context>",
            },
        },
    }


@router.get("")
def request_context_page(
    target_type: str = Query(default="text"),
    mode: str = Query(default="enforce"),
    source: str = Query(default="ui-console"),
) -> dict[str, Any]:
    selected_target_type = (
        target_type
        if target_type in {option["value"] for option in _target_type_options()}
        else "text"
    )
    selected_mode = (
        mode
        if mode in {option["value"] for option in _mode_options()}
        else "enforce"
    )
    selected_source = (
        source
        if source in {option["value"] for option in _source_options()}
        else "ui-console"
    )

    return {
        "page": "request-context",
        "title": "Request Context",
        "summary": (
            "Build, inspect, and submit context metadata attached to scans, "
            "brain decisions, history lookups, and customer-key-driven actions."
        ),
        "selected": {
            "target_type": selected_target_type,
            "mode": selected_mode,
            "source": selected_source,
        },
        "metrics": [
            _metric(
                metric_id="supported_target_types",
                label="Supported Target Types",
                value=4,
                tone="neutral",
                help_text="Available target types exposed by this request context builder.",
            ),
            _metric(
                metric_id="supported_modes",
                label="Supported Modes",
                value=3,
                tone="neutral",
                help_text="Enforcement strategies available to the operator.",
            ),
            _metric(
                metric_id="history_enabled",
                label="History-Aware Decisions",
                value=True,
                tone="positive",
                help_text="Brain decision flows can optionally include history context.",
            ),
            _metric(
                metric_id="customer_key_ready",
                label="Customer Key Ready",
                value=True,
                tone="positive",
                help_text="Payload examples include customer-key linkage fields.",
            ),
        ],
        "sections": [
            _section(
                id="identity",
                title="Identity",
                description="Identify who initiated the request and which session or trace it belongs to.",
                fields=[
                    _field(
                        name="user_id",
                        label="User ID",
                        field_type="text",
                        required=False,
                        placeholder="user_123",
                        help_text="Stable user identifier for correlation and history lookups.",
                        validation={
                            "max_length": 128,
                            "pattern_hint": "letters, numbers, dashes, and underscores",
                        },
                    ),
                    _field(
                        name="session_id",
                        label="Session ID",
                        field_type="text",
                        required=False,
                        placeholder="sess_123",
                        help_text="Session identifier used for related-history decisions.",
                        validation={
                            "max_length": 128,
                        },
                    ),
                    _field(
                        name="trace_id",
                        label="Trace ID",
                        field_type="text",
                        required=False,
                        placeholder="trace_123",
                        help_text="Optional trace identifier for request-chain correlation.",
                        validation={
                            "max_length": 128,
                        },
                    ),
                    _field(
                        name="source",
                        label="Source",
                        field_type="select",
                        required=False,
                        default=selected_source,
                        help_text="Origin of the action, such as dashboard, api, cli, or integration.",
                        options=_source_options(),
                    ),
                ],
            ),
            _section(
                id="scan-input",
                title="Scan Input",
                description="Define the scan target and the mode used to interpret enforcement behavior.",
                fields=[
                    _field(
                        name="target_type",
                        label="Target Type",
                        field_type="select",
                        required=True,
                        default=selected_target_type,
                        help_text="Supported values include text, url, githubrepo, and archive.",
                        options=_target_type_options(),
                    ),
                    _field(
                        name="target_value",
                        label="Target Value",
                        field_type="textarea",
                        required=True,
                        placeholder="Paste the content or target to inspect",
                        help_text="Primary content or pointer that will be scanned.",
                        validation={
                            "min_length": 1,
                            "max_length": 20000,
                        },
                    ),
                    _field(
                        name="mode",
                        label="Mode",
                        field_type="select",
                        required=True,
                        default=selected_mode,
                        help_text="Typical modes are enforce, monitor, and strict.",
                        options=_mode_options(),
                    ),
                ],
            ),
            _section(
                id="routing",
                title="Routing Metadata",
                description="Attach metadata used to route the request across customer-key and execution-aware flows.",
                fields=[
                    _field(
                        name="customer_key_id",
                        label="Customer Key ID",
                        field_type="text",
                        required=False,
                        placeholder="ck_live_primary",
                        help_text="Optional customer key identifier associated with the request origin.",
                        validation={
                            "max_length": 128,
                        },
                    ),
                    _field(
                        name="operation_name",
                        label="Operation Name",
                        field_type="text",
                        required=False,
                        placeholder="scan.upload.review",
                        help_text="Optional logical operation label for audit and telemetry grouping.",
                        validation={
                            "max_length": 128,
                        },
                    ),
                ],
            ),
            _section(
                id="context",
                title="Context Notes",
                description="Attach situational notes that help explain why the request exists.",
                fields=[
                    _field(
                        name="context",
                        label="Context",
                        field_type="textarea",
                        required=False,
                        placeholder="Why is this request happening?",
                        help_text="Freeform operational context for review, history, and brain decisions.",
                        validation={
                            "max_length": 4000,
                        },
                    ),
                ],
            ),
        ],
        "actions": [
            {
                "id": "scan",
                "title": "Run Scan",
                "method": "POST",
                "path": "/scan",
                "description": "Submit a scan request with request context metadata attached.",
                "example_payload": _example_payload(
                    target_type=selected_target_type,
                    mode=selected_mode,
                    source=selected_source,
                ),
            },
            {
                "id": "brain-decision",
                "title": "Run Brain Decision",
                "method": "POST",
                "path": "/brain/decision",
                "description": (
                    "Submit a contextual decision request that can use history "
                    "for higher-confidence actioning."
                ),
                "example_payload": {
                    **_example_payload(
                        target_type=selected_target_type,
                        mode=selected_mode,
                        source=selected_source,
                    ),
                    "use_history": True,
                    "max_history": 20,
                },
            },
            {
                "id": "history",
                "title": "Inspect History",
                "method": "GET",
                "path": "/history",
                "description": "Review recent stored events that share the same request context identifiers.",
                "query": {
                    "user_id": "user_demo_001",
                    "session_id": "sess_demo_001",
                    "trace_id": "trace_demo_001",
                },
            },
        ],
        "result_preview": _result_preview(
            target_type=selected_target_type,
            mode=selected_mode,
        ),
        "examples": [
            {
                "name": "Customer dashboard scan",
                "payload": _example_payload(
                    target_type=selected_target_type,
                    mode=selected_mode,
                    source=selected_source,
                ),
            },
            {
                "name": "URL monitoring flow",
                "payload": _example_payload(
                    target_type="url",
                    target_value="https://example.com/suspicious-page",
                    mode="monitor",
                    source="customer-portal",
                    context="User submitted a URL for passive inspection",
                    customer_key_id="ck_customer_portal",
                    trace_id="trace_url_monitor_001",
                ),
            },
            {
                "name": "Strict repository review",
                "payload": _example_payload(
                    target_type="githubrepo",
                    target_value="https://github.com/example/repo",
                    mode="strict",
                    source="security-review",
                    context="High assurance review before repository ingestion",
                    customer_key_id="ck_security_review",
                    trace_id="trace_repo_review_001",
                ),
            },
        ],
        "related_pages": [
            {
                "id": "metrics-summary",
                "title": "Open Metrics Summary",
                "method": "GET",
                "path": "/ui/metricssummary",
                "query": {
                    "metric_group": "security",
                },
            },
            {
                "id": "telemetry-access-summary",
                "title": "Open Telemetry Access Summary",
                "method": "GET",
                "path": "/ui/telemetryaccesssummary",
                "query": {
                    "period": "24h",
                },
            },
            {
                "id": "customer-keys",
                "title": "Open Customer Keys",
                "method": "GET",
                "path": "/ui/customerkeys",
            },
        ],
    }