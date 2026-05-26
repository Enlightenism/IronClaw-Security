from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/docs",
    tags=["docs-api-reference"],
)


class ApiRouteFieldView(BaseModel):
    name: str
    location: str
    required: bool = False
    description: str


class ApiRouteEntryView(BaseModel):
    routeid: str
    method: str
    path: str
    description: str
    authrequired: bool
    requestfields: list[ApiRouteFieldView] = Field(default_factory=list)
    responsefields: list[ApiRouteFieldView] = Field(default_factory=list)


class ApiRouteGroupView(BaseModel):
    groupid: str
    label: str
    description: str
    routes: list[ApiRouteEntryView] = Field(default_factory=list)


class ApiReferencePageResponse(BaseModel):
    generatedat: str
    version: str
    baseurl: str
    apikeyheadername: str
    totalgroupcount: int
    totalroutecount: int
    groups: list[ApiRouteGroupView] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _build_groups() -> list[ApiRouteGroupView]:
    guard_routes = [
        ApiRouteEntryView(
            routeid="guard-action",
            method="POST",
            path="/guard/action",
            description="Evaluate a proposed agent action against runtime policy and return an allow, warn, quarantine, or block verdict.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="actiontype", location="body", required=True, description="Type of action being guarded (e.g. toolcall, httpfetch, shellexec)."),
                ApiRouteFieldView(name="target", location="body", required=True, description="Target resource or destination the action will operate against."),
                ApiRouteFieldView(name="riskscore", location="body", required=False, description="Caller-supplied risk score hint (0–100); influences policy threshold checks."),
                ApiRouteFieldView(name="metadata", location="body", required=False, description="Arbitrary key-value context passed through to audit and telemetry."),
            ],
            responsefields=[
                ApiRouteFieldView(name="verdict", location="body", required=True, description="Policy decision: allow | warn | quarantine | block."),
                ApiRouteFieldView(name="reason", location="body", required=False, description="Human-readable explanation for the verdict."),
                ApiRouteFieldView(name="policyid", location="body", required=False, description="ID of the policy rule that produced the verdict."),
                ApiRouteFieldView(name="eventid", location="body", required=False, description="Audit event ID emitted for this guard decision."),
            ],
        ),
        ApiRouteEntryView(
            routeid="guard-action-decision",
            method="POST",
            path="/guard/action-decision",
            description="Return a decision-only guard response optimised for orchestration layer consumption.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="actiontype", location="body", required=True, description="Type of action being evaluated."),
                ApiRouteFieldView(name="target", location="body", required=True, description="Target resource identifier."),
                ApiRouteFieldView(name="riskscore", location="body", required=False, description="Caller-provided risk score (0–100)."),
            ],
            responsefields=[
                ApiRouteFieldView(name="decision", location="body", required=True, description="allow | warn | quarantine | block."),
                ApiRouteFieldView(name="confidence", location="body", required=False, description="Model or policy confidence for the decision (0.0–1.0)."),
                ApiRouteFieldView(name="eventid", location="body", required=False, description="Linked audit event ID."),
            ],
        ),
        ApiRouteEntryView(
            routeid="guard-execute",
            method="POST",
            path="/guard/execute",
            description="Submit a guarded runtime execution request; IronClaw evaluates the execution plan before allowing it to proceed.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="actiontype", location="body", required=True, description="Execution action category."),
                ApiRouteFieldView(name="target", location="body", required=True, description="Execution target (e.g. shell command, file path, endpoint URL)."),
                ApiRouteFieldView(name="riskscore", location="body", required=False, description="Risk score hint (0–100)."),
                ApiRouteFieldView(name="sessionid", location="body", required=False, description="Session context identifier for correlated telemetry."),
            ],
            responsefields=[
                ApiRouteFieldView(name="verdict", location="body", required=True, description="Guard verdict for the execution plan."),
                ApiRouteFieldView(name="executionid", location="body", required=False, description="Execution record ID for downstream audit lookup."),
                ApiRouteFieldView(name="reason", location="body", required=False, description="Explanation attached to non-allow verdicts."),
            ],
        ),
        ApiRouteEntryView(
            routeid="guard-reviews-pending",
            method="GET",
            path="/guard/reviews/pending",
            description="List all actions currently queued for analyst review.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="limit", location="query", required=False, description="Maximum number of pending items to return."),
                ApiRouteFieldView(name="offset", location="query", required=False, description="Pagination offset."),
            ],
            responsefields=[
                ApiRouteFieldView(name="items", location="body", required=True, description="Array of pending review action records."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total count of items currently in the review queue."),
            ],
        ),
        ApiRouteEntryView(
            routeid="guard-reviews-decide",
            method="POST",
            path="/guard/reviews/decide",
            description="Submit an analyst decision (approve or deny) for a queued review item.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="reviewid", location="body", required=True, description="ID of the review queue item being decided."),
                ApiRouteFieldView(name="decision", location="body", required=True, description="approve | deny."),
                ApiRouteFieldView(name="reason", location="body", required=False, description="Analyst rationale attached to the decision."),
            ],
            responsefields=[
                ApiRouteFieldView(name="reviewid", location="body", required=True, description="ID of the resolved review item."),
                ApiRouteFieldView(name="status", location="body", required=True, description="Updated review status after the decision."),
                ApiRouteFieldView(name="eventid", location="body", required=False, description="Audit event ID for the decision."),
            ],
        ),
        ApiRouteEntryView(
            routeid="guard-audit-events",
            method="GET",
            path="/guard/audit/events",
            description="Retrieve recent guard-layer audit events for policy, review, and runtime outcomes.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="limit", location="query", required=False, description="Number of events to return (default 50)."),
                ApiRouteFieldView(name="since", location="query", required=False, description="ISO 8601 timestamp lower bound for event filtering."),
            ],
            responsefields=[
                ApiRouteFieldView(name="events", location="body", required=True, description="Array of audit event records."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total matching event count."),
            ],
        ),
        ApiRouteEntryView(
            routeid="guard-scan-prompt",
            method="POST",
            path="/guard/scan/prompt",
            description="Run prompt-injection and data-exfiltration detection against a raw prompt string.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="prompt", location="body", required=True, description="Raw prompt text to scan."),
                ApiRouteFieldView(name="context", location="body", required=False, description="Additional context passed to the scanner (model id, session metadata)."),
            ],
            responsefields=[
                ApiRouteFieldView(name="threatdetected", location="body", required=True, description="True if an injection or exfiltration pattern was found."),
                ApiRouteFieldView(name="threattype", location="body", required=False, description="Classification of detected threat if present."),
                ApiRouteFieldView(name="confidence", location="body", required=False, description="Detection confidence score (0.0–1.0)."),
                ApiRouteFieldView(name="scanid", location="body", required=False, description="Unique ID for this scan event."),
            ],
        ),
        ApiRouteEntryView(
            routeid="guard-session-risk",
            method="GET",
            path="/guard/session/{sessionid}/risk",
            description="Return the current risk profile and accumulated threat signals for an active session.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="sessionid", location="path", required=True, description="Session identifier to evaluate."),
            ],
            responsefields=[
                ApiRouteFieldView(name="sessionid", location="body", required=True, description="Echoed session identifier."),
                ApiRouteFieldView(name="riskscore", location="body", required=True, description="Aggregated session risk score (0–100)."),
                ApiRouteFieldView(name="signals", location="body", required=False, description="List of contributing threat signal records."),
                ApiRouteFieldView(name="recommendedaction", location="body", required=False, description="Policy-recommended action given current risk level."),
            ],
        ),
    ]

    policy_routes = [
        ApiRouteEntryView(
            routeid="policy-status",
            method="GET",
            path="/policy/status",
            description="Read the currently active runtime policy configuration and enforcement thresholds.",
            authrequired=True,
            requestfields=[],
            responsefields=[
                ApiRouteFieldView(name="mode", location="body", required=True, description="Enforcement mode: strict | permissive | monitor."),
                ApiRouteFieldView(name="reviewthreshold", location="body", required=True, description="Risk score at which actions enter the review queue."),
                ApiRouteFieldView(name="blockthreshold", location="body", required=True, description="Risk score at which actions are hard-blocked."),
                ApiRouteFieldView(name="quarantinethreshold", location="body", required=False, description="Risk score at which actions are quarantined pending investigation."),
                ApiRouteFieldView(name="updatedby", location="body", required=False, description="Operator identity who last modified policy settings."),
            ],
        ),
        ApiRouteEntryView(
            routeid="policy-update",
            method="POST",
            path="/policy/update",
            description="Apply new enforcement thresholds and mode to the active runtime policy.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="mode", location="body", required=False, description="New enforcement mode: strict | permissive | monitor."),
                ApiRouteFieldView(name="reviewthreshold", location="body", required=False, description="Updated review threshold (0–100)."),
                ApiRouteFieldView(name="blockthreshold", location="body", required=False, description="Updated block threshold (0–100)."),
            ],
            responsefields=[
                ApiRouteFieldView(name="applied", location="body", required=True, description="True if the policy change was committed."),
                ApiRouteFieldView(name="policy", location="body", required=True, description="Full policy object reflecting the new state."),
                ApiRouteFieldView(name="eventid", location="body", required=False, description="Audit event ID for the policy change."),
            ],
        ),
        ApiRouteEntryView(
            routeid="policy-rules",
            method="GET",
            path="/policy/rules",
            description="List all active policy rules with their conditions, verdicts, and priority ordering.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="enabled", location="query", required=False, description="Filter to only enabled rules when true."),
            ],
            responsefields=[
                ApiRouteFieldView(name="rules", location="body", required=True, description="Ordered array of policy rule objects."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total rule count."),
            ],
        ),
    ]

    audit_routes = [
        ApiRouteEntryView(
            routeid="audit-events",
            method="GET",
            path="/audit/events",
            description="Query the audit log for security events, policy decisions, and operator actions.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="limit", location="query", required=False, description="Page size (default 50, max 200)."),
                ApiRouteFieldView(name="offset", location="query", required=False, description="Pagination offset."),
                ApiRouteFieldView(name="since", location="query", required=False, description="ISO 8601 lower-bound timestamp."),
                ApiRouteFieldView(name="eventtype", location="query", required=False, description="Filter by event type category."),
            ],
            responsefields=[
                ApiRouteFieldView(name="events", location="body", required=True, description="Array of audit event records."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total events matching the query."),
                ApiRouteFieldView(name="page", location="body", required=False, description="Current page metadata."),
            ],
        ),
        ApiRouteEntryView(
            routeid="audit-event-detail",
            method="GET",
            path="/audit/events/{eventid}",
            description="Retrieve the full detail record for a single audit event by its ID.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="eventid", location="path", required=True, description="Audit event identifier."),
            ],
            responsefields=[
                ApiRouteFieldView(name="eventid", location="body", required=True, description="Unique event ID."),
                ApiRouteFieldView(name="eventtype", location="body", required=True, description="Classification of the event."),
                ApiRouteFieldView(name="timestamp", location="body", required=True, description="UTC ISO 8601 event timestamp."),
                ApiRouteFieldView(name="actor", location="body", required=False, description="Operator or system identity that triggered the event."),
                ApiRouteFieldView(name="payload", location="body", required=False, description="Full event payload including context and outcome fields."),
            ],
        ),
        ApiRouteEntryView(
            routeid="audit-export",
            method="GET",
            path="/audit/export",
            description="Export a paginated audit log slice as a structured downloadable payload.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="since", location="query", required=False, description="Start of export window (ISO 8601)."),
                ApiRouteFieldView(name="until", location="query", required=False, description="End of export window (ISO 8601)."),
                ApiRouteFieldView(name="format", location="query", required=False, description="Output format hint: json | csv."),
            ],
            responsefields=[
                ApiRouteFieldView(name="exportid", location="body", required=True, description="Export batch identifier."),
                ApiRouteFieldView(name="recordcount", location="body", required=True, description="Number of records included in the export."),
                ApiRouteFieldView(name="data", location="body", required=True, description="Array of audit records in the requested format."),
            ],
        ),
    ]

    telemetry_routes = [
        ApiRouteEntryView(
            routeid="telemetry-events",
            method="GET",
            path="/telemetry/events",
            description="Retrieve raw telemetry events emitted by the IronClaw guard and execution layers.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="limit", location="query", required=False, description="Page size."),
                ApiRouteFieldView(name="since", location="query", required=False, description="ISO 8601 lower bound."),
                ApiRouteFieldView(name="source", location="query", required=False, description="Filter by emitting component."),
            ],
            responsefields=[
                ApiRouteFieldView(name="events", location="body", required=True, description="Array of telemetry event records."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total matching events."),
            ],
        ),
        ApiRouteEntryView(
            routeid="telemetry-access-summary",
            method="GET",
            path="/telemetry/access-summary",
            description="Return aggregated access pattern and request volume telemetry for a given window.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="window", location="query", required=False, description="Aggregation window: 1h | 6h | 24h | 7d."),
            ],
            responsefields=[
                ApiRouteFieldView(name="totalrequests", location="body", required=True, description="Total requests in the window."),
                ApiRouteFieldView(name="blocked", location="body", required=True, description="Count of blocked actions."),
                ApiRouteFieldView(name="quarantined", location="body", required=True, description="Count of quarantined actions."),
                ApiRouteFieldView(name="reviewed", location="body", required=True, description="Count of actions that entered review queue."),
                ApiRouteFieldView(name="topactions", location="body", required=False, description="Most-frequent action types observed in the window."),
            ],
        ),
        ApiRouteEntryView(
            routeid="telemetry-session-risk",
            method="GET",
            path="/telemetry/session-risk",
            description="List aggregated risk scores across active and recently closed sessions.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="limit", location="query", required=False, description="Number of sessions to return."),
                ApiRouteFieldView(name="minscore", location="query", required=False, description="Minimum aggregated risk score filter."),
            ],
            responsefields=[
                ApiRouteFieldView(name="sessions", location="body", required=True, description="Array of session risk summary records."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total sessions in result set."),
            ],
        ),
    ]

    admin_routes = [
        ApiRouteEntryView(
            routeid="admin-health",
            method="GET",
            path="/admin/health",
            description="Return IronClaw system health status including subsystem readiness and uptime.",
            authrequired=True,
            requestfields=[],
            responsefields=[
                ApiRouteFieldView(name="status", location="body", required=True, description="overall | degraded | down."),
                ApiRouteFieldView(name="subsystems", location="body", required=True, description="Per-subsystem health map."),
                ApiRouteFieldView(name="uptime", location="body", required=False, description="Process uptime in seconds."),
                ApiRouteFieldView(name="version", location="body", required=False, description="IronClaw build version string."),
            ],
        ),
        ApiRouteEntryView(
            routeid="admin-operators-list",
            method="GET",
            path="/admin/operators",
            description="List all registered operator accounts with their assigned roles and status.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="role", location="query", required=False, description="Filter by operator role."),
                ApiRouteFieldView(name="active", location="query", required=False, description="Filter to active operators only when true."),
            ],
            responsefields=[
                ApiRouteFieldView(name="operators", location="body", required=True, description="Array of operator records."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total operator count."),
            ],
        ),
        ApiRouteEntryView(
            routeid="admin-operators-create",
            method="POST",
            path="/admin/operators",
            description="Register a new operator account with a scoped role and access level.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="email", location="body", required=True, description="Operator email address."),
                ApiRouteFieldView(name="role", location="body", required=True, description="Assigned role: analyst | admin | readonly."),
                ApiRouteFieldView(name="organizationid", location="body", required=False, description="Organization scope for the operator."),
            ],
            responsefields=[
                ApiRouteFieldView(name="operatorid", location="body", required=True, description="Newly created operator ID."),
                ApiRouteFieldView(name="email", location="body", required=True, description="Confirmed operator email."),
                ApiRouteFieldView(name="role", location="body", required=True, description="Assigned role."),
            ],
        ),
        ApiRouteEntryView(
            routeid="admin-api-keys-create",
            method="POST",
            path="/admin/api-keys",
            description="Generate a new scoped API key for a protected environment.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="label", location="body", required=True, description="Human-readable key label."),
                ApiRouteFieldView(name="scope", location="body", required=False, description="Key scope: guard | read | admin."),
                ApiRouteFieldView(name="expiresinseconds", location="body", required=False, description="TTL in seconds; omit for non-expiring keys."),
            ],
            responsefields=[
                ApiRouteFieldView(name="keyid", location="body", required=True, description="Newly issued key ID."),
                ApiRouteFieldView(name="key", location="body", required=True, description="Raw API key value (returned once only)."),
                ApiRouteFieldView(name="label", location="body", required=True, description="Confirmed key label."),
                ApiRouteFieldView(name="expiresat", location="body", required=False, description="Expiration timestamp if a TTL was set."),
            ],
        ),
        ApiRouteEntryView(
            routeid="admin-api-keys-list",
            method="GET",
            path="/admin/api-keys",
            description="List all API keys for the organisation with status and expiration metadata.",
            authrequired=True,
            requestfields=[
                ApiRouteFieldView(name="active", location="query", required=False, description="Filter to non-revoked keys when true."),
            ],
            responsefields=[
                ApiRouteFieldView(name="keys", location="body", required=True, description="Array of API key summary records (raw value not returned)."),
                ApiRouteFieldView(name="total", location="body", required=True, description="Total key count."),
            ],
        ),
    ]

    docs_routes = [
        ApiRouteEntryView(
            routeid="docs-quickstart",
            method="GET",
            path="/ui/docs/quickstart",
            description="Return the structured quickstart onboarding page payload for the IronClaw hosted documentation surface.",
            authrequired=False,
            requestfields=[],
            responsefields=[
                ApiRouteFieldView(name="steps", location="body", required=True, description="Ordered onboarding steps with code blocks."),
                ApiRouteFieldView(name="sdkoptions", location="body", required=True, description="Available SDK and language samples."),
                ApiRouteFieldView(name="keyendpoints", location="body", required=True, description="Key endpoint quick-reference list."),
                ApiRouteFieldView(name="checklist", location="body", required=True, description="Completion checklist items."),
            ],
        ),
        ApiRouteEntryView(
            routeid="docs-api-reference",
            method="GET",
            path="/ui/docs/api-reference",
            description="Return the full grouped API reference index for the IronClaw hosted documentation surface.",
            authrequired=False,
            requestfields=[],
            responsefields=[
                ApiRouteFieldView(name="groups", location="body", required=True, description="Tag-grouped route entries covering guard, policy, audit, telemetry, admin, and docs."),
                ApiRouteFieldView(name="totalgroupcount", location="body", required=True, description="Number of tag groups."),
                ApiRouteFieldView(name="totalroutecount", location="body", required=True, description="Total route entries across all groups."),
            ],
        ),
    ]

    return [
        ApiRouteGroupView(
            groupid="guard",
            label="Guard",
            description="Core enforcement layer: action evaluation, execution guarding, session risk, prompt scanning, and review queue management.",
            routes=guard_routes,
        ),
        ApiRouteGroupView(
            groupid="policy",
            label="Policy",
            description="Runtime policy configuration: enforcement mode, thresholds, and rule management.",
            routes=policy_routes,
        ),
        ApiRouteGroupView(
            groupid="audit",
            label="Audit",
            description="Tamper-evident audit log: event query, detail retrieval, and structured export.",
            routes=audit_routes,
        ),
        ApiRouteGroupView(
            groupid="telemetry",
            label="Telemetry",
            description="Observability layer: raw telemetry events, access summaries, and session risk aggregation.",
            routes=telemetry_routes,
        ),
        ApiRouteGroupView(
            groupid="admin",
            label="Admin",
            description="Platform control plane: system health, operator management, and API key lifecycle.",
            routes=admin_routes,
        ),
        ApiRouteGroupView(
            groupid="docs",
            label="Docs",
            description="Hosted documentation surfaces: quickstart and API reference index pages.",
            routes=docs_routes,
        ),
    ]


@router.get("/api-reference", response_model=ApiReferencePageResponse)
def get_docs_api_reference() -> ApiReferencePageResponse:
    groups = _build_groups()
    total_routes = sum(len(g.routes) for g in groups)

    return ApiReferencePageResponse(
        generatedat=_utc_now(),
        version="gen1",
        baseurl="http://127.0.0.1:8000",
        apikeyheadername="X-API-Key",
        totalgroupcount=len(groups),
        totalroutecount=total_routes,
        groups=groups,
    )
