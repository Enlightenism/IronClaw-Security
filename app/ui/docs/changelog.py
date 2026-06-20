from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/docs",
    tags=["docs-changelog"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ChangelogAdditionView(BaseModel):
    itemid: str
    label: str
    description: str
    relatedroute: str | None = None


class ChangelogChangeView(BaseModel):
    itemid: str
    label: str
    before: str
    after: str
    reason: str
    relatedroute: str | None = None


class ChangelogDeprecationView(BaseModel):
    itemid: str
    label: str
    description: str
    replacedby: str | None = None
    sunsetversion: str | None = None


class ChangelogBreakingChangeView(BaseModel):
    itemid: str
    label: str
    description: str
    migrationnote: str
    affectedroutes: list[str] = Field(default_factory=list)


class ChangelogEntryView(BaseModel):
    version: str
    releasedate: str
    summary: str
    additions: list[ChangelogAdditionView] = Field(default_factory=list)
    changes: list[ChangelogChangeView] = Field(default_factory=list)
    deprecations: list[ChangelogDeprecationView] = Field(default_factory=list)
    breakingchanges: list[ChangelogBreakingChangeView] = Field(default_factory=list)


class ChangelogPageResponse(BaseModel):
    generatedat: str
    headline: str
    intro: str
    totalentries: int
    entries: list[ChangelogEntryView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_entries() -> list[ChangelogEntryView]:
    return [
        ChangelogEntryView(
            version="gen1.5.0",
            releasedate="2026-05-26",
            summary=("Webhook delivery layer, hosted documentation expansion, and policy violation event recording. Adds outbound webhook registration, HMAC-SHA256 signed delivery, three webhook event types, and two new hosted docs surfaces."),
            additions=[
                ChangelogAdditionView(
                    itemid="add-webhook-registration",
                    label="POST /admin/webhooks — outbound webhook registration",
                    description=("Operators can now register HTTPS endpoints to receive outbound payloads for scan_verdict_issued, quarantine_triggered, and policy_violation_recorded events. Each registration generates a unique HMAC-SHA256 signing key returned once at creation."),
                    relatedroute="POST /admin/webhooks",
                ),
                ChangelogAdditionView(
                    itemid="add-webhook-list",
                    label="GET /admin/webhooks — list registered webhooks",
                    description=("Returns all registered webhook endpoints for the organization with status, subscribed event types, label, and masked signing key suffix. Raw signing key values are never returned after the creation response."),
                    relatedroute="GET /admin/webhooks",
                ),
                ChangelogAdditionView(
                    itemid="add-webhook-update",
                    label="PATCH /admin/webhooks/{webhookid} — update or re-enable a webhook",
                    description=("Allows operators to update the webhook URL, subscribed event list, label, and active status. Use this endpoint to re-enable a webhook that was automatically disabled after 10 consecutive delivery failures."),
                    relatedroute="PATCH /admin/webhooks/{webhookid}",
                ),
                ChangelogAdditionView(
                    itemid="add-webhook-test",
                    label="POST /admin/webhooks/{webhookid}/test — fire synthetic test delivery",
                    description=("Sends a signed synthetic payload for each subscribed event type to the registered endpoint. Signatures are computed with the live signing key so receiver-side verification logic can be validated end-to-end before going live."),
                    relatedroute="POST /admin/webhooks/{webhookid}/test",
                ),
                ChangelogAdditionView(
                    itemid="add-webhook-deliveries",
                    label="GET /admin/webhooks/{webhookid}/deliveries — delivery log",
                    description=("Returns the per-delivery log for a webhook showing event type, HTTP response status, attempt number, timestamp, and success or failure status for every delivery attempt including retries."),
                    relatedroute="GET /admin/webhooks/{webhookid}/deliveries",
                ),
                ChangelogAdditionView(
                    itemid="add-webhook-event-scan-verdict",
                    label="Outbound event: scan_verdict_issued",
                    description=(
                        "Fires after every guard action or guard execute evaluation that produces a "
                        "warn, quarantine, or block verdict. Delivers the full decision payload including "
                        "actiontype, target, riskscore, verdict, reason, policyversion, sessionid, "
                        "and metadata. Allow verdicts suppressed by default."
                    ),
                    relatedroute="POST /guard/action",
                ),
                ChangelogAdditionView(
                    itemid="add-webhook-event-quarantine",
                    label="Outbound event: quarantine_triggered",
                    description=("Fires when a guard evaluation produces a quarantine verdict and the action is isolated. Delivers quarantine ID, action details, risk score, and requiresoperatorrelease flag. Fires in addition to scan_verdict_issued for the same event."),
                    relatedroute="POST /guard/execute",
                ),
                ChangelogAdditionView(
                    itemid="add-webhook-event-policy-violation",
                    label="Outbound event: policy_violation_recorded",
                    description=(
                        "Fires when a guard evaluation matches a named policy rule — an action type "
                        "rule or target pattern rule — in addition to or instead of a numeric threshold. "
                        "Delivers violation ID, matched rule ID and label, rule type, and verdict. "
                        "Score-only threshold decisions that do not match a named rule do not fire this event."
                    ),
                    relatedroute="POST /guard/action",
                ),
                ChangelogAdditionView(
                    itemid="add-docs-webhooks",
                    label="GET /ui/docs/webhooks — hosted webhooks documentation surface",
                    description=("New hosted docs page covering webhook registration, all three outbound event types with exact payload shapes, HMAC-SHA256 signature verification with Python and curl examples, retry and failure behavior, and a six-step testing workflow."),
                    relatedroute="GET /ui/docs/webhooks",
                ),
                ChangelogAdditionView(
                    itemid="add-docs-changelog",
                    label="GET /ui/docs/changelog — hosted changelog documentation surface",
                    description=("Single source of truth for all versioned IronClaw changes. Each entry covers additions, behavior changes, deprecations, and breaking changes with migration notes. Entries ordered newest-first."),
                    relatedroute="GET /ui/docs/changelog",
                ),
            ],
            changes=[
                ChangelogChangeView(
                    itemid="change-webhook-auto-disable",
                    label="Webhook auto-disable after consecutive delivery failures",
                    before="No automatic endpoint disable on repeated delivery failure.",
                    after=("After 10 consecutive delivery failures across any event type for the same webhook, the webhook is automatically set to inactive and a webhook_auto_disabled audit event is emitted."),
                    reason=("Prevents unbounded retry accumulation against permanently unreachable endpoints and surfaces the failure to operators via the audit log."),
                    relatedroute="GET /admin/webhooks/{webhookid}/deliveries",
                ),
                ChangelogChangeView(
                    itemid="change-guard-telemetry-webhook-emit",
                    label="Guard layer now emits webhook delivery triggers on non-allow verdicts",
                    before="Guard verdict outcomes were written to audit and telemetry only.",
                    after=("Non-allow guard verdicts now also trigger outbound webhook delivery for registered scan_verdict_issued subscribers. Quarantine verdicts additionally trigger quarantine_triggered deliveries. Named-rule matches additionally trigger policy_violation_recorded deliveries."),
                    reason=("Enables real-time SIEM, alerting, and compliance pipeline integration without requiring polling of the audit or telemetry endpoints."),
                    relatedroute="POST /guard/action",
                ),
            ],
            deprecations=[],
            breakingchanges=[],
        ),
        ChangelogEntryView(
            version="gen1.4.0",
            releasedate="2026-05-20",
            summary=("Telemetry guide and policy guide documentation surfaces. Adds hosted docs pages for the telemetry layer and the policy configuration layer."),
            additions=[
                ChangelogAdditionView(
                    itemid="add-docs-telemetry-guide",
                    label="GET /ui/docs/telemetry-guide — hosted telemetry documentation surface",
                    description=("Covers telemetry architecture, all emitted event types with schema shapes, aggregation windows, session risk scoring, and integration patterns for SIEM and observability pipelines."),
                    relatedroute="GET /ui/docs/telemetry-guide",
                ),
                ChangelogAdditionView(
                    itemid="add-docs-policy-guide",
                    label="GET /ui/docs/policy-guide — hosted policy documentation surface",
                    description=("Covers policy enforcement modes, threshold configuration, rule types (action type rules and target pattern rules), priority ordering, and policy change audit trail."),
                    relatedroute="GET /ui/docs/policy-guide",
                ),
            ],
            changes=[
                ChangelogChangeView(
                    itemid="change-policy-quarantine-threshold",
                    label="quarantinethreshold added to policy status response",
                    before="Policy status returned reviewthreshold and blockthreshold only.",
                    after=("Policy status now includes quarantinethreshold as an optional field alongside reviewthreshold and blockthreshold."),
                    reason=("Quarantine verdict behavior requires its own configurable threshold distinct from the review and block thresholds."),
                    relatedroute="GET /policy/status",
                ),
            ],
            deprecations=[],
            breakingchanges=[],
        ),
        ChangelogEntryView(
            version="gen1.3.0",
            releasedate="2026-05-12",
            summary=("Authentication documentation surface and API key scope expansion. Adds the hosted authentication docs page and introduces the admin:write scope."),
            additions=[
                ChangelogAdditionView(
                    itemid="add-docs-authentication",
                    label="GET /ui/docs/authentication — hosted authentication documentation surface",
                    description=("Covers API key creation, the X-API-Key header contract, available scopes (guard, read, admin, admin:write), key rotation workflow, and key expiration behavior."),
                    relatedroute="GET /ui/docs/authentication",
                ),
                ChangelogAdditionView(
                    itemid="add-scope-admin-write",
                    label="New API key scope: admin:write",
                    description=("Adds admin:write as a distinct scope for operator actions that mutate platform state — webhook registration, operator creation, and policy updates. Separates read-only admin inspection (admin scope) from mutating admin operations (admin:write scope)."),
                    relatedroute="POST /admin/api-keys",
                ),
            ],
            changes=[
                ChangelogChangeView(
                    itemid="change-api-key-prefix",
                    label="API key format prefix standardized to ic_prod_",
                    before="API keys were generated without a fixed prefix.",
                    after="All newly generated API keys carry the ic_prod_ prefix for visual identification.",
                    reason=("Standardized prefix enables reliable secret-scanning rules and prevents accidental exposure by making IronClaw keys identifiable in code review and log scrubbing pipelines."),
                    relatedroute="POST /admin/api-keys",
                ),
            ],
            deprecations=[],
            breakingchanges=[],
        ),
        ChangelogEntryView(
            version="gen1.2.0",
            releasedate="2026-05-05",
            summary=("API reference documentation surface, audit export endpoint, and session risk telemetry. Adds the hosted API reference docs page and two new data access endpoints."),
            additions=[
                ChangelogAdditionView(
                    itemid="add-docs-api-reference",
                    label="GET /ui/docs/api-reference — hosted API reference documentation surface",
                    description=("Full grouped route index covering guard, policy, audit, telemetry, admin, and docs endpoint groups with request and response field schemas."),
                    relatedroute="GET /ui/docs/api-reference",
                ),
                ChangelogAdditionView(
                    itemid="add-audit-export",
                    label="GET /audit/export — structured audit log export",
                    description=("Exports a bounded audit log slice as a structured payload. Supports since and until window parameters and a format hint (json | csv)."),
                    relatedroute="GET /audit/export",
                ),
                ChangelogAdditionView(
                    itemid="add-telemetry-session-risk",
                    label="GET /telemetry/session-risk — session risk aggregation",
                    description=("Returns aggregated risk scores across active and recently closed sessions with a minscore filter for high-risk session surfacing."),
                    relatedroute="GET /telemetry/session-risk",
                ),
            ],
            changes=[],
            deprecations=[],
            breakingchanges=[],
        ),
        ChangelogEntryView(
            version="gen1.1.0",
            releasedate="2026-04-28",
            summary=("Quickstart documentation surface, prompt scan endpoint, and guard session risk. Adds the first hosted docs page and two new guard-layer endpoints."),
            additions=[
                ChangelogAdditionView(
                    itemid="add-docs-quickstart",
                    label="GET /ui/docs/quickstart — hosted quickstart documentation surface",
                    description=("Covers API key creation, the first guarded execution request, review and audit surface inspection, and policy tuning. Includes curl, Python, and JavaScript SDK samples."),
                    relatedroute="GET /ui/docs/quickstart",
                ),
                ChangelogAdditionView(
                    itemid="add-guard-scan-prompt",
                    label="POST /guard/scan/prompt — prompt injection and exfiltration detection",
                    description=("Runs prompt-injection and data-exfiltration detection against a raw prompt string and returns a threatdetected flag, threattype classification, and a confidence score."),
                    relatedroute="POST /guard/scan/prompt",
                ),
                ChangelogAdditionView(
                    itemid="add-guard-session-risk",
                    label="GET /guard/session/{sessionid}/risk — session risk profile",
                    description=("Returns the current risk profile and accumulated threat signals for an active session, including aggregated risk score and recommended action."),
                    relatedroute="GET /guard/session/{sessionid}/risk",
                ),
            ],
            changes=[
                ChangelogChangeView(
                    itemid="change-guard-action-decision-shape",
                    label="POST /guard/action-decision response shape updated",
                    before="Response returned verdict and eventid fields only.",
                    after="Response now returns decision (renamed from verdict), confidence, and eventid.",
                    reason=("Renaming verdict to decision on the decision-only endpoint distinguishes it from the full guard/action verdict response and aligns field naming with orchestration layer conventions."),
                    relatedroute="POST /guard/action-decision",
                ),
            ],
            deprecations=[],
            breakingchanges=[
                ChangelogBreakingChangeView(
                    itemid="break-guard-action-decision-verdict-rename",
                    label="POST /guard/action-decision: verdict field renamed to decision",
                    description=("The verdict field in the POST /guard/action-decision response has been renamed to decision. Clients that read response.verdict on this endpoint will receive undefined and must be updated."),
                    migrationnote=("Update all consumers of POST /guard/action-decision to read response.decision instead of response.verdict. The POST /guard/action endpoint is unaffected — its response field remains verdict."),
                    affectedroutes=["POST /guard/action-decision"],
                ),
            ],
        ),
        ChangelogEntryView(
            version="gen1.0.0",
            releasedate="2026-04-14",
            summary=("Initial Gen1 release. Core guard layer, policy enforcement, audit log, telemetry layer, and admin control plane."),
            additions=[
                ChangelogAdditionView(
                    itemid="add-guard-action",
                    label="POST /guard/action — core guard action evaluation",
                    description=("Evaluates a proposed agent action against runtime policy and returns an allow, warn, quarantine, or block verdict with reason and policy ID."),
                    relatedroute="POST /guard/action",
                ),
                ChangelogAdditionView(
                    itemid="add-guard-action-decision",
                    label="POST /guard/action-decision — decision-only guard response",
                    description=("Returns a decision-focused guard response optimized for orchestration layer consumption with a confidence score."),
                    relatedroute="POST /guard/action-decision",
                ),
                ChangelogAdditionView(
                    itemid="add-guard-execute",
                    label="POST /guard/execute — guarded runtime execution",
                    description=("Submits a guarded runtime execution request. IronClaw evaluates the execution plan before allowing it to proceed, returning a verdict and execution record ID."),
                    relatedroute="POST /guard/execute",
                ),
                ChangelogAdditionView(
                    itemid="add-guard-reviews-pending",
                    label="GET /guard/reviews/pending — review queue",
                    description="Lists all actions currently queued for analyst review with pagination support.",
                    relatedroute="GET /guard/reviews/pending",
                ),
                ChangelogAdditionView(
                    itemid="add-guard-reviews-decide",
                    label="POST /guard/reviews/decide — analyst decision submission",
                    description=("Submits an analyst approve or deny decision for a queued review item and emits a linked audit event."),
                    relatedroute="POST /guard/reviews/decide",
                ),
                ChangelogAdditionView(
                    itemid="add-guard-audit-events",
                    label="GET /guard/audit/events — guard-layer audit events",
                    description=("Retrieves recent guard-layer audit events for policy, review, and runtime outcomes with since timestamp filtering."),
                    relatedroute="GET /guard/audit/events",
                ),
                ChangelogAdditionView(
                    itemid="add-policy-status",
                    label="GET /policy/status — active runtime policy",
                    description=("Returns the currently active runtime policy configuration including enforcement mode, reviewthreshold, and blockthreshold."),
                    relatedroute="GET /policy/status",
                ),
                ChangelogAdditionView(
                    itemid="add-policy-update",
                    label="POST /policy/update — apply policy changes",
                    description=("Applies new enforcement thresholds and mode to the active runtime policy and emits a policy change audit event."),
                    relatedroute="POST /policy/update",
                ),
                ChangelogAdditionView(
                    itemid="add-policy-rules",
                    label="GET /policy/rules — active policy rules",
                    description=("Lists all active policy rules with their conditions, verdicts, and priority ordering."),
                    relatedroute="GET /policy/rules",
                ),
                ChangelogAdditionView(
                    itemid="add-audit-events",
                    label="GET /audit/events — audit log query",
                    description=("Queries the audit log for security events, policy decisions, and operator actions with limit, offset, since, and eventtype filters."),
                    relatedroute="GET /audit/events",
                ),
                ChangelogAdditionView(
                    itemid="add-audit-event-detail",
                    label="GET /audit/events/{eventid} — audit event detail",
                    description="Retrieves the full detail record for a single audit event by its ID.",
                    relatedroute="GET /audit/events/{eventid}",
                ),
                ChangelogAdditionView(
                    itemid="add-telemetry-events",
                    label="GET /telemetry/events — raw telemetry events",
                    description=("Retrieves raw telemetry events emitted by the IronClaw guard and execution layers with limit, since, and source filters."),
                    relatedroute="GET /telemetry/events",
                ),
                ChangelogAdditionView(
                    itemid="add-telemetry-access-summary",
                    label="GET /telemetry/access-summary — access pattern aggregation",
                    description=("Returns aggregated access pattern and request volume telemetry for a configurable window (1h | 6h | 24h | 7d)."),
                    relatedroute="GET /telemetry/access-summary",
                ),
                ChangelogAdditionView(
                    itemid="add-admin-health",
                    label="GET /admin/health — system health",
                    description=("Returns IronClaw system health status including per-subsystem readiness, uptime, and build version."),
                    relatedroute="GET /admin/health",
                ),
                ChangelogAdditionView(
                    itemid="add-admin-operators",
                    label="GET /admin/operators and POST /admin/operators — operator management",
                    description=("Lists all registered operator accounts and creates new operator accounts with scoped roles (analyst | admin | readonly)."),
                    relatedroute="POST /admin/operators",
                ),
                ChangelogAdditionView(
                    itemid="add-admin-api-keys",
                    label="GET /admin/api-keys and POST /admin/api-keys — API key lifecycle",
                    description=("Generates new scoped API keys and lists existing keys with status and expiration metadata. Raw key value returned once at creation only."),
                    relatedroute="POST /admin/api-keys",
                ),
            ],
            changes=[],
            deprecations=[],
            breakingchanges=[],
        ),
    ]


@router.get("/changelog", response_model=ChangelogPageResponse)
def get_docs_changelog() -> ChangelogPageResponse:
    entries = _build_entries()
    return ChangelogPageResponse(
        generatedat=_utc_now(),
        headline="IronClaw Changelog",
        intro=(
            "This is the single source of truth for all versioned IronClaw changes. "
            "Every entry covers additions (new endpoints, new policy fields, new verdict types), "
            "behavior changes (modified logic, renamed fields), deprecations, and breaking changes "
            "with migration notes. "
            "Entries are ordered newest-first. "
            "Breaking changes always include affected routes and a concrete migration note."
        ),
        totalentries=len(entries),
        entries=entries,
        notes=[
            "Version tags follow a gen{major}.{minor}.{patch} scheme reflecting IronClaw generation and feature milestones.",
            "Breaking changes are always accompanied by affected route lists and migration notes. Never upgrade past a breaking change entry without reading its migrationnote.",
            "Deprecation entries include a replacedby field pointing to the successor endpoint or field and a sunsetversion indicating when the deprecated item will be removed.",
            "All values reflect the current local-first Gen1 build. Cloud-hosted changelog entries, RSS feed delivery, and SDK version cross-references will expand in later generations.",
        ],
    )
