# IronClaw-Security — Security Model

This document describes the architectural trust model, enforcement layers, and runtime boundaries that IronClaw-Security uses to protect agentic systems.

---

## Design Philosophy

IronClaw operates on a **fail-closed** principle: when in doubt, block. Blocked
artifacts may also be isolated for review, but quarantine is an operational
workflow state rather than a verdict. Every action taken by an agent, tool, or
LLM is treated as untrusted until it passes inspection. Trust is earned at the
infrastructure level — not assumed at the prompt level.

The system is designed to answer one question at every decision point:

> "Is it safe to let this action proceed?"

---

## Trust Layers

IronClaw enforces security across four layers:

┌────────────────────────────────────────────────────┐
│ Layer 1 — Input Inspection │
│ Prompt injection, PII detection, pattern matching │
├────────────────────────────────────────────────────┤
│ Layer 2 — Policy Enforcement │
│ Rule evaluation, context-aware policy gates │
├────────────────────────────────────────────────────┤
│ Layer 3 — Tool Call Guarding │
│ Tool name allowlist, argument validation │
├────────────────────────────────────────────────────┤
│ Layer 4 — Runtime Boundaries │
│ Sandboxed execution, resource limits │
└────────────────────────────────────────────────────┘


Every scan passes through all applicable layers before a verdict is issued.

---

## Verdict Pipeline

Each scan produces exactly one final verdict: `allow` or `block`. Pattern,
heuristic, policy, tool-validation, and data-leakage signals block at every
severity. When Prompt Guard is enabled, it must run successfully and return
`BENIGN`; a malicious result or classifier failure blocks. An allow is issued
only when all applicable checks complete without a match or error. A block has
a risk score at or above `RISK_THRESHOLD_BLOCK_MIN`.

Blocked artifacts may be isolated in a review workflow. That operational state
does not create another verdict.

---

## Prompt Injection Detection

IronClaw detects prompt injection at the input layer using:

- **Pattern matching** — known injection signatures (role override instructions, jailbreak templates, instruction injection via delimiter abuse)
- **Semantic analysis** — content that attempts to redefine the agent's context, persona, or operating boundaries
- **Nested instruction detection** — injected instructions embedded in retrieved documents, tool outputs, or user-supplied data

Detected injections receive a `block` verdict with `reason` set to the matched pattern identifier.

---

## Data Leakage Prevention

Outbound content (agent outputs, tool results) is scanned for:

- **PII** — names, emails, phone numbers, SSNs, addresses
- **Credentials** — API keys, tokens, passwords, private keys
- **Sensitive business data** — patterns defined in policy rules

Any detected leakage receives a `block` verdict, regardless of severity.

---

## Policy Enforcement

Policies are composable rule sets stored in Supabase and loaded at startup (with hot-reload support). Each policy contains:

- **Rules** — conditions (pattern, semantic, context, agent_id); any matched
  detection rule results in `block`
- **Scope** — global, per-agent, or per-session
- **Priority** — rules are evaluated in priority order; first match wins

The guard bundle (`GET /policy/guard-bundle`) is the compiled, versioned snapshot of all active rules. Clients may cache it for local pre-filtering before calling `/scan/`.

---

## Tool Call Guarding

When `context = tool_call`, IronClaw applies additional validation:

- **Tool allowlist** — only explicitly permitted tools may be invoked
- **Argument schema validation** — tool arguments are validated against defined schemas
- **Privilege escalation detection** — argument patterns that attempt to exceed declared tool scope are flagged
- **Blocked tool patterns** — tools that match suspicious high-risk patterns
  (e.g., shell execution, filesystem traversal) are blocked; allowlists do not
  override a detected signal

---

## Sandboxed Execution

Code execution and tool dispatch occur inside runtime boundaries:

- Process isolation — agent code runs in a restricted subprocess
- Resource limits — CPU time, memory, and I/O are capped
- Network policy — outbound connections are blocked by default unless explicitly allowed
- Filesystem scope — access is restricted to declared working directories

---

## Review Workflow

Blocked items may be placed in operational quarantine and held in the review
queue. Quarantine is not a verdict; review status is recorded separately:

- **Approve** — records the review decision; a subsequent action must pass the
  applicable guard checks before execution
- **Reject** — the held action is permanently blocked and logged as a security incident

Review decisions are audited with reviewer identity and timestamp.

---

## Audit Log

Every scan, verdict, policy decision, review action, and incident is written to the audit log in Supabase. Audit records are:

- **Immutable** — records are append-only; no update or delete is permitted
- **Timestamped** — all records carry server-side ISO 8601 timestamps
- **Correlated** — `scan_id`, `agent_id`, `session_id`, and `review_id` are propagated across records for full traceability

---

## Telemetry

IronClaw emits a real-time event stream via the `/telemetry/` endpoint. Events include:

- `scan.completed` — every scan result
- `verdict.block` — every blocked action
- `verdict.quarantine` — retained for historical and compatibility records; it
  is not a new verdict
- `review.approved` / `review.rejected` — review decisions
- `incident.created` — new incidents
- `policy.updated` — policy changes

Telemetry is designed for ingestion into observability pipelines (Datadog, Grafana, custom SIEM).

---

## Incident Management

Blocked scans that meet configured incident criteria are promoted to incidents.
Incident severity is independent of the final allow/block verdict and continues
to describe the detected signal and its impact.

Incidents remain open until explicitly resolved by a reviewer.

---

## Authentication

All API endpoints (except `/health`) require `X-API-Key` authentication. Keys are validated against the Supabase `api_keys` table. Key rotation does not require a server restart.