# IronClaw-Security — Security Model

This document describes the architectural trust model, enforcement layers, and runtime boundaries that IronClaw-Security uses to protect agentic systems.

---

## Design Philosophy

IronClaw operates on a **fail-closed** principle: when in doubt, quarantine or block. Every action taken by an agent, tool, or LLM is treated as untrusted until it passes inspection. Trust is earned at the infrastructure level — not assumed at the prompt level.

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

Each scan produces exactly one verdict. The pipeline evaluates layers in order and escalates as violations are found:

Input
│ ▼ Prompt Injection Check
│ violation → block
▼ Data Leakage / PII Check
│ violation → block or quarantine
▼ Policy Rule Evaluation
│ rule match → allow / warn / quarantine / block
▼ Tool Call Validation (if context = tool_call)
│ blocked tool or invalid args → block
▼ Confidence Threshold Check
│ low confidence + high risk → quarantine
▼ Verdict Issued


The first layer to produce a `block` short-circuits the pipeline. `quarantine` escalates to the review queue. `warn` continues but is logged as a flagged event. `allow` clears the full pipeline.

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

Detected leakage receives a `quarantine` or `block` verdict depending on severity.

---

## Policy Enforcement

Policies are composable rule sets stored in Supabase and loaded at startup (with hot-reload support). Each policy contains:

- **Rules** — conditions (pattern, semantic, context, agent_id) and resulting verdict
- **Scope** — global, per-agent, or per-session
- **Priority** — rules are evaluated in priority order; first match wins

The guard bundle (`GET /policy/guard-bundle`) is the compiled, versioned snapshot of all active rules. Clients may cache it for local pre-filtering before calling `/scan/`.

---

## Tool Call Guarding

When `context = tool_call`, IronClaw applies additional validation:

- **Tool allowlist** — only explicitly permitted tools may be invoked
- **Argument schema validation** — tool arguments are validated against defined schemas
- **Privilege escalation detection** — argument patterns that attempt to exceed declared tool scope are flagged
- **Blocked tool patterns** — tools that match high-risk name patterns (e.g., shell execution, filesystem traversal) require explicit policy allow rules

---

## Sandboxed Execution

Code execution and tool dispatch occur inside runtime boundaries:

- Process isolation — agent code runs in a restricted subprocess
- Resource limits — CPU time, memory, and I/O are capped
- Network policy — outbound connections are blocked by default unless explicitly allowed
- Filesystem scope — access is restricted to declared working directories

---

## Review Workflow

Items receiving a `quarantine` verdict are not executed. They are placed in the review queue and held until a human reviewer takes action:

- **Approve** — the held action is released and may proceed
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
- `verdict.quarantine` — every quarantine event
- `review.approved` / `review.rejected` — review decisions
- `incident.created` — new incidents
- `policy.updated` — policy changes

Telemetry is designed for ingestion into observability pipelines (Datadog, Grafana, custom SIEM).

---

## Incident Management

Scans that escalate to `block` or `quarantine` and meet severity thresholds are promoted to incidents. Incidents carry a severity classification:

| Severity | Trigger |
|----------|---------|
| `low` | Single warn escalation |
| `medium` | Repeated warns from same agent or session |
| `high` | Block verdict with high-confidence rule match |
| `critical` | Block verdict matching known attack signature |

Incidents remain open until explicitly resolved by a reviewer.

---

## Authentication

All API endpoints (except `/health`) require `X-API-Key` authentication. Keys are validated against the Supabase `api_keys` table. Key rotation does not require a server restart.