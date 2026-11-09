# IronClaw-Security — API Reference

Base URL: `http://localhost:8000` (default local). All routes require the `X-API-Key` header unless otherwise noted.

---

## Authentication

All protected endpoints require:

X-API-Key: <your-ironclaw-api-key>

Unauthorized requests return `401 Unauthorized`.

---

## Verdicts

Every scan response includes a `verdict` field. Possible values:

| Verdict | Description |
|---------|-------------|
| `allow` | All applicable checks completed without a suspicious signal or error |
| `block` | A suspicious signal, matched rule, malicious classifier result, or scan error was detected |

Quarantine is an operational isolation/review state, not a final verdict.
Historical records may retain legacy verdict values.

---

## Routes

### Health

#### `GET /health`

Returns server health status. No authentication required.

**Response `200`**
```json
{ "status": "ok" }
```

---

### Scan

#### `POST /scan/`

Inspect a single prompt, tool call, or content string and return a verdict.

**Request body**
```json
{
  "content": "string",
  "context": "string",
  "agent_id": "string (optional)",
  "tool_name": "string (optional)",
  "tool_args": "object (optional)",
  "session_id": "string (optional)",
  "metadata": "object (optional)"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | Yes | The text, tool call, or prompt to inspect |
| `context` | string | Yes | Describes what is being scanned: `user_input`, `tool_call`, `agent_output`, `system_prompt` |
| `agent_id` | string | No | Identifier for the agent making the request |
| `tool_name` | string | No | Name of the tool being called (for `tool_call` context) |
| `tool_args` | object | No | Arguments passed to the tool |
| `session_id` | string | No | Session identifier for correlation |
| `metadata` | object | No | Arbitrary key-value pairs for context |

**Response `200`**
```json
{
  "scan_id": "uuid",
  "verdict": "allow | block",
  "reason": "string",
  "rule_id": "string | null",
  "confidence": 0.0,
  "timestamp": "ISO 8601",
  "metadata": {}
}
```

**Response `422`** — Validation error (malformed request body)

---

#### `POST /scan/batch`

Inspect multiple items in a single request.

**Request body**
```json
{
  "items": [
    {
      "content": "string",
      "context": "string",
      "agent_id": "string (optional)",
      "tool_name": "string (optional)",
      "tool_args": "object (optional)"
    }
  ]
}
```

**Response `200`**
```json
{
  "results": [
    {
      "scan_id": "uuid",
      "verdict": "allow | block",
      "reason": "string",
      "confidence": 0.0,
      "timestamp": "ISO 8601"
    }
  ]
}
```

---

### Policy

#### `GET /policy/`

List all active policies.

**Response `200`**
```json
{
  "policies": [
    {
      "policy_id": "string",
      "name": "string",
      "enabled": true,
      "rules": []
    }
  ]
}
```

---

#### `GET /policy/guard-bundle`

Returns the full guard bundle — the compiled set of active rules used at scan time. Useful for clients that want to cache and apply rules locally before hitting the scan endpoint.

**Response `200`**
```json
{
  "bundle_id": "string",
  "version": "string",
  "rules": [],
  "generated_at": "ISO 8601"
}
```

---

#### `POST /policy/`

Create or update a policy.

**Request body**
```json
{
  "name": "string",
  "enabled": true,
  "rules": []
}
```

**Response `200`**
```json
{
  "policy_id": "string",
  "name": "string",
  "enabled": true
}
```

---

### Audit

#### `GET /audit/`

Retrieve the audit log. Supports pagination and filtering.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Number of records to return (default 50) |
| `offset` | int | Pagination offset (default 0) |
| `verdict` | string | Filter by verdict value |
| `agent_id` | string | Filter by agent |
| `from` | ISO 8601 | Start of time range |
| `to` | ISO 8601 | End of time range |

**Response `200`**
```json
{
  "total": 0,
  "records": [
    {
      "scan_id": "uuid",
      "verdict": "string",
      "reason": "string",
      "agent_id": "string",
      "timestamp": "ISO 8601"
    }
  ]
}
```

---

### Telemetry

#### `POST /telemetry/`

Ingest a telemetry event from an agent or client.

**Request body**
```json
{
  "event_type": "string",
  "agent_id": "string",
  "payload": {},
  "timestamp": "ISO 8601 (optional)"
}
```

**Response `200`**
```json
{ "status": "received", "event_id": "uuid" }
```

---

#### `GET /telemetry/`

Query stored telemetry events.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_id` | string | Filter by agent |
| `event_type` | string | Filter by event type |
| `limit` | int | Number of records (default 50) |

**Response `200`**
```json
{
  "events": [
    {
      "event_id": "uuid",
      "event_type": "string",
      "agent_id": "string",
      "payload": {},
      "timestamp": "ISO 8601"
    }
  ]
}
```

---

### Review Queue

#### `GET /review/`

List items held in the operational review queue. Quarantine describes isolation
for review; it is not a final verdict.

**Response `200`**
```json
{
  "items": [
    {
      "review_id": "uuid",
      "scan_id": "uuid",
      "content": "string",
      "context": "string",
      "agent_id": "string",
      "submitted_at": "ISO 8601",
      "status": "pending | approved | rejected"
    }
  ]
}
```

---

#### `POST /review/{review_id}/approve`

Record approval of an item held for operational review. Review status is
separate from the original scan verdict; re-evaluate an action before execution.

**Response `200`**
```json
{ "review_id": "uuid", "status": "approved" }
```

---

#### `POST /review/{review_id}/reject`

Record rejection of an item held for operational review.

**Response `200`**
```json
{ "review_id": "uuid", "status": "rejected" }
```

---

### History

#### `GET /history/`

Retrieve scan history with filtering and pagination.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_id` | string | Filter by agent |
| `verdict` | string | Filter by verdict |
| `limit` | int | Records to return (default 50) |
| `offset` | int | Pagination offset |

**Response `200`**
```json
{
  "total": 0,
  "scans": [
    {
      "scan_id": "uuid",
      "content": "string",
      "verdict": "string",
      "reason": "string",
      "timestamp": "ISO 8601"
    }
  ]
}
```

---

### Incidents

#### `GET /incidents/`

List security incidents created from blocked scans that meet configured
incident criteria.

**Response `200`**
```json
{
  "incidents": [
    {
      "incident_id": "uuid",
      "scan_id": "uuid",
      "severity": "low | medium | high | critical",
      "verdict": "string",
      "agent_id": "string",
      "created_at": "ISO 8601",
      "resolved": false
    }
  ]
}
```

---

### Payments and wallet

The dashboard billing endpoints require an authenticated user. Package and
billing-owner details are resolved by the server; clients must not supply a
Stripe customer ID or wallet owner as proof of ownership.

#### `POST /billing/checkout/sessions`

Create a one-time Stripe Checkout session for a server-configured IronClaw
package. `packageId` is the canonical package ID (for example, `pkg_5000`);
the server selects the Stripe price and unit amount.

**Request body**
```json
{
  "packageId": "pkg_5000",
  "successUrl": "https://moving-forward.ca/dashboard?session_id={CHECKOUT_SESSION_ID}",
  "cancelUrl": "https://moving-forward.ca/dashboard?checkout=cancel",
  "quantity": 1
}
```

**Response `201`**
```json
{
  "session_id": "cs_...",
  "checkout_url": "https://checkout.stripe.com/...",
  "org_id": "authenticated-organization",
  "mode": "payment",
  "price_id": "price_...",
  "quantity": 1,
  "unit_credits": 5000
}
```

#### Stripe webhook configuration

Configure Stripe to send events to **`POST /webhooks/stripe`**. This is the
single canonical webhook destination; the legacy
`/billing/webhooks/stripe` and `/api/billing/webhooks/stripe` aliases exist
only for compatibility and should not be configured as additional Stripe
destinations. The endpoint verifies the raw request body against Stripe's
`Stripe-Signature` header. Signature rejection returns `400`; retryable
dispatch or fulfillment failures return `502` so Stripe can retry delivery.

#### Checkout status and recovery

The webhook is the normal fulfillment path. If the browser returns before the
webhook finishes, or fulfillment needs recovery, use these authenticated
endpoints:

1. `GET /billing/checkout/sessions/{session_id}/status` checks the Stripe
   session and reports `status`, `payment_status`, `unit_credits`, and
   `units_credited`.
2. If `payment_status` is `paid` but `units_credited` is missing or incomplete,
   call `POST /billing/checkout/sessions/{session_id}/reconcile`. This safely
   reruns the canonical fulfillment path, including wallet credit and paid
   install-key issuance.
3. Read `GET /billing/units/ledger` to confirm the resulting `balance` and
   ledger entries. A repeated reconcile for the same paid session is
   idempotent and must not credit units twice.
4. The dashboard's Refresh action calls authenticated
   `POST /billing/checkout/reconcile-recent`. It scans up to five Stripe pages
   of completed sessions, matches the authenticated billing owner, and runs
   the same verified fulfillment path. The response includes
   `sessions_reconciled`, `units_credited` verified from the wallet ledger,
   per-session `sessions` outcomes, and `truncated`. A `partial` status or
   `truncated: true` means not all candidate sessions were synced; the
   dashboard must report that rather than showing success. The scan requires
   valid signed IronClaw checkout metadata. Sessions without trusted metadata
   are not automatically credited; contact support with the Stripe Checkout
   Session ID for verification instead of paying again.

Example success response:

```json
{
  "status": "complete",
  "pages_scanned": 1,
  "sessions_scanned": 1,
  "sessions_matched": 1,
  "sessions_reconciled": 1,
  "units_credited": 5000,
  "sessions": [
    {
      "session_id": "cs_example",
      "status": "fulfilled",
      "units_credited": 5000
    }
  ],
  "truncated": false
}
```

`sessions` can also contain a `failed` status and an error for an individual
session. `status` is `partial` when any session fails or the scan is truncated,
and `no_paid_sessions_found` when no matching paid sessions were found.

Do not treat the browser redirect alone as proof of payment. Stripe's verified
session status is authoritative.

#### Saved payment methods

`POST /billing/payment-methods/setup-session` creates a hosted Stripe Setup
Checkout session without charging the customer. Its request body contains
`successUrl` and `cancelUrl`; URLs must use an allowed application host. The
`201` response contains `session_id`, `checkout_url`, `org_id`, and `mode`.
After setup, `GET /billing/payment-methods` retrieves the saved methods from
Stripe and returns redacted card details such as brand, last four digits, and
expiration. The dashboard displays them through
`GET /api/ui/billing/payment-methods?organizationid={organization_id}` (also
available at `/ui/billing/payment-methods`), whose `methods` array is sourced
from Stripe when a customer is mapped. A retrieval error is returned as `502`,
not an empty success response. Full card numbers are never stored by IronClaw.

#### Database deployment prerequisites

Apply and verify these migrations in the production Supabase project before
relying on durable wallet fulfillment and saved-card records:

- [`017_unit_wallets.sql`](../supabase/migrations/017_unit_wallets.sql) — persistent wallet balances and ledger.
- [`018_billing_payment_methods.sql`](../supabase/migrations/018_billing_payment_methods.sql) — redacted saved-payment-method metadata.
- [`019_atomic_unit_wallet_credits.sql`](../supabase/migrations/019_atomic_unit_wallet_credits.sql) — atomic, retry-safe wallet credits.

Check the Supabase migration history for all three before enabling this
workflow in production; repository presence alone does not confirm deployment.

---

## Error Shapes

All error responses follow this shape:

```json
{
  "detail": "string describing the error"
}
```

| Status | Meaning |
|--------|---------|
| `400` | Bad request — malformed input |
| `401` | Unauthorized — missing or invalid API key |
| `403` | Forbidden — valid key but insufficient permissions |
| `404` | Not found |
| `422` | Validation error — request body failed schema validation |
| `500` | Internal server error |