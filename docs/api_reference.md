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