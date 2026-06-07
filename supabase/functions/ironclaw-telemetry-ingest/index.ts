import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};

const JSON_HEADERS: Record<string, string> = {
  ...CORS_HEADERS,
  "Content-Type": "application/json",
};

const VALID_METRIC_TYPES = new Set([
  "counter",
  "gauge",
  "histogram",
  "event",
  "status",
]);

const MAX_BATCH_SIZE = 500;

interface TelemetryEventInput {
  event_key: string;
  metric_name: string;
  metric_type: string;
  source: string;
  org_id?: string | null;
  value_numeric?: number | null;
  value_text?: string | null;
  unit?: string;
  dimensions?: Record<string, unknown>;
  captured_at?: string;
  retention_until?: string | null;
}

interface ValidationError {
  index: number;
  event_key: string | undefined;
  error: string;
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ ok: false, error: message }, status);
}

function isIsoTimestamp(val: string): boolean {
  return !isNaN(Date.parse(val));
}

function validateEvent(
  item: unknown,
  index: number,
): { valid: true; row: TelemetryEventInput } | { valid: false; error: ValidationError } {
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    return {
      valid: false,
      error: { index, event_key: undefined, error: "Item must be a non-null object" },
    };
  }

  const e = item as Record<string, unknown>;

  if (typeof e.event_key !== "string" || e.event_key.trim() === "") {
    return {
      valid: false,
      error: { index, event_key: undefined, error: "event_key must be a non-empty string" },
    };
  }

  if (typeof e.metric_name !== "string" || e.metric_name.trim() === "") {
    return {
      valid: false,
      error: { index, event_key: e.event_key as string, error: "metric_name must be a non-empty string" },
    };
  }

  if (typeof e.metric_type !== "string" || !VALID_METRIC_TYPES.has(e.metric_type)) {
    return {
      valid: false,
      error: {
        index,
        event_key: e.event_key as string,
        error: `metric_type must be one of: ${[...VALID_METRIC_TYPES].join(", ")}`,
      },
    };
  }

  if (typeof e.source !== "string" || e.source.trim() === "") {
    return {
      valid: false,
      error: { index, event_key: e.event_key as string, error: "source must be a non-empty string" },
    };
  }

  if (
    e.value_numeric !== undefined &&
    e.value_numeric !== null &&
    typeof e.value_numeric !== "number"
  ) {
    return {
      valid: false,
      error: { index, event_key: e.event_key as string, error: "value_numeric must be a number or null" },
    };
  }

  if (
    e.value_text !== undefined &&
    e.value_text !== null &&
    typeof e.value_text !== "string"
  ) {
    return {
      valid: false,
      error: { index, event_key: e.event_key as string, error: "value_text must be a string or null" },
    };
  }

  if (
    e.captured_at !== undefined &&
    (typeof e.captured_at !== "string" || !isIsoTimestamp(e.captured_at as string))
  ) {
    return {
      valid: false,
      error: { index, event_key: e.event_key as string, error: "captured_at must be a valid ISO 8601 timestamp" },
    };
  }

  if (
    e.retention_until !== undefined &&
    e.retention_until !== null &&
    (typeof e.retention_until !== "string" || !isIsoTimestamp(e.retention_until as string))
  ) {
    return {
      valid: false,
      error: { index, event_key: e.event_key as string, error: "retention_until must be a valid ISO 8601 timestamp or null" },
    };
  }

  if (
    e.dimensions !== undefined &&
    e.dimensions !== null &&
    (typeof e.dimensions !== "object" || Array.isArray(e.dimensions))
  ) {
    return {
      valid: false,
      error: { index, event_key: e.event_key as string, error: "dimensions must be a non-array object or omitted" },
    };
  }

  const now = new Date().toISOString();

  return {
    valid: true,
    row: {
      event_key: e.event_key as string,
      metric_name: (e.metric_name as string).trim(),
      metric_type: e.metric_type as string,
      source: (e.source as string).trim(),
      org_id: typeof e.org_id === "string" ? e.org_id.trim() || null : null,
      value_numeric: typeof e.value_numeric === "number" ? e.value_numeric : null,
      value_text: typeof e.value_text === "string" ? e.value_text : null,
      unit: typeof e.unit === "string" ? e.unit : "",
      dimensions: (e.dimensions as Record<string, unknown>) ?? {},
      captured_at: typeof e.captured_at === "string" ? e.captured_at : now,
      retention_until:
        typeof e.retention_until === "string" ? e.retention_until : null,
    },
  };
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return errorResponse("Telemetry ingest service misconfigured", 500);
  }

  let rawBody: unknown;
  try {
    rawBody = await req.json();
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  if (!Array.isArray(rawBody)) {
    return errorResponse("Body must be a JSON array of telemetry events", 400);
  }

  if (rawBody.length === 0) {
    return jsonResponse({ ok: true, inserted: 0, duplicates: 0, validation_errors: [] }, 200);
  }

  if (rawBody.length > MAX_BATCH_SIZE) {
    return errorResponse(
      `Batch size exceeds maximum of ${MAX_BATCH_SIZE} events per request`,
      413,
    );
  }

  const validRows: TelemetryEventInput[] = [];
  const validationErrors: ValidationError[] = [];

  for (let i = 0; i < rawBody.length; i++) {
    const result = validateEvent(rawBody[i], i);
    if (result.valid) {
      validRows.push(result.row);
    } else {
      validationErrors.push(result.error);
    }
  }

  if (validRows.length === 0) {
    return jsonResponse(
      {
        ok: false,
        error: "All events failed validation",
        inserted: 0,
        duplicates: 0,
        validation_errors: validationErrors,
      },
      422,
    );
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  const { data: inserted, error: upsertError } = await supabase
    .from("telemetry_events")
    .upsert(validRows, {
      onConflict: "event_key",
      ignoreDuplicates: true,
    })
    .select("event_key");

  if (upsertError) {
    console.error("ironclaw-telemetry-ingest: upsert failed", upsertError.message);
    return errorResponse("Telemetry ingest write failed", 500);
  }

  const insertedCount = inserted?.length ?? 0;
  const duplicateCount = validRows.length - insertedCount;

  return jsonResponse(
    {
      ok: true,
      received: rawBody.length,
      valid: validRows.length,
      inserted: insertedCount,
      duplicates: duplicateCount,
      validation_errors: validationErrors.length > 0 ? validationErrors : undefined,
    },
    200,
  );
});
