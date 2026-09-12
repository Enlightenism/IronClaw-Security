import { createClient, SupabaseClient } from "npm:@supabase/supabase-js@2";

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

const DISPATCH_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = [500, 1500, 3000];

interface DispatchRequest {
  id?: string;
  event_id?: string;
  event_type: string;
  payload: Record<string, unknown>;
  tenant_id?: string;
  checkout_session_id?: string;
  purchase_id?: string;
  customer_id?: string;
  owner_key?: string;
}

interface StripeWebhookEventRow {
  id: string;
  stripe_event_id: string;
  event_type: string;
  checkout_session_id?: string | null;
  purchase_id?: string | null;
  customer_id?: string | null;
  owner_key?: string | null;
  status: string;
}

interface WebhookSubscription {
  id: string;
  tenant_id: string;
  url: string;
  events: string[];
  secret_hash: string;
  enabled: boolean;
}

interface DeliveryResult {
  subscription_id: string;
  status: "delivered" | "failed" | "abandoned";
  response_code: number | null;
  attempts: number;
  error?: string;
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ ok: false, error: message }, status);
}

function stableJsonStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJsonStringify(entry)).join(",")}]`;
  }
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJsonStringify((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", keyMaterial, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function deliverWithRetry(
  subscriptionId: string,
  url: string,
  secretHash: string,
  eventType: string,
  payload: Record<string, unknown>,
  deliveryId: string,
): Promise<DeliveryResult> {
  const body = JSON.stringify({
    id: deliveryId,
    event_type: eventType,
    payload,
    timestamp: new Date().toISOString(),
  });

  let lastResponseCode: number | null = null;
  let attempts = 0;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    attempts = attempt + 1;

    if (attempt > 0) {
      await new Promise((resolve) =>
        setTimeout(resolve, RETRY_BACKOFF_MS[attempt - 1] ?? 3000)
      );
    }

    let signature = "";
    if (secretHash && /^[a-f0-9]{64}$/.test(secretHash)) {
      try {
        signature = await hmacSha256Hex(secretHash, body);
      } catch {
        // non-fatal — deliver unsigned
      }
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-IronClaw-Event": eventType,
      "X-IronClaw-Delivery": deliveryId,
    };
    if (signature) {
      headers["X-IronClaw-Signature-256"] = `sha256=${signature}`;
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), DISPATCH_TIMEOUT_MS);

      let res: Response;
      try {
        res = await fetch(url, {
          method: "POST",
          headers,
          body,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      lastResponseCode = res.status;

      if (res.status >= 200 && res.status < 300) {
        return {
          subscription_id: subscriptionId,
          status: "delivered",
          response_code: lastResponseCode,
          attempts,
        };
      }

      // 4xx are non-retryable (except 429)
      if (res.status >= 400 && res.status < 500 && res.status !== 429) {
        return {
          subscription_id: subscriptionId,
          status: "failed",
          response_code: lastResponseCode,
          attempts,
          error: `Non-retryable HTTP ${res.status}`,
        };
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt === MAX_RETRIES - 1) {
        return {
          subscription_id: subscriptionId,
          status: "abandoned",
          response_code: null,
          attempts,
          error: msg,
        };
      }
    }
  }

  return {
    subscription_id: subscriptionId,
    status: "abandoned",
    response_code: lastResponseCode,
    attempts,
    error: "Exhausted retries",
  };
}

async function writeDeliveryLog(
  supabase: SupabaseClient,
  deliveryId: string,
  subscriptionId: string,
  eventType: string,
  payload: Record<string, unknown>,
  result: DeliveryResult,
  eventId: string | null,
  checkoutSessionId: string | null,
  purchaseId: string | null,
): Promise<void> {
  const now = new Date().toISOString();
  const payloadHash = await sha256Hex(stableJsonStringify(payload));
  const { error } = await supabase.from("webhook_delivery_log").insert({
    id: deliveryId,
    subscription_id: subscriptionId,
    stripe_event_id: eventId ?? null,
    purchase_id: purchaseId ?? null,
    checkout_session_id: checkoutSessionId ?? null,
    event_type: eventType,
    payload,
    payload_hash: payloadHash,
    status: result.status,
    response_code: result.response_code ?? null,
    attempts: result.attempts,
    delivered_at: result.status === "delivered" ? now : null,
    created_at: now,
    updated_at: now,
  });
  if (error) {
    console.error(
      "ironclaw-webhook-dispatch: delivery log write failed",
      subscriptionId,
      error.message,
    );
  }
}

function extractStripeEventMetadata(payload: Record<string, unknown>, eventType: string, body: DispatchRequest): {
  event_id: string | null;
  checkout_session_id: string | null;
  purchase_id: string | null;
  customer_id: string | null;
  owner_key: string | null;
} {
  const object = (payload as Record<string, unknown> | undefined)?.data && typeof (payload as Record<string, unknown>).data === "object"
    ? ((payload as Record<string, unknown>).data as Record<string, unknown>).object as Record<string, unknown> | undefined
    : payload;
  const objectPayload = (object && typeof object === "object") ? object : {};
  const metadata = (objectPayload.metadata && typeof objectPayload.metadata === "object")
    ? (objectPayload.metadata as Record<string, unknown>)
    : {};

  const eventId = body.id ?? body.event_id ?? (typeof payload.id === "string" ? payload.id : null);
  const checkoutSessionId =
    (typeof body.checkout_session_id === "string" && body.checkout_session_id.trim() !== "")
      ? body.checkout_session_id.trim()
      : (typeof objectPayload.id === "string" && eventType === "checkout.session.completed")
        ? objectPayload.id
        : (typeof (objectPayload as Record<string, unknown>).checkout_session_id === "string"
            ? ((objectPayload as Record<string, unknown>).checkout_session_id as string)
            : null);
  const purchaseId =
    (typeof body.purchase_id === "string" && body.purchase_id.trim() !== "")
      ? body.purchase_id.trim()
      : (typeof metadata.purchase_id === "string" && metadata.purchase_id.trim() !== "")
        ? metadata.purchase_id.trim()
        : null;
  const customerId =
    (typeof body.customer_id === "string" && body.customer_id.trim() !== "")
      ? body.customer_id.trim()
      : (typeof objectPayload.customer === "string" && objectPayload.customer.trim() !== "")
        ? objectPayload.customer as string
        : (typeof metadata.customer_id === "string" && metadata.customer_id.trim() !== "")
          ? metadata.customer_id as string
          : null;
  const ownerKey =
    (typeof body.owner_key === "string" && body.owner_key.trim() !== "")
      ? body.owner_key.trim()
      : (typeof metadata.owner_key === "string" && metadata.owner_key.trim() !== "")
        ? metadata.owner_key.trim()
        : null;

  return {
    event_id: eventId ?? null,
    checkout_session_id: checkoutSessionId ?? null,
    purchase_id: purchaseId ?? null,
    customer_id: customerId ?? null,
    owner_key: ownerKey ?? null,
  };
}

async function registerStripeEventLedger(
  supabase: SupabaseClient,
  eventType: string,
  payload: Record<string, unknown>,
  body: DispatchRequest,
): Promise<{ duplicate: boolean; event_id: string | null; checkout_session_id: string | null; purchase_id: string | null; customer_id: string | null; owner_key: string | null; }> {
  const metadata = extractStripeEventMetadata(payload, eventType, body);
  const payloadHash = await sha256Hex(stableJsonStringify(payload));
  const eventId = metadata.event_id ?? payloadHash;

  const { data: existingRows, error: selectError } = await supabase
    .from("stripe_webhook_events")
    .select("id, stripe_event_id, status, event_type, checkout_session_id, purchase_id")
    .eq("stripe_event_id", eventId)
    .limit(1);

  if (selectError) {
    throw new Error(`Failed to read durable Stripe event ledger: ${selectError.message}`);
  }
  if (existingRows && existingRows.length > 0) {
    return {
      duplicate: true,
      event_id: eventId,
      checkout_session_id: metadata.checkout_session_id,
      purchase_id: metadata.purchase_id,
      customer_id: metadata.customer_id,
      owner_key: metadata.owner_key,
    };
  }

  const { error: insertError } = await supabase.from("stripe_webhook_events").insert({
    stripe_event_id: eventId,
    event_type: eventType,
    provider: "stripe",
    checkout_session_id: metadata.checkout_session_id,
    purchase_id: metadata.purchase_id,
    customer_id: metadata.customer_id,
    owner_key: metadata.owner_key,
    payload_hash: payloadHash,
    payload,
    status: "received",
    processed_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    metadata: {
      source: "ironclaw-webhook-dispatch",
      tenant_id: body.tenant_id ?? null,
      request_id: crypto.randomUUID(),
    },
  });

  if (insertError) {
    const msg = insertError.message || "";
    if (/duplicate|unique/i.test(msg)) {
      return {
        duplicate: true,
        event_id: eventId,
        checkout_session_id: metadata.checkout_session_id,
        purchase_id: metadata.purchase_id,
        customer_id: metadata.customer_id,
        owner_key: metadata.owner_key,
      };
    }
    throw new Error(`Failed to write durable Stripe event ledger: ${insertError.message}`);
  }

  return {
    duplicate: false,
    event_id: eventId,
    checkout_session_id: metadata.checkout_session_id,
    purchase_id: metadata.purchase_id,
    customer_id: metadata.customer_id,
    owner_key: metadata.owner_key,
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
    return errorResponse("Webhook dispatch service misconfigured", 500);
  }

  let body: DispatchRequest;
  try {
    body = await req.json() as DispatchRequest;
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const { event_type, payload, tenant_id } = body;

  if (!event_type || typeof event_type !== "string" || event_type.trim() === "") {
    return errorResponse("Missing required field: event_type", 400);
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return errorResponse("Missing or invalid field: payload (must be object)", 400);
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  let ledgerResult: { duplicate: boolean; event_id: string | null; checkout_session_id: string | null; purchase_id: string | null; customer_id: string | null; owner_key: string | null; };
  try {
    ledgerResult = await registerStripeEventLedger(supabase, event_type, payload, body);
  } catch (ledgerError) {
    const message = ledgerError instanceof Error ? ledgerError.message : String(ledgerError);
    console.error("ironclaw-webhook-dispatch: durable event ledger write failed", message);
    return errorResponse("Failed to persist durable webhook ledger", 500);
  }

  if (ledgerResult.duplicate) {
    return jsonResponse({
      ok: true,
      duplicate: true,
      event_id: ledgerResult.event_id,
      checkout_session_id: ledgerResult.checkout_session_id,
      purchase_id: ledgerResult.purchase_id,
      dispatched: 0,
      results: [],
    }, 200);
  }

  let query = supabase
    .from("webhook_subscriptions")
    .select("id, tenant_id, url, events, secret_hash, enabled")
    .eq("enabled", true)
    .contains("events", JSON.stringify([event_type]));

  if (tenant_id && typeof tenant_id === "string" && tenant_id.trim() !== "") {
    query = query.eq("tenant_id", tenant_id.trim());
  }

  const { data: subscriptions, error: subError } = await query;

  if (subError) {
    console.error("ironclaw-webhook-dispatch: subscription query failed", subError.message);
    return errorResponse("Failed to query webhook subscriptions", 500);
  }

  if (!subscriptions || subscriptions.length === 0) {
    return jsonResponse({ ok: true, dispatched: 0, results: [] }, 200);
  }

  const deliveries = await Promise.allSettled(
    (subscriptions as WebhookSubscription[]).map(async (sub) => {
      const deliveryId = crypto.randomUUID();
      const result = await deliverWithRetry(
        sub.id,
        sub.url,
        sub.secret_hash,
        event_type,
        payload,
        deliveryId,
      );
      await writeDeliveryLog(
        supabase,
        deliveryId,
        sub.id,
        event_type,
        payload,
        result,
        ledgerResult.event_id,
        ledgerResult.checkout_session_id,
        ledgerResult.purchase_id,
      );
      return result;
    }),
  );

  const results: DeliveryResult[] = deliveries.map((d) =>
    d.status === "fulfilled"
      ? d.value
      : ({
          subscription_id: "unknown",
          status: "abandoned" as const,
          response_code: null,
          attempts: 0,
          error: d.reason instanceof Error ? d.reason.message : String(d.reason),
        })
  );

  const delivered = results.filter((r) => r.status === "delivered").length;
  const failed = results.filter((r) => r.status !== "delivered").length;

  return jsonResponse({
    ok: true,
    dispatched: subscriptions.length,
    delivered,
    failed,
    results: results.map((r) => ({
      subscription_id: r.subscription_id,
      status: r.status,
      response_code: r.response_code,
      attempts: r.attempts,
    })),
  }, 200);
});
