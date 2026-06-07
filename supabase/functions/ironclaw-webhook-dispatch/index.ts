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
  event_type: string;
  payload: Record<string, unknown>;
  tenant_id?: string;
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
): Promise<void> {
  const now = new Date().toISOString();
  const { error } = await supabase.from("webhook_delivery_log").insert({
    id: deliveryId,
    subscription_id: subscriptionId,
    event_type: eventType,
    payload,
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
