import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
  "";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};

const JSON_HEADERS: Record<string, string> = {
  ...CORS_HEADERS,
  "Content-Type": "application/json",
};

async function sha256Hex(raw: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(raw);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ valid: false, error: message }, status);
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== "POST" && req.method !== "GET") {
    return errorResponse("Method not allowed", 405);
  }

  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return errorResponse("Missing or invalid Authorization header", 401);
  }

  const rawKey = authHeader.slice("Bearer ".length).trim();
  if (!rawKey) {
    return errorResponse("Empty API key", 401);
  }

  let keyHash: string;
  try {
    keyHash = await sha256Hex(rawKey);
  } catch {
    return errorResponse("Key hashing failed", 500);
  }

  if (!/^[a-f0-9]{64}$/.test(keyHash)) {
    return errorResponse("Invalid key format", 401);
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return errorResponse("Auth service misconfigured", 500);
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  const { data: keyRow, error: dbError } = await supabase
    .from("api_keys")
    .select("id, tenant_id, scopes, revoked, expires_at")
    .eq("key_hash", keyHash)
    .single();

  if (dbError || !keyRow) {
    return errorResponse("Invalid API key", 401);
  }

  if (keyRow.revoked === true) {
    return errorResponse("API key has been revoked", 401);
  }

  if (keyRow.expires_at !== null && keyRow.expires_at !== undefined) {
    const expiresAt = new Date(keyRow.expires_at as string).getTime();
    if (Date.now() > expiresAt) {
      return errorResponse("API key has expired", 401);
    }
  }

  supabase
    .from("api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", keyRow.id)
    .then(({ error }: { error: { message: string } | null }) => {
      if (error) {
        console.warn(
          "ironclaw-auth: last_used_at update failed",
          error.message,
        );
      }
    });

  const scopes: string[] = Array.isArray(keyRow.scopes)
    ? (keyRow.scopes as string[])
    : [];

  return jsonResponse({
    valid: true,
    tenant_id: keyRow.tenant_id ?? null,
    scopes,
  }, 200);
});
