// supabase/functions/ironclaw-threat-feed-sync/index.ts
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

// ─── Environment ────────────────────────────────────────────────────────────

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

// Comma-separated list of feed URLs injected at deploy time or via Supabase secrets.
// Example: "https://otx.alienvault.com/taxii/...,https://rules.emergingthreats.net/..."
const FEED_URLS_ENV = Deno.env.get("IRONCLAW_THREAT_FEED_URLS") ?? "";

// Optional per-feed bearer token (single token applied to all authenticated feeds).
const FEED_AUTH_TOKEN = Deno.env.get("IRONCLAW_THREAT_FEED_TOKEN") ?? "";

// Fetch timeout per feed in milliseconds.
const FETCH_TIMEOUT_MS = 20_000;

// Maximum IOCs processed per feed per run to bound memory and runtime.
const MAX_IOCS_PER_FEED = 5_000;

// Maximum upsert batch size per Supabase call.
const UPSERT_BATCH_SIZE = 500;

// ─── Response helpers ────────────────────────────────────────────────────────

const JSON_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
};

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ ok: false, error: message }, status);
}

// ─── IOC types ───────────────────────────────────────────────────────────────

type IocType =
  | "ip"
  | "domain"
  | "url"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "email"
  | "cidr"
  | "cve"
  | "unknown";

type FeedFormat = "misp_json" | "otx_json" | "emerging_threats_rules" | "plain_text";

interface ParsedIoc {
  type: IocType;
  value: string;
  source_feed: string;
  feed_format: FeedFormat;
  confidence: number;      // 0.0 – 1.0
  severity: string;        // low | medium | high | critical
  tags: string[];
  raw_context: Record<string, unknown>;
  first_seen_feed: string | null;
  last_seen_feed: string | null;
}

interface IocUpsertRow {
  type: IocType;
  value: string;
  source_feed: string;
  feed_format: FeedFormat;
  confidence: number;
  severity: string;
  tags: string[];
  raw_context: Record<string, unknown>;
  first_seen_feed: string | null;
  last_seen_feed: string | null;
  last_synced_at: string;
  is_active: boolean;
}

interface FeedRunResult {
  feed_url: string;
  feed_format: FeedFormat;
  status: "success" | "error" | "empty";
  iocs_parsed: number;
  iocs_upserted: number;
  error_message: string | null;
  started_at: string;
  finished_at: string;
}

// ─── Detection helpers ───────────────────────────────────────────────────────

const RE_IPV4 =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const RE_IPV6 = /^[0-9a-fA-F:]{2,39}$/;
const RE_CIDR =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/\d{1,2}$/;
const RE_DOMAIN =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const RE_MD5 = /^[a-fA-F0-9]{32}$/;
const RE_SHA1 = /^[a-fA-F0-9]{40}$/;
const RE_SHA256 = /^[a-fA-F0-9]{64}$/;
const RE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RE_URL = /^https?:\/\/.+/i;
const RE_CVE = /^CVE-\d{4}-\d{4,}$/i;

function detectIocType(value: string): IocType {
  const v = value.trim();
  if (RE_CVE.test(v)) return "cve";
  if (RE_CIDR.test(v)) return "cidr";
  if (RE_IPV4.test(v) || RE_IPV6.test(v)) return "ip";
  if (RE_SHA256.test(v)) return "hash_sha256";
  if (RE_SHA1.test(v)) return "hash_sha1";
  if (RE_MD5.test(v)) return "hash_md5";
  if (RE_EMAIL.test(v)) return "email";
  if (RE_URL.test(v)) return "url";
  if (RE_DOMAIN.test(v)) return "domain";
  return "unknown";
}

function normalizeSeverity(raw: unknown): string {
  const s = String(raw ?? "medium").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(s)) return s;
  // OTX numeric threat score → severity
  const n = Number(raw);
  if (!isNaN(n)) {
    if (n >= 8) return "critical";
    if (n >= 6) return "high";
    if (n >= 4) return "medium";
    return "low";
  }
  return "medium";
}

function clampConfidence(v: unknown): number {
  const n = Number(v);
  if (isNaN(n)) return 0.5;
  return Math.min(1.0, Math.max(0.0, n));
}

function toIsoOrNull(v: unknown): string | null {
  if (!v) return null;
  const d = new Date(String(v));
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// ─── Feed format detection ───────────────────────────────────────────────────

function detectFormat(url: string, contentType: string): FeedFormat {
  const u = url.toLowerCase();
  const ct = contentType.toLowerCase();
  if (u.includes("misp") || ct.includes("application/json")) {
    // Will be disambiguated during parse — default to misp_json
    return "misp_json";
  }
  if (u.includes("otx") || u.includes("alienvault")) return "otx_json";
  if (
    u.includes("emerging") ||
    u.includes("emergingthreats") ||
    u.endsWith(".rules")
  ) {
    return "emerging_threats_rules";
  }
  if (ct.includes("text/plain")) return "plain_text";
  return "plain_text";
}

// ─── MISP JSON parser ────────────────────────────────────────────────────────
// Accepts MISP export format: { response: [ { Event: { ... } } ] }
// or flat array of Event objects.

function parseMispJson(
  body: unknown,
  feedUrl: string,
): ParsedIoc[] {
  const iocs: ParsedIoc[] = [];

  let events: unknown[] = [];
  if (Array.isArray(body)) {
    events = body;
  } else if (
    body &&
    typeof body === "object" &&
    Array.isArray((body as Record<string, unknown>).response)
  ) {
    events = (body as Record<string, unknown>).response as unknown[];
  } else {
    return iocs;
  }

  for (const wrapper of events) {
    const ev =
      wrapper &&
      typeof wrapper === "object" &&
      (wrapper as Record<string, unknown>).Event
        ? (wrapper as Record<string, unknown>).Event
        : wrapper;

    if (!ev || typeof ev !== "object") continue;
    const event = ev as Record<string, unknown>;

    const eventTags: string[] = [];
    if (Array.isArray(event.Tag)) {
      for (const t of event.Tag as Record<string, unknown>[]) {
        if (typeof t.name === "string") eventTags.push(t.name);
      }
    }

    const attrs = Array.isArray(event.Attribute)
      ? (event.Attribute as Record<string, unknown>[])
      : [];

    for (const attr of attrs) {
      const raw = String(attr.value ?? "").trim();
      if (!raw) continue;
      if (iocs.length >= MAX_IOCS_PER_FEED) break;

      const attrTags: string[] = [...eventTags];
      if (Array.isArray(attr.Tag)) {
        for (const t of attr.Tag as Record<string, unknown>[]) {
          if (typeof t.name === "string") attrTags.push(t.name);
        }
      }

      const detectedType = detectIocType(raw);

      iocs.push({
        type: detectedType,
        value: raw.toLowerCase(),
        source_feed: feedUrl,
        feed_format: "misp_json",
        confidence: clampConfidence(attr.comment ? 0.7 : 0.6),
        severity: normalizeSeverity(event.threat_level_id ?? attr.threat_level_id),
        tags: [...new Set(attrTags)],
        raw_context: {
          event_uuid: event.uuid,
          event_info: event.info,
          category: attr.category,
          type: attr.type,
          to_ids: attr.to_ids,
        },
        first_seen_feed: toIsoOrNull(attr.first_seen ?? event.date),
        last_seen_feed: toIsoOrNull(attr.last_seen ?? event.timestamp),
      });
    }

    if (iocs.length >= MAX_IOCS_PER_FEED) break;
  }

  return iocs;
}

// ─── OTX JSON parser ─────────────────────────────────────────────────────────
// OTX Pulse export: { results: [ { indicators: [...] } ] }
// or flat pulse: { indicators: [...] }

function parseOtxJson(
  body: unknown,
  feedUrl: string,
): ParsedIoc[] {
  const iocs: ParsedIoc[] = [];

  if (!body || typeof body !== "object") return iocs;

  const root = body as Record<string, unknown>;
  let pulses: Record<string, unknown>[] = [];

  if (Array.isArray(root.results)) {
    pulses = root.results as Record<string, unknown>[];
  } else if (Array.isArray(root.indicators)) {
    // Treat as single inline pulse
    pulses = [root];
  } else {
    pulses = [root];
  }

  for (const pulse of pulses) {
    const pulseTags: string[] = Array.isArray(pulse.tags)
      ? (pulse.tags as string[]).filter((t) => typeof t === "string")
      : [];

    const indicators = Array.isArray(pulse.indicators)
      ? (pulse.indicators as Record<string, unknown>[])
      : [];

    for (const ind of indicators) {
      if (iocs.length >= MAX_IOCS_PER_FEED) break;

      const raw = String(ind.indicator ?? "").trim();
      if (!raw) continue;

      const otxType = String(ind.type ?? "").toLowerCase();
      let iocType: IocType;
      if (otxType === "ipv4" || otxType === "ipv6") iocType = "ip";
      else if (otxType === "domain" || otxType === "hostname") iocType = "domain";
      else if (otxType === "url") iocType = "url";
      else if (otxType === "filehash-md5") iocType = "hash_md5";
      else if (otxType === "filehash-sha1") iocType = "hash_sha1";
      else if (otxType === "filehash-sha256") iocType = "hash_sha256";
      else if (otxType === "email") iocType = "email";
      else if (otxType === "cidr") iocType = "cidr";
      else if (otxType === "cve") iocType = "cve";
      else iocType = detectIocType(raw);

      iocs.push({
        type: iocType,
        value: raw.toLowerCase(),
        source_feed: feedUrl,
        feed_format: "otx_json",
        confidence: clampConfidence(ind.confidence ?? pulse.targeted_countries ? 0.75 : 0.6),
        severity: normalizeSeverity(pulse.TLP ?? ind.threat_score ?? 5),
        tags: [...new Set([...pulseTags, ...(Array.isArray(ind.tags) ? ind.tags as string[] : [])])],
        raw_context: {
          pulse_id: pulse.id,
          pulse_name: pulse.name,
          author: pulse.author_name,
          malware_families: pulse.malware_families,
          attack_ids: pulse.attack_ids,
        },
        first_seen_feed: toIsoOrNull(ind.created ?? pulse.created),
        last_seen_feed: toIsoOrNull(ind.modified ?? pulse.modified),
      });
    }

    if (iocs.length >= MAX_IOCS_PER_FEED) break;
  }

  return iocs;
}

// ─── Emerging Threats rules parser ───────────────────────────────────────────
// Parses Snort/Suricata .rules files.
// Extracts: msg, content, metadata, reference, classtype, sid.

const RE_ET_CONTENT = /content:"([^"]+)"/g;
const RE_ET_DNS = /dns_query;\s*content:"([^"]+)"/;
const RE_ET_MSG = /msg:"([^"]+)"/;
const RE_ET_CLASSTYPE = /classtype:([^;]+)/;
const RE_ET_SID = /sid:(\d+)/;
const RE_ET_IP_INLINE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

function parseEmergingThreatsRules(
  text: string,
  feedUrl: string,
): ParsedIoc[] {
  const iocs: ParsedIoc[] = [];
  const lines = text.split("\n");

  for (const line of lines) {
    if (iocs.length >= MAX_IOCS_PER_FEED) break;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (!trimmed.startsWith("alert") && !trimmed.startsWith("drop")) continue;

    const msgMatch = RE_ET_MSG.exec(trimmed);
    const msg = msgMatch ? msgMatch[1] : "";
    const classtypeMatch = RE_ET_CLASSTYPE.exec(trimmed);
    const classtype = classtypeMatch ? classtypeMatch[1].trim() : "";
    const sidMatch = RE_ET_SID.exec(trimmed);
    const sid = sidMatch ? sidMatch[1] : "";

    let severity: string;
    const ct = classtype.toLowerCase();
    if (
      ct.includes("trojan") ||
      ct.includes("exploit") ||
      ct.includes("ransomware") ||
      ct.includes("shellcode")
    ) {
      severity = "critical";
    } else if (ct.includes("malware") || ct.includes("c2") || ct.includes("command")) {
      severity = "high";
    } else if (ct.includes("suspicious") || ct.includes("scan")) {
      severity = "medium";
    } else {
      severity = "low";
    }

    // DNS-query based domain IOCs
    const dnsMatch = RE_ET_DNS.exec(trimmed);
    if (dnsMatch) {
      const domain = dnsMatch[1].trim().toLowerCase();
      if (domain && RE_DOMAIN.test(domain)) {
        iocs.push({
          type: "domain",
          value: domain,
          source_feed: feedUrl,
          feed_format: "emerging_threats_rules",
          confidence: 0.8,
          severity,
          tags: [classtype, "emerging_threats"].filter(Boolean),
          raw_context: { msg, classtype, sid, rule_fragment: trimmed.slice(0, 200) },
          first_seen_feed: null,
          last_seen_feed: null,
        });
        continue;
      }
    }

    // IP addresses embedded inline in the rule header (source/destination)
    const headerPart = trimmed.slice(0, trimmed.indexOf("(")).trim();
    const ipMatches = [...headerPart.matchAll(RE_ET_IP_INLINE)];
    const seenIps = new Set<string>();
    for (const m of ipMatches) {
      const ip = m[1];
      if (ip === "any" || seenIps.has(ip)) continue;
      if (!RE_IPV4.test(ip)) continue;
      // Skip broadcast / loopback / private ranges (reduce noise)
      if (
        ip.startsWith("127.") ||
        ip.startsWith("10.") ||
        ip.startsWith("192.168.") ||
        ip === "255.255.255.255" ||
        ip === "0.0.0.0"
      ) continue;
      seenIps.add(ip);
      if (iocs.length >= MAX_IOCS_PER_FEED) break;
      iocs.push({
        type: "ip",
        value: ip,
        source_feed: feedUrl,
        feed_format: "emerging_threats_rules",
        confidence: 0.7,
        severity,
        tags: [classtype, "emerging_threats"].filter(Boolean),
        raw_context: { msg, classtype, sid },
        first_seen_feed: null,
        last_seen_feed: null,
      });
    }
  }

  return iocs;
}

// ─── Plain-text parser ───────────────────────────────────────────────────────
// One IOC per line; supports # comments and inline comments.

function parsePlainText(text: string, feedUrl: string): ParsedIoc[] {
  const iocs: ParsedIoc[] = [];
  const lines = text.split("\n");
  for (const line of lines) {
    if (iocs.length >= MAX_IOCS_PER_FEED) break;
    const stripped = line.split("#")[0].trim();
    if (!stripped) continue;
    const type = detectIocType(stripped);
    if (type === "unknown") continue;
    iocs.push({
      type,
      value: stripped.toLowerCase(),
      source_feed: feedUrl,
      feed_format: "plain_text",
      confidence: 0.5,
      severity: "medium",
      tags: [],
      raw_context: {},
      first_seen_feed: null,
      last_seen_feed: null,
    });
  }
  return iocs;
}

// ─── Feed fetch + parse ───────────────────────────────────────────────────────

async function fetchAndParseFeed(feedUrl: string): Promise<{
  iocs: ParsedIoc[];
  format: FeedFormat;
  error: string | null;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const headers: Record<string, string> = {
      "Accept": "application/json, text/plain, */*",
      "User-Agent": "IronClaw-ThreatFeedSync/1.0",
    };
    if (FEED_AUTH_TOKEN) {
      headers["Authorization"] = `Bearer ${FEED_AUTH_TOKEN}`;
    }

    const resp = await fetch(feedUrl, {
      method: "GET",
      headers,
      signal: controller.signal,
    });

    if (!resp.ok) {
      return {
        iocs: [],
        format: "plain_text",
        error: `HTTP ${resp.status} ${resp.statusText}`,
      };
    }

    const contentType = resp.headers.get("content-type") ?? "";
    const format = detectFormat(feedUrl, contentType);

    if (format === "emerging_threats_rules") {
      const text = await resp.text();
      return { iocs: parseEmergingThreatsRules(text, feedUrl), format, error: null };
    }

    if (format === "plain_text" || !contentType.includes("json")) {
      const text = await resp.text();
      // Re-check: if it parses as JSON, treat as MISP or OTX
      try {
        const json = JSON.parse(text);
        const misp = parseMispJson(json, feedUrl);
        if (misp.length > 0) return { iocs: misp, format: "misp_json", error: null };
        const otx = parseOtxJson(json, feedUrl);
        if (otx.length > 0) return { iocs: otx, format: "otx_json", error: null };
      } catch {
        // Not JSON — treat as plain text
      }
      return { iocs: parsePlainText(text, feedUrl), format: "plain_text", error: null };
    }

    const json = await resp.json();

    // Disambiguate JSON: MISP has .response[] or top-level Attribute arrays;
    // OTX has .results[] with .indicators or a top-level .indicators array.
    if (
      feedUrl.toLowerCase().includes("otx") ||
      feedUrl.toLowerCase().includes("alienvault") ||
      (json && typeof json === "object" &&
        (Array.isArray((json as Record<string, unknown>).results) ||
          Array.isArray((json as Record<string, unknown>).indicators)))
    ) {
      return { iocs: parseOtxJson(json, feedUrl), format: "otx_json", error: null };
    }

    const misp = parseMispJson(json, feedUrl);
    if (misp.length > 0) return { iocs: misp, format: "misp_json", error: null };
    const otx = parseOtxJson(json, feedUrl);
    return { iocs: otx, format: "otx_json", error: null };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { iocs: [], format: "plain_text", error: msg };
  } finally {
    clearTimeout(timer);
  }
}

// ─── Supabase upsert helpers ──────────────────────────────────────────────────

async function upsertIocs(
  supabase: ReturnType<typeof createClient>,
  iocs: ParsedIoc[],
  now: string,
): Promise<{ upserted: number; error: string | null }> {
  if (iocs.length === 0) return { upserted: 0, error: null };

  const rows: IocUpsertRow[] = iocs.map((ioc) => ({
    type: ioc.type,
    value: ioc.value,
    source_feed: ioc.source_feed,
    feed_format: ioc.feed_format,
    confidence: ioc.confidence,
    severity: ioc.severity,
    tags: ioc.tags,
    raw_context: ioc.raw_context,
    first_seen_feed: ioc.first_seen_feed,
    last_seen_feed: ioc.last_seen_feed,
    last_synced_at: now,
    is_active: true,
  }));

  let upserted = 0;

  for (let i = 0; i < rows.length; i += UPSERT_BATCH_SIZE) {
    const batch = rows.slice(i, i + UPSERT_BATCH_SIZE);
    const { data, error } = await supabase
      .from("ioc_records")
      .upsert(batch, {
        onConflict: "type,value",
        ignoreDuplicates: false, // merge: update last_synced_at, severity, confidence on conflict
      })
      .select("type");

    if (error) {
      console.error(
        `ironclaw-threat-feed-sync: ioc_records upsert batch ${i / UPSERT_BATCH_SIZE + 1} failed`,
        error.message,
      );
      return { upserted, error: error.message };
    }
    upserted += data?.length ?? 0;
  }

  return { upserted, error: null };
}

async function writeFeedIngestLog(
  supabase: ReturnType<typeof createClient>,
  runResults: FeedRunResult[],
  runStartedAt: string,
  runFinishedAt: string,
  totalIocsUpserted: number,
  overallStatus: "success" | "partial" | "error",
): Promise<void> {
  const { error } = await supabase.from("feed_ingest_log").insert({
    run_started_at: runStartedAt,
    run_finished_at: runFinishedAt,
    overall_status: overallStatus,
    total_iocs_upserted: totalIocsUpserted,
    feeds_processed: runResults.length,
    feed_results: runResults,
  });

  if (error) {
    console.error(
      "ironclaw-threat-feed-sync: feed_ingest_log write failed",
      error.message,
    );
  }
}

// ─── Main handler ─────────────────────────────────────────────────────────────

Deno.serve(async (req: Request): Promise<Response> => {
  // Only GET (CRON trigger) and POST (external scheduler / manual trigger) allowed.
  if (req.method !== "GET" && req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return errorResponse("Threat feed sync service misconfigured: missing Supabase credentials", 500);
  }

  const feedUrls = FEED_URLS_ENV
    .split(",")
    .map((u) => u.trim())
    .filter((u) => u.startsWith("http://") || u.startsWith("https://"));

  if (feedUrls.length === 0) {
    return errorResponse(
      "No valid feed URLs configured. Set IRONCLAW_THREAT_FEED_URLS env secret.",
      400,
    );
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  const runStartedAt = new Date().toISOString();
  const runResults: FeedRunResult[] = [];
  let totalIocsUpserted = 0;

  for (const feedUrl of feedUrls) {
    const feedStarted = new Date().toISOString();
    console.log(`ironclaw-threat-feed-sync: fetching ${feedUrl}`);

    const { iocs, format, error: fetchError } = await fetchAndParseFeed(feedUrl);

    if (fetchError || iocs.length === 0) {
      const feedFinished = new Date().toISOString();
      runResults.push({
        feed_url: feedUrl,
        feed_format: format,
        status: fetchError ? "error" : "empty",
        iocs_parsed: 0,
        iocs_upserted: 0,
        error_message: fetchError,
        started_at: feedStarted,
        finished_at: feedFinished,
      });
      console.warn(
        `ironclaw-threat-feed-sync: feed ${feedUrl} ${fetchError ? "error: " + fetchError : "returned 0 IOCs"}`,
      );
      continue;
    }

    // Deduplicate within this feed batch by (type, value) before hitting DB.
    const seen = new Set<string>();
    const dedupedIocs = iocs.filter((ioc) => {
      const key = `${ioc.type}:${ioc.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const { upserted, error: upsertError } = await upsertIocs(
      supabase,
      dedupedIocs,
      runStartedAt,
    );

    const feedFinished = new Date().toISOString();
    totalIocsUpserted += upserted;

    runResults.push({
      feed_url: feedUrl,
      feed_format: format,
      status: upsertError ? "error" : "success",
      iocs_parsed: dedupedIocs.length,
      iocs_upserted: upserted,
      error_message: upsertError,
      started_at: feedStarted,
      finished_at: feedFinished,
    });

    console.log(
      `ironclaw-threat-feed-sync: ${feedUrl} → parsed=${dedupedIocs.length} upserted=${upserted}`,
    );
  }

  const runFinishedAt = new Date().toISOString();

  const successCount = runResults.filter((r) => r.status === "success").length;
  const errorCount = runResults.filter((r) => r.status === "error").length;
  const overallStatus: "success" | "partial" | "error" =
    errorCount === 0
      ? "success"
      : successCount > 0
      ? "partial"
      : "error";

  await writeFeedIngestLog(
    supabase,
    runResults,
    runStartedAt,
    runFinishedAt,
    totalIocsUpserted,
    overallStatus,
  );

  return jsonResponse(
    {
      ok: overallStatus !== "error",
      overall_status: overallStatus,
      run_started_at: runStartedAt,
      run_finished_at: runFinishedAt,
      feeds_processed: feedUrls.length,
      total_iocs_upserted: totalIocsUpserted,
      feed_results: runResults,
    },
    overallStatus === "error" ? 500 : 200,
  );
});
