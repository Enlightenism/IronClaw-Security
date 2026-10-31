import { randomUUID } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

const REQUEST_TIMEOUT_MS = 12_000;
const REDACTED = "[REDACTED]";
const SENSITIVE_FIELD_PATTERN =
  /password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key/i;

export function redactText(value) {
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(?:ic_install|ic_claim)_[A-Za-z0-9_-]+\b/gi, REDACTED)
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/gi, REDACTED)
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/gi, REDACTED)
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/gi, REDACTED)
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/gi, REDACTED)
    .replace(
      /(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret|authorization|cookie|credential|private[_-]?key)\s*[:=]\s*["']?([^"'\s&,;]+)/gi,
      "$1=[REDACTED]",
    );
}

export function serializeToolParams(params) {
  const serialized = JSON.stringify(params ?? {}, (key, value) => {
    if (key && SENSITIVE_FIELD_PATTERN.test(key)) {
      return REDACTED;
    }
    return typeof value === "string" ? redactText(value) : value;
  });
  if (typeof serialized !== "string") {
    throw new Error("Tool parameters are not serializable.");
  }
  return serialized;
}

export function actionTypeForTool(toolName) {
  const name = toolName.toLowerCase().replace(/[^a-z0-9]+/g, "_");
  if (/(^|_)(exec|shell|command|bash|terminal)(_|$)/.test(name)) {
    return "command";
  }
  if (/(^|_)(write|edit|patch|delete|move|copy|mkdir|touch)(_|$)/.test(name)) {
    return "filewrite";
  }
  if (/(^|_)(browser|navigate|browse|open_url)(_|$)/.test(name)) {
    return "browseropen";
  }
  if (/(^|_)(http|fetch|web_search)(_|$)/.test(name)) {
    return "httpfetch";
  }
  if (/(^|_)(read|list|search|glob)(_|$)/.test(name)) {
    return "fileread";
  }
  return "toolcall";
}

function actionEndpoint(baseUrl) {
  const parsed = new URL(baseUrl);
  const hostname = parsed.hostname.toLowerCase();
  const isLoopback = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(hostname);
  if (
    (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopback)) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error("IronClaw base URL is not safe for install-key authentication.");
  }
  return `${baseUrl.replace(/\/+$/, "")}/action/execute`;
}

async function loadRuntimeConfig(configFile) {
  if (typeof configFile !== "string" || !configFile.trim() || !isAbsolute(configFile)) {
    throw new Error("OpenClaw plugin configuration does not contain an absolute IronClaw config path.");
  }

  const fileInfo = await lstat(configFile);
  if (!fileInfo.isFile()) {
    throw new Error("IronClaw config must be a regular, non-symlink file.");
  }

  const parsed = JSON.parse(await readFile(configFile, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("IronClaw config must be a JSON object.");
  }

  const installKey = parsed.install_keys?.openclaw;
  if (typeof installKey !== "string" || !installKey.trim()) {
    throw new Error("The paid OpenClaw install key is missing.");
  }
  if (typeof parsed.base_url !== "string" || !parsed.base_url.trim()) {
    throw new Error("The IronClaw base URL is missing.");
  }

  return {
    installKey: installKey.trim(),
    endpoint: actionEndpoint(parsed.base_url.trim()),
  };
}

function blocked(reason) {
  return { block: true, blockReason: reason };
}

async function requestAuthorization(event, context, configFile, fetchImpl) {
  const toolName = typeof event?.toolName === "string" ? event.toolName.trim() : "";
  if (!toolName) {
    return blocked("IronClaw could not identify this tool call; the action was blocked.");
  }

  const payload = {
    actiontype: actionTypeForTool(toolName),
    target: toolName,
    content: serializeToolParams(event.params),
    clientid: "openclaw",
    sessionid: context?.sessionId || context?.sessionKey || context?.runId || randomUUID(),
    eventid: randomUUID(),
    metadata: { runtime: "openclaw" },
  };
  const runtime = await loadRuntimeConfig(configFile);
  if (typeof fetchImpl !== "function") {
    throw new Error("The OpenClaw runtime does not provide fetch.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const parentSignal = context?.abortSignal;
  const abortFromParent = () => controller.abort();
  if (parentSignal?.aborted) {
    abortFromParent();
  } else {
    parentSignal?.addEventListener("abort", abortFromParent, { once: true });
  }

  let response;
  try {
    response = await fetchImpl(runtime.endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-Install-Key": runtime.installKey,
      },
      body: JSON.stringify(payload),
      redirect: "error",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abortFromParent);
  }

  if (!response.ok) {
    return blocked(`IronClaw enforcement failed with HTTP ${response.status}; the action was blocked.`);
  }

  const decision = await response.json();
  if (
    decision?.status === "allowed" &&
    decision.executionallowed === true &&
    decision.usage?.executed === true &&
    decision.usage?.applied === true
  ) {
    return undefined;
  }

  const reason =
    typeof decision?.message === "string" && decision.message.trim()
      ? redactText(decision.message).slice(0, 240)
      : "IronClaw did not authorize this action.";
  return blocked(`${reason} The action was blocked.`);
}

export async function authorizeToolCall(
  event,
  context,
  configFile,
  fetchImpl = globalThis.fetch,
) {
  try {
    return await requestAuthorization(event, context, configFile, fetchImpl);
  } catch (error) {
    const errorName = error instanceof Error ? error.name : "UnknownError";
    console.error(
      `[ironclaw-security] Authorization failed (${errorName}); the tool call was blocked.`,
    );
    return blocked("IronClaw could not verify this action; the action was blocked.");
  }
}
