import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

const REQUEST_TIMEOUT_MS = 12_000;
// Matches INSTALL_GATE_TIMEOUT_SECONDS in ironclaw_sdk/runtime_hooks.py: the scan budgets total about 20 s.
const INSTALL_GATE_TIMEOUT_MS = 26_000;
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
  if (/(^|_)(exec|shell|command|bash|terminal|powershell|pwsh)(_|$)/.test(name)) {
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

// Mirrors INSTALL_CHECKED_ACTIONS and _INSTALL_COMMAND_PATTERN in ironclaw_sdk/runtime_hooks.py.
const INSTALL_CHECKED_ACTIONS = new Set(["command", "httpfetch", "toolcall"]);
const INSTALL_COMMAND_PATTERN =
  /\b(?:install|clone|skill|plugin|recipe)s?\b|\b(?:npx|pipx|uvx|cargo|brew|gem)\b|\b(?:pip3?|uv|npm|pnpm|yarn|bun)\s+(?:add|i)\b|\bgit\s+(?:submodule|fetch|pull)\b|\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*?(?:\|\s*(?:sh|bash|zsh|python3?|pwsh|powershell|iex)\b|\s-o\b|\s-outfile\b|\s--output\b|\s>)  |\$\(\s*(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b|<\(\s*(?:curl|wget)\b|\b(?:iex|invoke-expression)\b.*\b(?:downloadstring|downloadfile|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i;
function stringValues(value) {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap(stringValues);
  }
  if (value && typeof value === "object") {
    return Object.values(value).flatMap(stringValues);
  }
  return [];
}

export function installCommandText(toolName, params) {
  if (!INSTALL_CHECKED_ACTIONS.has(actionTypeForTool(toolName))) {
    return null;
  }
  const text = stringValues(params).join(" ");
  return INSTALL_COMMAND_PATTERN.test(text) ? text : null;
}

function safeBaseUrl(baseUrl) {
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
  return baseUrl.replace(/\/+$/, "");
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
    baseUrl: safeBaseUrl(parsed.base_url.trim()),
  };
}

function blocked(reason) {
  return { block: true, blockReason: reason };
}

function sessionIdFor(context) {
  return context?.sessionId || context?.sessionKey || context?.runId || randomUUID();
}

function installBlockReason(decision) {
  const first = Array.isArray(decision?.reasons)
    ? decision.reasons.find((reason) => typeof reason === "string" && reason.trim())
    : undefined;
  return first
    ? `${redactText(first.trim()).slice(0, 240)} The action was blocked.`
    : "IronClaw blocked this install command; the action was blocked.";
}

async function postToGate(route, body, runtime, context, fetchImpl, timeoutMs = REQUEST_TIMEOUT_MS) {
  if (typeof fetchImpl !== "function") {
    throw new Error("The OpenClaw runtime does not provide fetch.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const parentSignal = context?.abortSignal;
  const abortFromParent = () => controller.abort();
  if (parentSignal?.aborted) {
    abortFromParent();
  } else {
    parentSignal?.addEventListener("abort", abortFromParent, { once: true });
  }

  try {
    return await fetchImpl(`${runtime.baseUrl}${route}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-Install-Key": runtime.installKey,
      },
      body: JSON.stringify(body),
      redirect: "error",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abortFromParent);
  }
}

async function requestInstallDecision(command, context, runtime, fetchImpl) {
  const response = await postToGate(
    "/install-gate/evaluate",
    { platform: "openclaw", command, client_id: "openclaw" },
    runtime,
    context,
    fetchImpl,
    INSTALL_GATE_TIMEOUT_MS,
  );
  if (!response.ok) {
    return blocked(`IronClaw install gate failed with HTTP ${response.status}; the action was blocked.`);
  }

  const decision = await response.json();
  return decision?.verdict === "allow" ? undefined : blocked(installBlockReason(decision));
}

async function requestAuthorization(event, context, configFile, fetchImpl) {
  const toolName = typeof event?.toolName === "string" ? event.toolName.trim() : "";
  if (!toolName) {
    return blocked("IronClaw could not identify this tool call; the action was blocked.");
  }

  rememberToolInput(event.toolCallId, event.params);
  const runtime = await loadRuntimeConfig(configFile);
  const installCommand = installCommandText(toolName, event.params);
  if (installCommand !== null) {
    const installBlock = await requestInstallDecision(installCommand, context, runtime, fetchImpl);
    if (installBlock) {
      return installBlock;
    }
  }

  const payload = {
    actiontype: actionTypeForTool(toolName),
    target: toolName,
    content: serializeToolParams(event.params),
    clientid: "openclaw",
    sessionid: sessionIdFor(context),
    eventid: randomUUID(),
    metadata: { runtime: "openclaw", ...actionFields(event.params) },
  };
  const response = await postToGate("/action/execute", payload, runtime, context, fetchImpl);

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

const RETURN_BLOCKED_TEXT =
  "[BLOCKED BY IRONCLAW RETURN GATE] The original tool output was withheld because it failed the return-gate scan.";
const PERSIST_TIMEOUT_MS = 30_000;
const PERSIST_MAX_BUFFER = 16 * 1024 * 1024;
const TOOL_INPUT_LIMIT = 500;
const toolInputs = new Map();

function asObject(value) {
  let parsed = value;
  if (typeof parsed === "string") {
    try {
      parsed = JSON.parse(parsed);
    } catch {
      return {};
    }
  }
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
}

const ACTION_FIELD_ALIASES = {
  url: ["url"],
  command: ["command"],
  file_path: ["file_path", "filePath", "path"],
};

function actionFields(params) {
  const source = asObject(params);
  const fields = {};
  for (const [field, aliases] of Object.entries(ACTION_FIELD_ALIASES)) {
    for (const alias of aliases) {
      const value = source[alias];
      if (typeof value === "string" && value.trim()) {
        fields[field] = value.trim();
        break;
      }
    }
  }
  return fields;
}

function rememberToolInput(toolCallId, params) {
  if (typeof toolCallId !== "string" || !toolCallId) {
    return;
  }
  toolInputs.delete(toolCallId);
  toolInputs.set(toolCallId, actionFields(params));
  if (toolInputs.size > TOOL_INPUT_LIMIT) {
    toolInputs.delete(toolInputs.keys().next().value);
  }
}

function takeToolInput(toolCallId) {
  const fields = toolInputs.get(toolCallId) ?? {};
  toolInputs.delete(toolCallId);
  return fields;
}

function firstString(...values) {
  const value = values.find((item) => typeof item === "string" && item.trim());
  return value ? value.trim() : "";
}

function persistableText(message) {
  const { content, details } = message;
  if (typeof content === "string") {
    return details === undefined ? content : `${content}\n${JSON.stringify({ details })}`;
  }
  if (!Array.isArray(content)) {
    return JSON.stringify(message);
  }
  const isText = (part) => part?.type === "text" && typeof part.text === "string";
  const textParts = content.filter(isText).map((part) => part.text);
  const otherParts = content.filter((part) => !isText(part));
  if (otherParts.length > 0 || details !== undefined) {
    textParts.push(JSON.stringify({ content: otherParts, details }));
  }
  return textParts.join("\n");
}

function persistedMessage(message, text) {
  return { message: { ...message, content: [{ type: "text", text }], details: undefined } };
}

export function persistToolResult(event, configFile, pythonPath, runPython = execFileSync) {
  const message = event?.message ?? event;
  if (!message || typeof message !== "object") {
    return undefined;
  }
  if (message.role !== undefined && message.role !== "toolResult") {
    return undefined;
  }

  const toolName = firstString(message.toolName, event?.toolName);
  const toolCallId = firstString(message.toolCallId, event?.toolCallId);
  if (
    !toolName ||
    typeof configFile !== "string" ||
    !isAbsolute(configFile) ||
    typeof pythonPath !== "string" ||
    !isAbsolute(pythonPath)
  ) {
    console.error("[ironclaw-security] Return gate is not configured; the tool output was withheld.");
    return persistedMessage(message, RETURN_BLOCKED_TEXT);
  }

  try {
    const input = JSON.stringify({
      tool_name: toolName,
      tool_input: takeToolInput(toolCallId),
      tool_response: persistableText(message),
    });
    const stdout = runPython(
      pythonPath,
      ["-m", "ironclaw_sdk.runtime_hooks", "--program", "openclaw", "--phase", "persist", "--config-file", configFile],
      {
        input,
        encoding: "utf8",
        timeout: PERSIST_TIMEOUT_MS,
        maxBuffer: PERSIST_MAX_BUFFER,
        windowsHide: true,
      },
    );
    const output = typeof stdout === "string" ? stdout.trim() : "";
    if (!output) {
      return undefined;
    }
    const replacement = JSON.parse(output)?.replacement;
    if (typeof replacement !== "string" || !replacement) {
      throw new Error("Unexpected return gate output.");
    }
    return persistedMessage(message, replacement);
  } catch (error) {
    const errorName = error instanceof Error ? error.name : "UnknownError";
    console.error(`[ironclaw-security] Return gate failed (${errorName}); the tool output was withheld.`);
    return persistedMessage(message, RETURN_BLOCKED_TEXT);
  }
}
