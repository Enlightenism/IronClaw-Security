import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";

import {
  actionTypeForTool,
  authorizeToolCall,
  serializeToolParams,
} from "../ironclaw_sdk/openclaw_plugin/policy.js";

const INSTALL_KEY = "ic_install_openclaw_test_value";

async function createRuntimeConfig(t, baseUrl = "http://127.0.0.1:8000") {
  const directory = await mkdtemp(join(tmpdir(), "ironclaw-openclaw-test-"));
  const configFile = join(directory, "config.json");
  await writeFile(
    configFile,
    JSON.stringify({
      base_url: baseUrl,
      install_keys: { openclaw: INSTALL_KEY },
    }),
    "utf8",
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  return configFile;
}

test("classifies OpenClaw tools into canonical action types", () => {
  assert.equal(actionTypeForTool("exec"), "command");
  assert.equal(actionTypeForTool("apply_patch"), "filewrite");
  assert.equal(actionTypeForTool("web_fetch"), "httpfetch");
  assert.equal(actionTypeForTool("browser"), "browseropen");
  assert.equal(actionTypeForTool("spawn_agent"), "toolcall");
});

test("redacts credential fields and values before submitting tool parameters", () => {
  const content = serializeToolParams({
    password: "example-password",
    command: "export API_KEY=example-token",
  });

  assert.equal(
    content,
    JSON.stringify({
      password: "[REDACTED]",
      command: "export API_KEY=[REDACTED]",
    }),
  );
});

test("allows only an explicitly allowed and metered server decision", async (t) => {
  const configFile = await createRuntimeConfig(t);
  const calls = [];
  const result = await authorizeToolCall(
    {
      toolName: "exec",
      params: { command: "echo safe", password: "example-password" },
    },
    { sessionKey: "openclaw-session-test" },
    configFile,
    async (url, options) => {
      calls.push({ url, options });
      return {
        ok: true,
        status: 200,
        json: async () => ({
          status: "allowed",
          executionallowed: true,
          usage: { executed: true, applied: true },
        }),
      };
    },
  );

  assert.equal(result, undefined);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:8000/action/execute");
  assert.equal(calls[0].options.headers["X-Install-Key"], INSTALL_KEY);
  assert.equal(calls[0].options.redirect, "error");
  const payload = JSON.parse(calls[0].options.body);
  assert.equal(payload.actiontype, "command");
  assert.equal(payload.sessionid, "openclaw-session-test");
  assert.equal(payload.content, JSON.stringify({ command: "echo safe", password: "[REDACTED]" }));
  assert.equal(calls[0].options.body.includes(INSTALL_KEY), false);
});

test("blocks denied, unmetered, and unreachable server decisions", async (t) => {
  const configFile = await createRuntimeConfig(t);
  const event = { toolName: "exec", params: { command: "echo safe" } };
  const unmetered = await authorizeToolCall(
    event,
    {},
    configFile,
    async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        status: "allowed",
        executionallowed: true,
        usage: { executed: false, applied: false },
      }),
    }),
  );
  assert.equal(unmetered.block, true);

  const denied = await authorizeToolCall(
    event,
    {},
    configFile,
    async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        status: "denied",
        executionallowed: false,
        message: "Action denied.",
      }),
    }),
  );
  assert.equal(denied.block, true);
  assert.match(denied.blockReason, /Action denied/);

  const unavailable = await authorizeToolCall(
    event,
    {},
    configFile,
    async () => ({ ok: false, status: 503 }),
  );
  assert.equal(unavailable.block, true);
  assert.match(unavailable.blockReason, /HTTP 503/);
});

test("blocks when install-key configuration or the API transport is invalid", async (t) => {
  const configFile = await createRuntimeConfig(t);
  const missingConfig = await authorizeToolCall(
    { toolName: "exec", params: {} },
    {},
    "",
    async () => {
      throw new Error("Must not call the API.");
    },
  );
  assert.equal(missingConfig.block, true);

  const originalError = console.error;
  console.error = () => {};
  try {
    const unavailable = await authorizeToolCall(
      { toolName: "exec", params: {} },
      {},
      configFile,
      async () => {
        throw new Error("Network unavailable.");
      },
    );
    assert.equal(unavailable.block, true);
  } finally {
    console.error = originalError;
  }
});

test("refuses to send the install key to a remote HTTP endpoint", async (t) => {
  const configFile = await createRuntimeConfig(t, "http://attacker.example");
  let fetchCalled = false;
  const originalError = console.error;
  console.error = () => {};
  try {
    const result = await authorizeToolCall(
      { toolName: "exec", params: {} },
      {},
      configFile,
      async () => {
        fetchCalled = true;
        return { ok: true, status: 200, json: async () => ({}) };
      },
    );
    assert.equal(result.block, true);
    assert.equal(fetchCalled, false);
  } finally {
    console.error = originalError;
  }
});
