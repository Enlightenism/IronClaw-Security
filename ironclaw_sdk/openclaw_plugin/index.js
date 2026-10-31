import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { authorizeToolCall } from "./policy.js";

export default definePluginEntry({
  id: "ironclaw-security",
  name: "IronClaw Security",
  description: "Fail-closed OpenClaw tool authorization through IronClaw.",
  register(api) {
    api.on(
      "before_tool_call",
      (event, context) =>
        authorizeToolCall(event, context, api.pluginConfig?.configFile),
      { priority: 100, timeoutMs: 14_000 },
    );
  },
});
