import { useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";
import { toast } from "sonner";

const CANONICAL_RUNTIME_COMMANDS = {
  claude_code:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user",
  openclaw:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user",
  cursor:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user",
  goose:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user",
  gemini_cli:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user",
  copilot:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user",
  hermes:
    "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security",
};

const SECURITY_GUARDIAN_ALIASES = new Set([
  "security guardian",
  "security_guardian",
  "security-guardian",
  "securityguardian",
  "security guardian skill",
  "security_guardian_skill",
  "skill",
  "skills",
]);

const RUNTIME_TITLE_ALIASES = {
  "claude code": "Claude Code",
  claude_code: "Claude Code",
  openclaw: "OpenClaw",
  cursor: "Cursor",
  goose: "Goose",
  "gemini cli": "Gemini CLI",
  gemini_cli: "Gemini CLI",
  "github copilot": "GitHub Copilot",
  copilot: "GitHub Copilot",
  hermes: "Hermes",
};

const normalizeRuntimeKey = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
};

const resolveCanonicalTitle = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  const normalized = normalizeRuntimeKey(trimmed);
  if (!normalized) {
    return "";
  }

  if (RUNTIME_TITLE_ALIASES[normalized]) {
    return RUNTIME_TITLE_ALIASES[normalized];
  }

  return trimmed;
};

const resolveCanonicalRuntimeKey = (value) => {
  const title = resolveCanonicalTitle(value);
  if (!title) {
    return "";
  }

  const normalized = normalizeRuntimeKey(title);
  const keyMap = {
    "claude code": "claude_code",
    openclaw: "openclaw",
    cursor: "cursor",
    goose: "goose",
    "gemini cli": "gemini_cli",
    "github copilot": "copilot",
    hermes: "hermes",
  };

  return keyMap[normalized] || "";
};

const isSecurityGuardian = (value) => {
  const key = normalizeRuntimeKey(value);
  return Boolean(key) && SECURITY_GUARDIAN_ALIASES.has(key);
};

const looksLikeTokenCommand = (value) => {
  if (typeof value !== "string") {
    return false;
  }

  const candidate = value.trim();
  if (!candidate) {
    return false;
  }

  return (
    candidate.includes("--token") ||
    candidate.includes("token ") ||
    candidate.includes("api-key") ||
    candidate.includes("api key") ||
    candidate.includes("gh auth") ||
    candidate.includes("placeholder") ||
    candidate.includes("loading")
  );
};

const commandMatchesRuntime = (command, runtimeKey) => {
  if (!runtimeKey || typeof command !== "string") {
    return false;
  }

  const candidate = command.trim();
  if (!candidate || looksLikeTokenCommand(candidate)) {
    return false;
  }

  switch (runtimeKey) {
    case "claude_code":
      return (
        candidate.includes("--agent claude-code") ||
        candidate.includes("claude-code")
      );
    case "openclaw":
      return (
        candidate.includes("--agent openclaw") || candidate.includes("openclaw")
      );
    case "cursor":
      return (
        candidate.includes("--agent cursor") || candidate.includes("cursor")
      );
    case "goose":
      return candidate.includes("--agent goose") || candidate.includes("goose");
    case "gemini_cli":
      return (
        candidate.includes("--agent gemini-cli") ||
        candidate.includes("gemini-cli")
      );
    case "copilot":
      return (
        candidate.includes("--agent copilot") || candidate.includes("copilot")
      );
    case "hermes":
      return (
        candidate.includes("hermes skills install") ||
        (candidate.includes("ironclaw-security") &&
          candidate.includes("hermes"))
      );
    default:
      return false;
  }
};

const resolveCommand = (title, command) => {
  const runtimeKey = resolveCanonicalRuntimeKey(title);
  if (!runtimeKey) {
    return "";
  }

  const canonicalCommand = CANONICAL_RUNTIME_COMMANDS[runtimeKey] || "";
  const rawCommand = typeof command === "string" ? command.trim() : "";

  if (rawCommand && commandMatchesRuntime(rawCommand, runtimeKey)) {
    return rawCommand;
  }

  return canonicalCommand;
};

const IntegrationCard = ({ title, command, tint = "gold", testid }) => {
  const [copied, setCopied] = useState(false);

  const canonicalTitle = resolveCanonicalTitle(title);
  const runtimeKey = resolveCanonicalRuntimeKey(canonicalTitle);

  if (!canonicalTitle || isSecurityGuardian(canonicalTitle) || !runtimeKey) {
    return null;
  }

  const normalizedCommand = resolveCommand(canonicalTitle, command);

  if (!normalizedCommand) {
    return null;
  }

  const surface = tint === "gold" ? "glass-gold" : "glass-platinum";
  const accent = tint === "gold" ? "#FFD700" : "#E5E4E2";

  const copy = async () => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(normalizedCommand);
      } else {
        throw new Error("clipboard unavailable");
      }
    } catch {
      const ta = document.createElement("textarea");
      ta.value = normalizedCommand;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } finally {
        document.body.removeChild(ta);
      }
    }
    setCopied(true);
    toast.success("Install command copied");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`${surface} rounded-xl p-6`} data-testid={testid}>
      <div className="mb-4 flex items-center gap-2">
        <Terminal size={16} style={{ color: accent }} />
        <h3
          className="font-tech text-sm font-semibold uppercase tracking-[0.25em]"
          style={{ color: accent }}
        >
          {canonicalTitle}
        </h3>
      </div>

      <p className="mb-3 text-xs text-[#BFC1C2]">
        Drop this one-liner into your agent host. Every unit draw and blocked
        attack from this install streams straight to your dashboard.
      </p>

      <div className="flex items-stretch gap-2">
        <code className="font-tech flex-1 overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-white/10 bg-black/50 px-4 py-3 text-xs leading-relaxed text-white/90">
          {normalizedCommand}
        </code>
        <button
          type="button"
          onClick={copy}
          data-testid={`${testid}-copy`}
          className="flex w-12 shrink-0 items-center justify-center rounded-lg border transition disabled:cursor-not-allowed disabled:opacity-50"
          style={{
            borderColor: `${accent}55`,
            background: `${accent}14`,
            color: accent,
          }}
          aria-label={`Copy ${canonicalTitle} install command`}
        >
          {copied ? <Check size={18} /> : <Copy size={18} />}
        </button>
      </div>
    </div>
  );
};

export default IntegrationCard;
