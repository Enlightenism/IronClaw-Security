import { useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";
import { toast } from "sonner";

const CANONICAL_RUNTIME_COMMANDS = {
  "Claude Code":
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user",
  OpenClaw:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user",
  Cursor:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user",
  Goose:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user",
  "Gemini CLI":
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user",
  "GitHub Copilot":
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user",
  Hermes:
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

const isSecurityGuardian = (value) => {
  const key = normalizeRuntimeKey(value);
  return Boolean(key) && SECURITY_GUARDIAN_ALIASES.has(key);
};

const resolveCommand = (title, command) => {
  const rawCommand = typeof command === "string" ? command.trim() : "";
  if (
    rawCommand &&
    !rawCommand.includes("placeholder") &&
    !rawCommand.includes("loading")
  ) {
    return rawCommand;
  }

  if (typeof title !== "string") {
    return "";
  }

  const canonicalTitle = resolveCanonicalTitle(title);
  return CANONICAL_RUNTIME_COMMANDS[canonicalTitle] || "";
};

const IntegrationCard = ({ title, command, tint = "gold", testid }) => {
  const [copied, setCopied] = useState(false);

  const canonicalTitle = resolveCanonicalTitle(title);

  if (!canonicalTitle || isSecurityGuardian(canonicalTitle)) {
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
